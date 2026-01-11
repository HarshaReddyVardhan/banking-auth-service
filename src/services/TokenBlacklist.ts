import Redis from 'ioredis';
import { config } from '../config/config';
import { logger } from '../middleware/requestLogger';
import { AuditLog, AuditEventType } from '../models/AuditLog';
import { SecurityEvent, SecurityEventCategory, SecurityEventSeverity } from '../models/SecurityEvent';
import { eventPublisher } from '../kafka/EventPublisher';

/**
 * Token Blacklist - Redis-backed JWT revocation
 * Stores revoked tokens until their natural expiry
 */
export class TokenBlacklist {
    private redis: Redis;
    private readonly prefix = 'token_blacklist:';
    private readonly jtiPrefix = 'jti:';

    constructor() {
        this.redis = new Redis({
            host: config.redis.host,
            port: config.redis.port,
            password: config.redis.password,
            db: config.redis.db,
            tls: config.redis.tls ? {} : undefined,
        });

        this.redis.on('error', (err) => {
            logger.error('Redis error in TokenBlacklist:', err);
        });
    }

    /**
     * Add a token to the blacklist
     */
    async blacklist(
        tokenHash: string,
        expiresAt: Date,
        reason: string,
        userId: string,
        sessionId?: string,
        ip?: string
    ): Promise<void> {
        const key = `${this.prefix}${tokenHash}`;
        const ttlSeconds = Math.max(0, Math.floor((expiresAt.getTime() - Date.now()) / 1000));

        if (ttlSeconds <= 0) {
            // Token already expired, no need to blacklist
            return;
        }

        const data = JSON.stringify({
            reason,
            userId,
            sessionId,
            blacklistedAt: new Date().toISOString(),
        });

        await this.redis.setex(key, ttlSeconds, data);

        logger.info('Token blacklisted', {
            tokenHash: tokenHash.substring(0, 16) + '...',
            reason,
            userId,
            ttlSeconds,
        });

        // Log to audit
        if (ip) {
            await AuditLog.log({
                eventType: AuditEventType.TOKEN_REVOKED,
                userId,
                resourceType: 'token',
                resourceId: tokenHash.substring(0, 16),
                payload: { reason },
                ipAddress: ip,
                sessionId,
                severity: 'INFO',
            });
        }
    }

    /**
     * Check if a token is blacklisted
     */
    async isBlacklisted(tokenHash: string): Promise<boolean> {
        const key = `${this.prefix}${tokenHash}`;
        const exists = await this.redis.exists(key);
        return exists === 1;
    }

    /**
     * Get blacklist reason (for debugging)
     */
    async getBlacklistReason(tokenHash: string): Promise<string | null> {
        const key = `${this.prefix}${tokenHash}`;
        const data = await this.redis.get(key);
        if (!data) return null;

        try {
            const parsed = JSON.parse(data) as { reason: string };
            return parsed.reason;
        } catch {
            return null;
        }
    }

    /**
     * Blacklist all tokens for a user (security breach response)
     */
    async blacklistAllUserTokens(
        userId: string,
        reason: string,
        ip: string
    ): Promise<void> {
        // Store a user-level block that lasts 24 hours
        const userBlockKey = `${this.prefix}user:${userId}`;
        await this.redis.setex(userBlockKey, 86400, JSON.stringify({
            reason,
            blockedAt: new Date().toISOString(),
        }));

        logger.warn('All user tokens blocked', { userId, reason });

        // Log security event
        await SecurityEvent.log({
            category: SecurityEventCategory.TOKEN,
            severity: SecurityEventSeverity.CRITICAL,
            eventType: 'ALL_TOKENS_REVOKED',
            description: `All tokens revoked for user: ${reason}`,
            userId,
            ipAddress: ip,
        });

        // Publish event
        await eventPublisher.publish('security.all_tokens_revoked', {
            userId,
            reason,
            timestamp: new Date().toISOString(),
        });
    }

    /**
     * Check if user has global token block
     */
    async isUserBlocked(userId: string): Promise<boolean> {
        const userBlockKey = `${this.prefix}user:${userId}`;
        return (await this.redis.exists(userBlockKey)) === 1;
    }

    /**
     * Remove user block (after password reset)
     */
    async removeUserBlock(userId: string): Promise<void> {
        const userBlockKey = `${this.prefix}user:${userId}`;
        await this.redis.del(userBlockKey);
    }

    /**
     * Track JTI to prevent token replay
     */
    async trackJti(jti: string, expiresAt: Date): Promise<boolean> {
        const key = `${this.jtiPrefix}${jti}`;
        const ttlSeconds = Math.max(0, Math.floor((expiresAt.getTime() - Date.now()) / 1000));

        if (ttlSeconds <= 0) {
            return false;
        }

        // Use NX to ensure atomicity - returns null if key already exists
        const result = await this.redis.set(key, '1', 'EX', ttlSeconds, 'NX');
        return result === 'OK';
    }

    /**
     * Check if JTI was already seen (replay attack)
     */
    async isJtiSeen(jti: string): Promise<boolean> {
        const key = `${this.jtiPrefix}${jti}`;
        return (await this.redis.exists(key)) === 1;
    }

    /**
     * Close Redis connection
     */
    async close(): Promise<void> {
        await this.redis.quit();
    }
}

// Export singleton
export const tokenBlacklist = new TokenBlacklist();
