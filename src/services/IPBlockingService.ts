import Redis from 'ioredis';
import { config } from '../config/config';
import { logger } from '../middleware/requestLogger';

/**
 * IP Blocking Service
 * 
 * Provides automatic blocking of suspicious IPs based on:
 * - Multiple failed login attempts across accounts
 * - Suspicious activity patterns
 * - Manual blocks from security team
 * 
 * This is a defense-in-depth measure beyond account-level rate limiting.
 */

interface BlockedIPData {
    reason: string;
    blockedAt: number;
    expiresAt: number;
    failedAttempts: number;
    affectedAccounts: string[];  // Masked emails
}

interface SuspiciousIPData {
    failedAttempts: number;
    lastAttemptAt: number;
    targetedAccounts: Set<string>;
}

export class IPBlockingService {
    private redis: Redis;
    private readonly blockedIPPrefix = 'blocked_ip:';
    private readonly suspiciousIPPrefix = 'suspicious_ip:';

    // Thresholds for automatic blocking
    private readonly MAX_FAILED_ATTEMPTS_PER_IP = 20; // Across all accounts
    private readonly MAX_TARGETED_ACCOUNTS = 5; // Credential stuffing indicator
    private readonly SUSPICIOUS_WINDOW_MS = 60 * 60 * 1000; // 1 hour
    private readonly BLOCK_DURATION_MS = 24 * 60 * 60 * 1000; // 24 hours

    constructor() {
        this.redis = new Redis({
            host: config.redis.host,
            port: config.redis.port,
            password: config.redis.password,
            db: config.redis.db,
            tls: config.redis.tls ? {} : undefined,
        });

        this.redis.on('error', (err) => {
            logger.error('Redis error in IPBlockingService:', err);
        });
    }

    /**
     * Check if an IP is blocked
     */
    async isBlocked(ip: string): Promise<{ blocked: boolean; reason?: string; expiresIn?: number }> {
        const key = `${this.blockedIPPrefix}${ip}`;
        const data = await this.redis.get(key);

        if (!data) {
            return { blocked: false };
        }

        const blockData = JSON.parse(data) as BlockedIPData;
        const now = Date.now();

        if (now >= blockData.expiresAt) {
            // Block expired, clean up
            await this.redis.del(key);
            return { blocked: false };
        }

        return {
            blocked: true,
            reason: blockData.reason,
            expiresIn: Math.ceil((blockData.expiresAt - now) / 1000),
        };
    }

    /**
     * Record a failed login attempt from an IP
     * Automatically blocks if thresholds are exceeded
     */
    async recordFailedAttempt(ip: string, targetEmail: string): Promise<{ nowBlocked: boolean }> {
        const key = `${this.suspiciousIPPrefix}${ip}`;
        const now = Date.now();

        // Get current data
        const data = await this.redis.get(key);
        let suspiciousData: SuspiciousIPData;

        if (data) {
            const parsed = JSON.parse(data);
            suspiciousData = {
                failedAttempts: parsed.failedAttempts,
                lastAttemptAt: parsed.lastAttemptAt,
                targetedAccounts: new Set(parsed.targetedAccounts),
            };

            // Reset if outside window
            if (now - suspiciousData.lastAttemptAt > this.SUSPICIOUS_WINDOW_MS) {
                suspiciousData = {
                    failedAttempts: 0,
                    lastAttemptAt: now,
                    targetedAccounts: new Set(),
                };
            }
        } else {
            suspiciousData = {
                failedAttempts: 0,
                lastAttemptAt: now,
                targetedAccounts: new Set(),
            };
        }

        // Update data
        suspiciousData.failedAttempts++;
        suspiciousData.lastAttemptAt = now;
        suspiciousData.targetedAccounts.add(this.maskEmail(targetEmail));

        // Store updated data
        const ttlSeconds = Math.ceil(this.SUSPICIOUS_WINDOW_MS / 1000);
        await this.redis.setex(key, ttlSeconds, JSON.stringify({
            failedAttempts: suspiciousData.failedAttempts,
            lastAttemptAt: suspiciousData.lastAttemptAt,
            targetedAccounts: Array.from(suspiciousData.targetedAccounts),
        }));

        // Check if should block
        let shouldBlock = false;
        let blockReason = '';

        if (suspiciousData.failedAttempts >= this.MAX_FAILED_ATTEMPTS_PER_IP) {
            shouldBlock = true;
            blockReason = 'Excessive failed login attempts';
        } else if (suspiciousData.targetedAccounts.size >= this.MAX_TARGETED_ACCOUNTS) {
            shouldBlock = true;
            blockReason = 'Credential stuffing attempt detected';
        }

        if (shouldBlock) {
            await this.blockIP(ip, blockReason, Array.from(suspiciousData.targetedAccounts));
            logger.warn('IP automatically blocked', {
                ip,
                reason: blockReason,
                failedAttempts: suspiciousData.failedAttempts,
                targetedAccounts: suspiciousData.targetedAccounts.size,
            });
        }

        return { nowBlocked: shouldBlock };
    }

    /**
     * Block an IP address
     */
    async blockIP(
        ip: string,
        reason: string,
        affectedAccounts: string[] = [],
        durationMs: number = this.BLOCK_DURATION_MS
    ): Promise<void> {
        const key = `${this.blockedIPPrefix}${ip}`;
        const now = Date.now();

        const blockData: BlockedIPData = {
            reason,
            blockedAt: now,
            expiresAt: now + durationMs,
            failedAttempts: 0,
            affectedAccounts,
        };

        const ttlSeconds = Math.ceil(durationMs / 1000);
        await this.redis.setex(key, ttlSeconds, JSON.stringify(blockData));

        // Clear suspicious data since we've blocked
        await this.redis.del(`${this.suspiciousIPPrefix}${ip}`);

        logger.info('IP blocked', { ip, reason, durationMs });
    }

    /**
     * Unblock an IP address (manual intervention)
     */
    async unblockIP(ip: string): Promise<boolean> {
        const key = `${this.blockedIPPrefix}${ip}`;
        const deleted = await this.redis.del(key);

        if (deleted > 0) {
            logger.info('IP unblocked', { ip });
            return true;
        }
        return false;
    }

    /**
     * Clear failed attempts on successful login
     */
    async clearFailedAttempts(ip: string): Promise<void> {
        await this.redis.del(`${this.suspiciousIPPrefix}${ip}`);
    }

    /**
     * Get block info for an IP
     */
    async getBlockInfo(ip: string): Promise<BlockedIPData | null> {
        const key = `${this.blockedIPPrefix}${ip}`;
        const data = await this.redis.get(key);

        if (!data) return null;
        return JSON.parse(data) as BlockedIPData;
    }

    /**
     * Mask email for storage (privacy)
     */
    private maskEmail(email: string): string {
        const [local, domain] = email.toLowerCase().split('@');
        if (!local || !domain) return '***@***.***';
        return `${local.slice(0, 2)}***@${domain}`;
    }

    /**
     * Close Redis connection
     */
    async close(): Promise<void> {
        await this.redis.quit();
    }
}

// Export singleton
export const ipBlockingService = new IPBlockingService();
