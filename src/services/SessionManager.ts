import Redis from 'ioredis';
import crypto from 'crypto';
import { config } from '../config/config';
import { logger } from '../middleware/requestLogger';

/**
 * Session data stored in Redis
 */
export interface SessionData {
    userId: string;
    email: string;
    deviceId?: string;
    deviceFingerprint?: string;
    ip: string;
    userAgent: string;
    createdAt: number;
    lastActivityAt: number;
    expiresAt: number;
}

/**
 * Session Manager with Redis-backed sessions
 * - Concurrent session limits with LRU eviction
 * - Session fixation protection
 * - Secure session invalidation
 */
export class SessionManager {
    private redis: Redis;
    private readonly sessionPrefix = 'session:';
    private readonly userSessionsPrefix = 'user_sessions:';
    private readonly maxConcurrentSessions: number;
    private readonly sessionExpirySeconds: number;

    constructor() {
        this.redis = new Redis({
            host: config.redis.host,
            port: config.redis.port,
            password: config.redis.password,
            db: config.redis.db,
            tls: config.redis.tls ? {} : undefined,
            retryStrategy: (times) => {
                const delay = Math.min(times * 50, 2000);
                return delay;
            },
            maxRetriesPerRequest: 3,
        });

        this.maxConcurrentSessions = config.session.maxConcurrent;
        this.sessionExpirySeconds = config.session.expiryHours * 60 * 60;

        this.redis.on('error', (err) => {
            logger.error('Redis connection error:', err);
        });

        this.redis.on('connect', () => {
            logger.info('Redis connected for session management');
        });
    }

    /**
     * Generate a cryptographically secure session ID
     */
    generateSessionId(): string {
        return crypto.randomBytes(32).toString('hex');
    }

    /**
     * Create a new session with concurrent session limit enforcement
     */
    async createSession(
        userId: string,
        email: string,
        ip: string,
        userAgent: string,
        deviceId?: string,
        deviceFingerprint?: string
    ): Promise<string> {
        const sessionId = this.generateSessionId();
        const now = Date.now();
        const expiresAt = now + this.sessionExpirySeconds * 1000;

        const sessionData: SessionData = {
            userId,
            email,
            deviceId,
            deviceFingerprint,
            ip,
            userAgent,
            createdAt: now,
            lastActivityAt: now,
            expiresAt,
        };

        // Check concurrent session limit and evict oldest if needed
        await this.enforceSessionLimit(userId);

        // Store session in Redis
        const sessionKey = this.getSessionKey(sessionId);
        await this.redis.setex(
            sessionKey,
            this.sessionExpirySeconds,
            JSON.stringify(sessionData)
        );

        // Add session to user's session set (sorted by creation time)
        const userSessionsKey = this.getUserSessionsKey(userId);
        await this.redis.zadd(userSessionsKey, now, sessionId);
        await this.redis.expire(userSessionsKey, this.sessionExpirySeconds);

        logger.info('Session created', {
            userId,
            sessionId: sessionId.substring(0, 8) + '...',
            ip,
        });

        return sessionId;
    }

    /**
     * Enforce concurrent session limit using LRU eviction
     */
    private async enforceSessionLimit(userId: string): Promise<void> {
        const userSessionsKey = this.getUserSessionsKey(userId);
        const sessionCount = await this.redis.zcard(userSessionsKey);

        if (sessionCount >= this.maxConcurrentSessions) {
            // Get oldest sessions to evict (LRU)
            const sessionsToEvict = sessionCount - this.maxConcurrentSessions + 1;
            const oldestSessions = await this.redis.zrange(
                userSessionsKey,
                0,
                sessionsToEvict - 1
            );

            for (const sessionId of oldestSessions) {
                await this.revokeSession(sessionId, userId, 'session_limit_exceeded');
            }

            logger.info('Sessions evicted due to limit', {
                userId,
                evictedCount: oldestSessions.length,
            });
        }
    }

    /**
     * Get session data by ID
     */
    async getSession(sessionId: string): Promise<SessionData | null> {
        const sessionKey = this.getSessionKey(sessionId);
        const data = await this.redis.get(sessionKey);

        if (!data) {
            return null;
        }

        const session = JSON.parse(data) as SessionData;

        // Check if expired
        if (Date.now() > session.expiresAt) {
            await this.redis.del(sessionKey);
            return null;
        }

        return session;
    }

    /**
     * Validate a session and update last activity
     */
    async validateSession(sessionId: string): Promise<SessionData | null> {
        const session = await this.getSession(sessionId);

        if (!session) {
            return null;
        }

        // Update last activity time
        session.lastActivityAt = Date.now();
        const sessionKey = this.getSessionKey(sessionId);
        const ttl = await this.redis.ttl(sessionKey);

        if (ttl > 0) {
            await this.redis.setex(sessionKey, ttl, JSON.stringify(session));
        }

        return session;
    }

    /**
     * Revoke a specific session
     */
    async revokeSession(
        sessionId: string,
        userId: string,
        reason: string = 'user_logout'
    ): Promise<boolean> {
        const sessionKey = this.getSessionKey(sessionId);
        const userSessionsKey = this.getUserSessionsKey(userId);

        const deleted = await this.redis.del(sessionKey);
        await this.redis.zrem(userSessionsKey, sessionId);

        if (deleted > 0) {
            logger.info('Session revoked', {
                userId,
                sessionId: sessionId.substring(0, 8) + '...',
                reason,
            });
            return true;
        }

        return false;
    }

    /**
     * Revoke all sessions for a user (e.g., password change, security event)
     */
    async revokeAllUserSessions(
        userId: string,
        reason: string,
        excludeSessionId?: string
    ): Promise<number> {
        const userSessionsKey = this.getUserSessionsKey(userId);
        const sessionIds = await this.redis.zrange(userSessionsKey, 0, -1);

        let revokedCount = 0;
        for (const sessionId of sessionIds) {
            if (sessionId !== excludeSessionId) {
                const sessionKey = this.getSessionKey(sessionId);
                await this.redis.del(sessionKey);
                revokedCount++;
            }
        }

        // Clear the user's session set or keep only the excluded session
        if (excludeSessionId) {
            await this.redis.zremrangebyrank(userSessionsKey, 0, -1);
            const session = await this.getSession(excludeSessionId);
            if (session) {
                await this.redis.zadd(userSessionsKey, session.createdAt, excludeSessionId);
            }
        } else {
            await this.redis.del(userSessionsKey);
        }

        logger.info('All user sessions revoked', {
            userId,
            reason,
            revokedCount,
            excludedSession: excludeSessionId ? 'yes' : 'no',
        });

        return revokedCount;
    }

    /**
     * Get all active sessions for a user
     */
    async getUserSessions(userId: string): Promise<Array<{ sessionId: string; data: SessionData }>> {
        const userSessionsKey = this.getUserSessionsKey(userId);
        const sessionIds = await this.redis.zrange(userSessionsKey, 0, -1);

        const sessions: Array<{ sessionId: string; data: SessionData }> = [];

        for (const sessionId of sessionIds) {
            const session = await this.getSession(sessionId);
            if (session) {
                sessions.push({ sessionId, data: session });
            } else {
                // Clean up stale reference
                await this.redis.zrem(userSessionsKey, sessionId);
            }
        }

        return sessions;
    }

    /**
     * Regenerate session ID (for session fixation protection)
     */
    async regenerateSession(oldSessionId: string): Promise<string | null> {
        const session = await this.getSession(oldSessionId);

        if (!session) {
            return null;
        }

        // Create new session with same data
        const newSessionId = this.generateSessionId();
        const sessionKey = this.getSessionKey(newSessionId);
        const ttl = Math.floor((session.expiresAt - Date.now()) / 1000);

        if (ttl <= 0) {
            return null;
        }

        await this.redis.setex(sessionKey, ttl, JSON.stringify(session));

        // Update user sessions set
        const userSessionsKey = this.getUserSessionsKey(session.userId);
        await this.redis.zrem(userSessionsKey, oldSessionId);
        await this.redis.zadd(userSessionsKey, session.createdAt, newSessionId);

        // Delete old session
        await this.redis.del(this.getSessionKey(oldSessionId));

        logger.info('Session regenerated', {
            userId: session.userId,
            reason: 'session_fixation_protection',
        });

        return newSessionId;
    }

    /**
     * Check if a session exists (without loading full data)
     */
    async sessionExists(sessionId: string): Promise<boolean> {
        const sessionKey = this.getSessionKey(sessionId);
        return (await this.redis.exists(sessionKey)) === 1;
    }

    /**
     * Helper to get session Redis key
     */
    private getSessionKey(sessionId: string): string {
        return `${this.sessionPrefix}${sessionId}`;
    }

    /**
     * Helper to get user sessions Redis key
     */
    private getUserSessionsKey(userId: string): string {
        return `${this.userSessionsPrefix}${userId}`;
    }

    /**
     * Store a temporary token (e.g., for MFA completion or password reset)
     */
    async setTempToken(token: string, data: Record<string, unknown>, ttlSeconds: number = 300): Promise<void> {
        const key = `${this.sessionPrefix}temp:${token}`;
        await this.redis.setex(key, ttlSeconds, JSON.stringify(data));
    }

    /**
     * Retrieve and optionally delete a temporary token
     */
    async getTempToken(token: string, deleteAfterRead: boolean = true): Promise<Record<string, unknown> | null> {
        const key = `${this.sessionPrefix}temp:${token}`;
        const data = await this.redis.get(key);

        if (!data) {
            return null;
        }

        if (deleteAfterRead) {
            await this.redis.del(key);
        }

        return JSON.parse(data);
    }

    /**
     * Close Redis connection
     */
    async close(): Promise<void> {
        await this.redis.quit();
    }
}

// Export singleton instance
export const sessionManager = new SessionManager();
