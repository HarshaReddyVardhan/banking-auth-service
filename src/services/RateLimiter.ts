import Redis from 'ioredis';
import { config } from '../config/config';
import { logger } from '../middleware/requestLogger';

/**
 * Rate limit result
 */
export interface RateLimitResult {
    allowed: boolean;
    remainingAttempts: number;
    retryAfterMs: number;
    isLocked: boolean;
}

/**
 * Progressive Rate Limiter with exponential backoff
 * - IP-based rate limiting
 * - Account-based progressive delays
 * - Email resend limiting
 */
export class RateLimiter {
    private redis: Redis;

    // Redis key prefixes
    private readonly ipRateLimitPrefix = 'ratelimit:ip:';
    private readonly loginAttemptsPrefix = 'login_attempts:';
    private readonly emailResendPrefix = 'email_resend:';
    private readonly ipEmailResendPrefix = 'ip_email_resend:';

    // Progressive delay curve (attempt number -> delay in ms)
    private readonly delayCurve: Record<number, number>;

    constructor() {
        this.redis = new Redis({
            host: config.redis.host,
            port: config.redis.port,
            password: config.redis.password,
            db: config.redis.db,
            tls: config.redis.tls ? {} : undefined,
        });

        this.delayCurve = config.progressiveDelay;

        this.redis.on('error', (err) => {
            logger.error('Redis error in RateLimiter:', err);
        });
    }

    /**
     * Check IP-based rate limit (general API requests)
     */
    async checkIpRateLimit(ip: string): Promise<RateLimitResult> {
        const key = `${this.ipRateLimitPrefix}${ip}`;
        const windowMs = config.rateLimit.windowMs;
        const maxRequests = config.rateLimit.maxRequests;

        const current = await this.redis.incr(key);

        if (current === 1) {
            await this.redis.pexpire(key, windowMs);
        }

        const ttl = await this.redis.pttl(key);
        const remaining = Math.max(0, maxRequests - current);

        if (current > maxRequests) {
            logger.warn('IP rate limit exceeded', { ip, requests: current });
            return {
                allowed: false,
                remainingAttempts: 0,
                retryAfterMs: ttl > 0 ? ttl : windowMs,
                isLocked: false,
            };
        }

        return {
            allowed: true,
            remainingAttempts: remaining,
            retryAfterMs: 0,
            isLocked: false,
        };
    }

    /**
     * Check login attempt with progressive delay
     * Returns the delay the user must wait before attempting again
     */
    async checkLoginAttempt(email: string): Promise<RateLimitResult> {
        const key = `${this.loginAttemptsPrefix}${email.toLowerCase()}`;

        // Get current attempt data
        const data = await this.redis.get(key);

        if (!data) {
            // First attempt - no delay
            return {
                allowed: true,
                remainingAttempts: config.security.maxLoginAttempts,
                retryAfterMs: 0,
                isLocked: false,
            };
        }

        const attemptData = JSON.parse(data) as {
            count: number;
            lastAttemptAt: number;
            lockedUntil?: number;
        };

        const now = Date.now();

        // Check if account is locked
        if (attemptData.lockedUntil && now < attemptData.lockedUntil) {
            return {
                allowed: false,
                remainingAttempts: 0,
                retryAfterMs: attemptData.lockedUntil - now,
                isLocked: true,
            };
        }

        // Get required delay based on attempt count
        const requiredDelay = this.getRequiredDelay(attemptData.count);
        const timeSinceLastAttempt = now - attemptData.lastAttemptAt;

        if (timeSinceLastAttempt < requiredDelay) {
            return {
                allowed: false,
                remainingAttempts: Math.max(0, config.security.maxLoginAttempts - attemptData.count),
                retryAfterMs: requiredDelay - timeSinceLastAttempt,
                isLocked: false,
            };
        }

        return {
            allowed: true,
            remainingAttempts: Math.max(0, config.security.maxLoginAttempts - attemptData.count),
            retryAfterMs: 0,
            isLocked: false,
        };
    }

    /**
     * Record a failed login attempt
     */
    async recordFailedLogin(email: string): Promise<{ isNowLocked: boolean; lockDurationMs: number }> {
        const key = `${this.loginAttemptsPrefix}${email.toLowerCase()}`;
        const now = Date.now();

        // Get current data or initialize
        const data = await this.redis.get(key);
        let attemptData = data
            ? (JSON.parse(data) as { count: number; lastAttemptAt: number; lockedUntil?: number })
            : { count: 0, lastAttemptAt: now };

        attemptData.count++;
        attemptData.lastAttemptAt = now;

        // Check if should lock
        let isNowLocked = false;
        let lockDurationMs = 0;

        if (attemptData.count >= config.security.maxLoginAttempts) {
            isNowLocked = true;
            lockDurationMs = config.security.lockoutDurationMs;
            attemptData.lockedUntil = now + lockDurationMs;

            logger.warn('Account locked due to failed attempts', {
                email: email.replace(/(.{2}).*(@.*)/, '$1***$2'),
                attempts: attemptData.count,
                lockDurationMs,
            });
        }

        // Store with TTL (1 hour after last attempt or lock expiry)
        const ttlSeconds = Math.ceil((isNowLocked ? lockDurationMs : 3600000) / 1000);
        await this.redis.setex(key, ttlSeconds, JSON.stringify(attemptData));

        return { isNowLocked, lockDurationMs };
    }

    /**
     * Clear login attempts on successful login
     */
    async clearLoginAttempts(email: string): Promise<void> {
        const key = `${this.loginAttemptsPrefix}${email.toLowerCase()}`;
        await this.redis.del(key);
    }

    /**
     * Check email resend rate limit
     */
    async checkEmailResendLimit(email: string, ip: string): Promise<RateLimitResult> {
        const emailKey = `${this.emailResendPrefix}${email.toLowerCase()}`;
        const ipKey = `${this.ipEmailResendPrefix}${ip}`;
        const windowSeconds = config.rateLimit.emailResendWindowHours * 3600;

        // Check email-based limit
        const emailCount = await this.redis.incr(emailKey);
        if (emailCount === 1) {
            await this.redis.expire(emailKey, windowSeconds);
        }

        if (emailCount > config.rateLimit.emailResendPerEmail) {
            const ttl = await this.redis.ttl(emailKey);
            return {
                allowed: false,
                remainingAttempts: 0,
                retryAfterMs: ttl * 1000,
                isLocked: false,
            };
        }

        // Check IP-based limit
        const ipCount = await this.redis.incr(ipKey);
        if (ipCount === 1) {
            await this.redis.expire(ipKey, windowSeconds);
        }

        if (ipCount > config.rateLimit.emailResendPerIP) {
            const ttl = await this.redis.ttl(ipKey);
            return {
                allowed: false,
                remainingAttempts: 0,
                retryAfterMs: ttl * 1000,
                isLocked: false,
            };
        }

        return {
            allowed: true,
            remainingAttempts: Math.min(
                config.rateLimit.emailResendPerEmail - emailCount,
                config.rateLimit.emailResendPerIP - ipCount
            ),
            retryAfterMs: 0,
            isLocked: false,
        };
    }

    /**
     * Get required delay based on attempt count (exponential backoff)
     */
    private getRequiredDelay(attemptCount: number): number {
        // Find the highest defined delay for the current attempt count
        const delayKeys = Object.keys(this.delayCurve)
            .map(Number)
            .sort((a, b) => b - a);

        for (const threshold of delayKeys) {
            if (attemptCount >= threshold) {
                return this.delayCurve[threshold] ?? 0;
            }
        }

        return 0;
    }

    /**
     * Get current attempt count for an email
     */
    async getAttemptCount(email: string): Promise<number> {
        const key = `${this.loginAttemptsPrefix}${email.toLowerCase()}`;
        const data = await this.redis.get(key);

        if (!data) return 0;

        const attemptData = JSON.parse(data) as { count: number };
        return attemptData.count;
    }

    /**
     * Check if account is currently locked
     */
    async isAccountLocked(email: string): Promise<{ locked: boolean; remainingMs: number }> {
        const key = `${this.loginAttemptsPrefix}${email.toLowerCase()}`;
        const data = await this.redis.get(key);

        if (!data) {
            return { locked: false, remainingMs: 0 };
        }

        const attemptData = JSON.parse(data) as { lockedUntil?: number };
        const now = Date.now();

        if (attemptData.lockedUntil && now < attemptData.lockedUntil) {
            return { locked: true, remainingMs: attemptData.lockedUntil - now };
        }

        return { locked: false, remainingMs: 0 };
    }

    /**
     * Check per-user rate limit (authenticated requests)
     */
    async checkUserRateLimit(userId: string): Promise<RateLimitResult> {
        const key = `ratelimit:user:${userId}`;
        const windowMs = config.rateLimit.windowMs;
        const maxRequests = config.rateLimit.maxRequests * 2; // Higher limit for authenticated

        const current = await this.redis.incr(key);

        if (current === 1) {
            await this.redis.pexpire(key, windowMs);
        }

        const ttl = await this.redis.pttl(key);
        const remaining = Math.max(0, maxRequests - current);

        if (current > maxRequests) {
            return {
                allowed: false,
                remainingAttempts: 0,
                retryAfterMs: ttl > 0 ? ttl : windowMs,
                isLocked: false,
            };
        }

        return {
            allowed: true,
            remainingAttempts: remaining,
            retryAfterMs: 0,
            isLocked: false,
        };
    }

    /**
     * Check per-JWT rate limit (prevents token abuse)
     */
    async checkJwtRateLimit(jti: string): Promise<RateLimitResult> {
        const key = `ratelimit:jwt:${jti}`;
        const windowMs = 60000; // 1 minute
        const maxRequests = 60; // 60 requests/minute per token

        const current = await this.redis.incr(key);

        if (current === 1) {
            await this.redis.pexpire(key, windowMs);
        }

        const ttl = await this.redis.pttl(key);
        const remaining = Math.max(0, maxRequests - current);

        if (current > maxRequests) {
            return {
                allowed: false,
                remainingAttempts: 0,
                retryAfterMs: ttl > 0 ? ttl : windowMs,
                isLocked: false,
            };
        }

        return {
            allowed: true,
            remainingAttempts: remaining,
            retryAfterMs: 0,
            isLocked: false,
        };
    }

    /**
     * Close Redis connection
     */
    async close(): Promise<void> {
        await this.redis.quit();
    }
}

// Export singleton instance
export const rateLimiter = new RateLimiter();

