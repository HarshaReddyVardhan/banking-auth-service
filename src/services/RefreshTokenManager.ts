import { Op } from 'sequelize';
import { RefreshToken } from '../models/RefreshToken';
import { sessionManager } from './SessionManager';
import { tokenBlacklist } from './TokenBlacklist';
import { emailService } from './EmailService';
import { eventPublisher } from '../kafka/EventPublisher';
import { AuditLog, AuditEventType } from '../models/AuditLog';
import { SecurityEvent, SecurityEventCategory, SecurityEventSeverity } from '../models/SecurityEvent';
import { User } from '../models/User';
import { logger, securityLogger } from '../middleware/requestLogger';
import crypto from 'crypto';

/**
 * Refresh Token Manager - Handles token rotation with theft detection
 * Implements token family tracking to detect reuse attacks
 */
export class RefreshTokenManager {
    /**
     * Create a new refresh token for a user
     */
    async createToken(
        userId: string,
        sessionId: string,
        familyId: string,
        ip: string,
        userAgent: string,
        expiresAt: Date,
        deviceId?: string
    ): Promise<{ token: string; tokenHash: string }> {
        // Generate new token
        const token = crypto.randomBytes(64).toString('base64url');
        const tokenHash = RefreshToken.hashToken(token);

        await RefreshToken.create({
            userId,
            familyId,
            tokenHash,
            sessionId,
            deviceId,
            expiresAt,
            issuedIp: ip,
            issuedUserAgent: userAgent,
        });

        return { token, tokenHash };
    }

    /**
     * Rotate a refresh token - issue new one, invalidate old
     * CRITICAL: Detects token theft via reuse
     */
    async rotateToken(
        currentToken: string,
        ip: string,
        userAgent: string
    ): Promise<{
        success: boolean;
        newToken?: string;
        userId?: string;
        sessionId?: string;
        familyId?: string;
        error?: string;
    }> {
        const tokenHash = RefreshToken.hashToken(currentToken);

        // Find the token
        const storedToken = await RefreshToken.findOne({
            where: { tokenHash },
        });

        if (!storedToken) {
            return { success: false, error: 'Invalid refresh token' };
        }

        // Check if token was already used - THIS IS TOKEN THEFT
        if (storedToken.wasUsed()) {
            await this.handleTokenTheft(storedToken, ip, userAgent);
            return { success: false, error: 'Security violation detected' };
        }

        // Check if token is valid
        if (!storedToken.isValid()) {
            return { success: false, error: 'Refresh token expired or revoked' };
        }

        // Check if user is blocked
        if (await tokenBlacklist.isUserBlocked(storedToken.userId)) {
            return { success: false, error: 'Account temporarily blocked' };
        }

        // Mark current token as used (BEFORE creating new one)
        await storedToken.markAsUsed();

        // Create new token in the same family
        const newExpiry = new Date();
        newExpiry.setDate(newExpiry.getDate() + 7); // 7 day expiry

        const { token: newToken, tokenHash: newTokenHash } = await this.createToken(
            storedToken.userId,
            storedToken.sessionId,
            storedToken.familyId,
            ip,
            userAgent,
            newExpiry,
            storedToken.deviceId ?? undefined
        );

        // Update new token's parent reference
        await RefreshToken.update(
            { parentTokenHash: tokenHash },
            { where: { tokenHash: newTokenHash } }
        );

        logger.info('Refresh token rotated', {
            userId: storedToken.userId,
            familyId: storedToken.familyId,
        });

        return {
            success: true,
            newToken,
            userId: storedToken.userId,
            sessionId: storedToken.sessionId,
            familyId: storedToken.familyId,
        };
    }

    /**
     * Handle token theft - revoke all tokens and force password reset
     */
    async handleTokenTheft(
        storedToken: RefreshToken,
        ip: string,
        userAgent: string
    ): Promise<void> {
        const { userId, familyId } = storedToken;

        logger.error('TOKEN THEFT DETECTED', {
            userId,
            familyId,
            ip,
        });

        securityLogger.tokenTheftDetected(userId, familyId);

        // 1. Revoke ALL tokens in the family
        await RefreshToken.update(
            { revokedAt: new Date(), revokedReason: 'token_theft_detected' },
            { where: { familyId } }
        );

        // 2. Revoke ALL user sessions
        await sessionManager.revokeAllUserSessions(userId, 'token_theft_detected');

        // 3. Block all user tokens globally
        await tokenBlacklist.blacklistAllUserTokens(userId, 'token_theft_detected', ip);

        // 4. Log security event
        await SecurityEvent.log({
            category: SecurityEventCategory.TOKEN,
            severity: SecurityEventSeverity.CRITICAL,
            eventType: 'TOKEN_THEFT_DETECTED',
            description: `Token reuse detected - potential token theft. Family: ${familyId}`,
            userId,
            ipAddress: ip,
            userAgent,
            metadata: {
                familyId,
                originalUsedAt: storedToken.usedAt?.toISOString(),
                reuseAttemptAt: new Date().toISOString(),
            },
        });

        // 5. Log to audit trail
        await AuditLog.log({
            eventType: AuditEventType.TOKEN_THEFT_DETECTED,
            userId,
            resourceType: 'token_family',
            resourceId: familyId,
            payload: {
                familyId,
                action: 'all_tokens_revoked',
                passwordResetRequired: true,
            },
            ipAddress: ip,
            userAgent,
            severity: 'CRITICAL',
        });

        // 6. Send security alert email
        const user = await User.findByPk(userId);
        if (user) {
            await emailService.sendSecurityAlertEmail(
                user.email,
                'Suspicious Activity Detected',
                `We detected an attempt to access your account with a previously used authentication token from IP: ${ip}. ` +
                `All your sessions have been terminated for security. Please reset your password immediately.`
            );
        }

        // 7. Publish Kafka event
        await eventPublisher.publish('security.token_theft', {
            userId,
            familyId,
            ip,
            userAgent,
            timestamp: new Date().toISOString(),
        });
    }

    /**
     * Revoke a specific refresh token
     */
    async revokeToken(
        tokenHash: string,
        reason: string,
        ip?: string
    ): Promise<boolean> {
        const token = await RefreshToken.findOne({
            where: { tokenHash },
        });

        if (!token) {
            return false;
        }

        await token.revoke(reason);

        if (ip) {
            await AuditLog.log({
                eventType: AuditEventType.TOKEN_REVOKED,
                userId: token.userId,
                resourceType: 'refresh_token',
                resourceId: token.id,
                payload: { reason },
                ipAddress: ip,
                sessionId: token.sessionId,
                severity: 'INFO',
            });
        }

        return true;
    }

    /**
     * Revoke all tokens for a user
     */
    async revokeAllUserTokens(userId: string, reason: string): Promise<number> {
        const [affectedCount] = await RefreshToken.update(
            { revokedAt: new Date(), revokedReason: reason },
            { where: { userId, revokedAt: null } }
        );

        logger.info('All user refresh tokens revoked', {
            userId,
            reason,
            count: affectedCount,
        });

        return affectedCount;
    }

    /**
     * Revoke all tokens in a family
     */
    async revokeFamilyTokens(familyId: string, reason: string): Promise<number> {
        const [affectedCount] = await RefreshToken.update(
            { revokedAt: new Date(), revokedReason: reason },
            { where: { familyId, revokedAt: null } }
        );

        return affectedCount;
    }

    /**
     * Clean up expired tokens (maintenance job)
     */
    async cleanupExpiredTokens(): Promise<number> {
        const deleted = await RefreshToken.destroy({
            where: {
                expiresAt: { [Op.lt]: new Date() },
            },
        });

        logger.info('Expired refresh tokens cleaned up', { count: deleted });
        return deleted;
    }

    /**
     * Get active token count for a user
     */
    async getActiveTokenCount(userId: string): Promise<number> {
        return RefreshToken.count({
            where: {
                userId,
                revokedAt: null,
                expiresAt: { [Op.gt]: new Date() },
                usedAt: null,
            },
        });
    }
}

// Export singleton
export const refreshTokenManager = new RefreshTokenManager();
