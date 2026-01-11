import crypto from 'crypto';
import { Op } from 'sequelize';
import { User, UserStatus, KycStatus } from '../models/User';
import { PasswordHistory } from '../models/PasswordHistory';
import { PasswordResetToken } from '../models/PasswordResetToken';
import { RefreshToken } from '../models/RefreshToken';
import { LoginResult } from '../models/LoginHistory';
import { passwordHasher, PasswordValidationError } from '../utils/PasswordHasher';
import { jwtHandler, TokenPair, TokenExpiredError, TokenVerificationError } from '../utils/JWTHandler';
import { sessionManager } from './SessionManager';
import { rateLimiter } from './RateLimiter';
import { emailService } from './EmailService';
import { mfaService } from './MFAService';
import { deviceManager, DeviceFingerprintData } from './DeviceManager';
import { breachChecker } from './BreachChecker';
import { anomalyDetector } from './AnomalyDetector';
import { eventPublisher } from '../kafka/EventPublisher';
import { config } from '../config/config';
import { logger, securityLogger } from '../middleware/requestLogger';

/**
 * Registration request
 */
export interface RegisterRequest {
    email: string;
    password: string;
}

/**
 * Login request
 */
export interface LoginRequest {
    email: string;
    password: string;
    mfaToken?: string;
    deviceFingerprint?: DeviceFingerprintData;
}

/**
 * Login response
 */
export interface LoginResponse {
    success: boolean;
    tokens?: TokenPair;
    sessionId?: string;
    requiresMfa?: boolean;
    mfaToken?: string; // Temporary token for MFA completion
    user?: {
        id: string;
        email: string;
        emailVerified: boolean;
        mfaEnabled: boolean;
        kycStatus: KycStatus;
    };
    error?: string;
}

/**
 * Auth Service - Core authentication logic
 */
export class AuthService {
    /**
     * Register a new user
     */
    async register(
        request: RegisterRequest,
        ip: string,
        userAgent: string
    ): Promise<{ success: boolean; userId?: string; error?: string }> {
        const { email, password } = request;

        try {
            // Check if email already exists
            const existingUser = await User.findOne({
                where: { email: email.toLowerCase() },
            });

            if (existingUser) {
                logger.warn('Registration attempt with existing email', { email: email.replace(/(.{2}).*(@.*)/, '$1***$2') });
                return { success: false, error: 'Email already registered' };
            }

            // Validate password strength
            try {
                passwordHasher.validatePasswordStrength(password);
            } catch (error) {
                if (error instanceof PasswordValidationError) {
                    return { success: false, error: error.errors.join('. ') };
                }
                throw error;
            }

            // Check if password is breached
            const breachResult = await breachChecker.isPasswordSecure(password);
            if (!breachResult.secure) {
                return { success: false, error: breachResult.reason };
            }

            // Hash password
            const passwordHash = await passwordHasher.hash(password);

            // Generate email verification token
            const verificationToken = crypto.randomBytes(32).toString('hex');
            const verificationExpiry = new Date();
            verificationExpiry.setHours(verificationExpiry.getHours() + 24);

            // Create user
            const user = await User.create({
                email: email.toLowerCase(),
                passwordHash,
                emailVerificationToken: verificationToken,
                emailVerificationExpiry: verificationExpiry,
                status: UserStatus.PENDING_VERIFICATION,
                kycStatus: KycStatus.NOT_STARTED,
            });

            // Store password in history
            await PasswordHistory.create({
                userId: user.id,
                passwordHash,
            });

            // Send verification email
            await emailService.sendVerificationEmail(email, verificationToken);

            // Publish event
            await eventPublisher.publish('user.registered', {
                userId: user.id,
                email: email.replace(/(.{2}).*(@.*)/, '$1***$2'),
                ip,
                timestamp: new Date().toISOString(),
            });

            logger.info('User registered successfully', {
                userId: user.id,
                email: email.replace(/(.{2}).*(@.*)/, '$1***$2'),
            });

            return { success: true, userId: user.id };
        } catch (error) {
            logger.error('Registration error', { error });
            return { success: false, error: 'Registration failed. Please try again.' };
        }
    }

    /**
     * Verify email address
     */
    async verifyEmail(token: string): Promise<{ success: boolean; error?: string }> {
        try {
            const user = await User.findOne({
                where: {
                    emailVerificationToken: token,
                    emailVerificationExpiry: { [Op.gt]: new Date() },
                },
            });

            if (!user) {
                return { success: false, error: 'Invalid or expired verification token' };
            }

            user.emailVerified = true;
            user.emailVerificationToken = null;
            user.emailVerificationExpiry = null;
            user.status = UserStatus.ACTIVE;
            await user.save();

            await eventPublisher.publish('user.email.verified', {
                userId: user.id,
                timestamp: new Date().toISOString(),
            });

            logger.info('Email verified', { userId: user.id });

            return { success: true };
        } catch (error) {
            logger.error('Email verification error', { error });
            return { success: false, error: 'Verification failed' };
        }
    }

    /**
     * Resend verification email
     */
    async resendVerificationEmail(
        email: string,
        ip: string
    ): Promise<{ success: boolean; error?: string }> {
        // Check rate limit
        const rateLimit = await rateLimiter.checkEmailResendLimit(email, ip);
        if (!rateLimit.allowed) {
            return {
                success: false,
                error: `Too many requests. Try again in ${Math.ceil(rateLimit.retryAfterMs / 60000)} minutes`,
            };
        }

        const user = await User.findOne({
            where: { email: email.toLowerCase() },
        });

        if (!user) {
            // Don't reveal if user exists
            return { success: true };
        }

        if (user.emailVerified) {
            return { success: false, error: 'Email already verified' };
        }

        // Generate new token
        const verificationToken = crypto.randomBytes(32).toString('hex');
        const verificationExpiry = new Date();
        verificationExpiry.setHours(verificationExpiry.getHours() + 24);

        user.emailVerificationToken = verificationToken;
        user.emailVerificationExpiry = verificationExpiry;
        await user.save();

        await emailService.sendVerificationEmail(email, verificationToken);

        return { success: true };
    }

    /**
     * Login user
     */
    async login(
        request: LoginRequest,
        ip: string,
        userAgent: string
    ): Promise<LoginResponse> {
        const { email, password, mfaToken, deviceFingerprint } = request;

        try {
            // Check rate limit
            const rateLimit = await rateLimiter.checkLoginAttempt(email);
            if (!rateLimit.allowed) {
                await anomalyDetector.recordLoginAttempt(
                    null,
                    email,
                    ip,
                    userAgent,
                    LoginResult.FAILED_RATE_LIMITED
                );

                if (rateLimit.isLocked) {
                    return {
                        success: false,
                        error: `Account temporarily locked. Try again in ${Math.ceil(rateLimit.retryAfterMs / 60000)} minutes`,
                    };
                }

                return {
                    success: false,
                    error: `Too many attempts. Wait ${Math.ceil(rateLimit.retryAfterMs / 1000)} seconds`,
                };
            }

            // Find user
            const user = await User.findOne({
                where: { email: email.toLowerCase() },
            });

            if (!user) {
                await rateLimiter.recordFailedLogin(email);
                await anomalyDetector.recordLoginAttempt(
                    null,
                    email,
                    ip,
                    userAgent,
                    LoginResult.FAILED_USER_NOT_FOUND
                );
                return { success: false, error: 'Invalid email or password' };
            }

            // Check if account is locked
            if (user.isLocked()) {
                await anomalyDetector.recordLoginAttempt(
                    user.id,
                    email,
                    ip,
                    userAgent,
                    LoginResult.FAILED_ACCOUNT_LOCKED
                );
                return { success: false, error: 'Account is locked. Please contact support.' };
            }

            // Verify password
            const passwordValid = await passwordHasher.verify(password, user.passwordHash);
            if (!passwordValid) {
                const { isNowLocked } = await rateLimiter.recordFailedLogin(email);
                await user.incrementFailedAttempts();

                await anomalyDetector.recordLoginAttempt(
                    user.id,
                    email,
                    ip,
                    userAgent,
                    LoginResult.FAILED_INVALID_PASSWORD
                );

                if (isNowLocked) {
                    securityLogger.accountLocked(user.id, ip);
                    await eventPublisher.publish('user.locked', {
                        userId: user.id,
                        ip,
                        timestamp: new Date().toISOString(),
                    });
                }

                return { success: false, error: 'Invalid email or password' };
            }

            // Check if email is verified
            if (!user.isEmailVerified()) {
                await anomalyDetector.recordLoginAttempt(
                    user.id,
                    email,
                    ip,
                    userAgent,
                    LoginResult.FAILED_EMAIL_NOT_VERIFIED
                );
                return { success: false, error: 'Please verify your email before logging in' };
            }

            // Check if password is expired
            if (user.isPasswordExpired()) {
                await anomalyDetector.recordLoginAttempt(
                    user.id,
                    email,
                    ip,
                    userAgent,
                    LoginResult.FAILED_PASSWORD_EXPIRED
                );
                return { success: false, error: 'Password expired. Please reset your password.' };
            }

            // Run anomaly detection
            const anomalyResult = await anomalyDetector.analyzeLogin(
                user.id,
                email,
                ip,
                userAgent,
                deviceFingerprint ? deviceManager.generateFingerprint(deviceFingerprint) : undefined
            );

            // Block if high risk
            if (anomalyResult.shouldBlock) {
                await anomalyDetector.recordLoginAttempt(
                    user.id,
                    email,
                    ip,
                    userAgent,
                    LoginResult.FAILED_SUSPICIOUS_ACTIVITY,
                    anomalyResult
                );
                return { success: false, error: 'Login blocked due to suspicious activity' };
            }

            // Check MFA
            if (user.isMfaEnabled()) {
                if (!mfaToken) {
                    // MFA required but not provided - return temporary token
                    const tempToken = crypto.randomBytes(32).toString('hex');
                    // Store temp token in Redis with short TTL (5 min)
                    // In production, implement proper temp token storage

                    await anomalyDetector.recordLoginAttempt(
                        user.id,
                        email,
                        ip,
                        userAgent,
                        LoginResult.FAILED_MFA_REQUIRED
                    );

                    return {
                        success: false,
                        requiresMfa: true,
                        mfaToken: tempToken,
                    };
                }

                // Verify MFA token
                const mfaSecret = user.getDecryptedMfaSecret();
                if (!mfaSecret || !mfaService.verifyToken(mfaSecret, mfaToken)) {
                    // Try backup codes
                    const backupCodes = user.getBackupCodes();
                    const backupValid = await user.useBackupCode(mfaToken);

                    if (!backupValid) {
                        await anomalyDetector.recordLoginAttempt(
                            user.id,
                            email,
                            ip,
                            userAgent,
                            LoginResult.FAILED_MFA_INVALID
                        );
                        return { success: false, error: 'Invalid MFA code' };
                    }
                }
            } else if (anomalyResult.shouldChallenge) {
                // Anomaly detected but MFA not enabled - require it anyway
                // In production, implement step-up authentication
                logger.warn('Anomaly detected for user without MFA', {
                    userId: user.id,
                    riskScore: anomalyResult.riskScore,
                });
            }

            // Clear failed attempts
            await rateLimiter.clearLoginAttempts(email);
            await user.resetFailedAttempts();

            // Register/update device
            let deviceId: string | undefined;
            if (deviceFingerprint) {
                const device = await deviceManager.registerDevice(
                    user.id,
                    deviceFingerprint,
                    ip
                );
                deviceId = device.id;

                // Send alert for new device
                if (device.loginCount === 1) {
                    const location = anomalyDetector.getLocationFromIp(ip);
                    await emailService.sendLoginAlert(
                        email,
                        device.deviceName,
                        ip,
                        `${location.city || 'Unknown'}, ${location.country || 'Unknown'}`,
                        new Date()
                    );
                }
            }

            // Create session
            const sessionId = await sessionManager.createSession(
                user.id,
                email,
                ip,
                userAgent,
                deviceId,
                deviceFingerprint ? deviceManager.generateFingerprint(deviceFingerprint) : undefined
            );

            // Generate token family for refresh token rotation
            const familyId = RefreshToken.generateFamilyId();

            // Generate tokens
            const tokens = jwtHandler.generateTokenPair(
                user.id,
                email,
                sessionId,
                familyId,
                deviceId
            );

            // Store refresh token
            await RefreshToken.create({
                userId: user.id,
                familyId,
                tokenHash: RefreshToken.hashToken(tokens.refreshToken),
                sessionId,
                deviceId,
                expiresAt: tokens.refreshTokenExpiresAt,
                issuedIp: ip,
                issuedUserAgent: userAgent,
            });

            // Update user login info
            await user.recordLogin(ip, deviceId ?? '');

            // Record successful login
            await anomalyDetector.recordLoginAttempt(
                user.id,
                email,
                ip,
                userAgent,
                LoginResult.SUCCESS,
                anomalyResult,
                sessionId,
                deviceId
            );

            // Publish event
            await eventPublisher.publish('user.login.success', {
                userId: user.id,
                ip,
                deviceId,
                sessionId,
                isAnomaly: anomalyResult.isAnomaly,
                timestamp: new Date().toISOString(),
            });

            securityLogger.loginSuccess(user.id, ip, deviceId);

            return {
                success: true,
                tokens,
                sessionId,
                user: {
                    id: user.id,
                    email: user.email,
                    emailVerified: user.emailVerified,
                    mfaEnabled: user.mfaEnabled,
                    kycStatus: user.kycStatus,
                },
            };
        } catch (error) {
            logger.error('Login error', { error });
            return { success: false, error: 'Login failed' };
        }
    }

    /**
     * Logout user
     */
    async logout(
        userId: string,
        sessionId: string,
        refreshToken?: string
    ): Promise<{ success: boolean }> {
        try {
            // Revoke session
            await sessionManager.revokeSession(sessionId, userId, 'user_logout');

            // Revoke refresh token if provided
            if (refreshToken) {
                const tokenHash = RefreshToken.hashToken(refreshToken);
                const token = await RefreshToken.findOne({
                    where: { tokenHash },
                });
                if (token) {
                    await token.revoke('user_logout');
                }
            }

            await eventPublisher.publish('session.terminated', {
                userId,
                sessionId,
                reason: 'logout',
                timestamp: new Date().toISOString(),
            });

            return { success: true };
        } catch (error) {
            logger.error('Logout error', { error });
            return { success: false };
        }
    }

    /**
     * Refresh tokens with rotation
     */
    async refreshTokens(
        refreshToken: string,
        ip: string,
        userAgent: string
    ): Promise<{ success: boolean; tokens?: TokenPair; error?: string }> {
        try {
            // Verify refresh token JWT
            const payload = jwtHandler.verifyRefreshToken(refreshToken);

            // Find stored token
            const tokenHash = RefreshToken.hashToken(refreshToken);
            const storedToken = await RefreshToken.findOne({
                where: { tokenHash },
            });

            if (!storedToken) {
                return { success: false, error: 'Invalid refresh token' };
            }

            // Check if token was already used (THEFT DETECTED)
            if (storedToken.wasUsed()) {
                // Token reuse = theft - revoke entire family
                await RefreshToken.update(
                    { revokedAt: new Date(), revokedReason: 'token_theft_detected' },
                    { where: { familyId: storedToken.familyId } }
                );

                // Revoke all user sessions
                await sessionManager.revokeAllUserSessions(
                    payload.sub,
                    'token_theft_detected'
                );

                securityLogger.tokenTheftDetected(payload.sub, storedToken.familyId);

                await eventPublisher.publish('security.token_theft', {
                    userId: payload.sub,
                    familyId: storedToken.familyId,
                    ip,
                    timestamp: new Date().toISOString(),
                });

                return { success: false, error: 'Security violation detected' };
            }

            // Check if token is valid
            if (!storedToken.isValid()) {
                return { success: false, error: 'Refresh token expired or revoked' };
            }

            // Mark token as used
            await storedToken.markAsUsed();

            // Get user
            const user = await User.findByPk(payload.sub);
            if (!user) {
                return { success: false, error: 'User not found' };
            }

            // Generate new token pair
            const newTokens = jwtHandler.generateTokenPair(
                user.id,
                user.email,
                payload.sessionId,
                storedToken.familyId,
                storedToken.deviceId ?? undefined
            );

            // Store new refresh token with reference to parent
            await RefreshToken.create({
                userId: user.id,
                familyId: storedToken.familyId,
                tokenHash: RefreshToken.hashToken(newTokens.refreshToken),
                parentTokenHash: tokenHash,
                sessionId: payload.sessionId,
                deviceId: storedToken.deviceId,
                expiresAt: newTokens.refreshTokenExpiresAt,
                issuedIp: ip,
                issuedUserAgent: userAgent,
            });

            return { success: true, tokens: newTokens };
        } catch (error) {
            if (error instanceof TokenExpiredError) {
                return { success: false, error: 'Refresh token expired' };
            }
            if (error instanceof TokenVerificationError) {
                return { success: false, error: 'Invalid refresh token' };
            }
            logger.error('Token refresh error', { error });
            return { success: false, error: 'Token refresh failed' };
        }
    }

    /**
     * Request password reset
     */
    async forgotPassword(
        email: string,
        ip: string,
        userAgent: string
    ): Promise<{ success: boolean }> {
        try {
            const user = await User.findOne({
                where: { email: email.toLowerCase() },
            });

            // Always return success to prevent email enumeration
            if (!user) {
                return { success: true };
            }

            // Invalidate any existing reset tokens
            await PasswordResetToken.update(
                { usedAt: new Date() },
                { where: { userId: user.id, usedAt: null } }
            );

            // Generate token
            const token = crypto.randomBytes(32).toString('hex');
            const expiresAt = new Date();
            expiresAt.setHours(expiresAt.getHours() + 1);

            await PasswordResetToken.create({
                userId: user.id,
                tokenHash: PasswordResetToken.hashToken(token),
                expiresAt,
                requestedIp: ip,
                requestedUserAgent: userAgent,
            });

            await emailService.sendPasswordResetEmail(email, token, 60);

            await eventPublisher.publish('user.password.reset_requested', {
                userId: user.id,
                ip,
                timestamp: new Date().toISOString(),
            });

            return { success: true };
        } catch (error) {
            logger.error('Password reset request error', { error });
            return { success: true }; // Don't reveal errors
        }
    }

    /**
     * Reset password with token
     */
    async resetPassword(
        token: string,
        newPassword: string,
        ip: string
    ): Promise<{ success: boolean; error?: string }> {
        try {
            // Find token
            const tokenHash = PasswordResetToken.hashToken(token);
            const resetToken = await PasswordResetToken.findOne({
                where: { tokenHash },
            });

            if (!resetToken || !resetToken.isValid()) {
                return { success: false, error: 'Invalid or expired reset token' };
            }

            // Get user
            const user = await User.findByPk(resetToken.userId);
            if (!user) {
                return { success: false, error: 'User not found' };
            }

            // Validate new password
            try {
                passwordHasher.validatePasswordStrength(newPassword);
            } catch (error) {
                if (error instanceof PasswordValidationError) {
                    return { success: false, error: error.errors.join('. ') };
                }
                throw error;
            }

            // Check breach database
            const breachResult = await breachChecker.isPasswordSecure(newPassword);
            if (!breachResult.secure) {
                return { success: false, error: breachResult.reason };
            }

            // Check password history
            const passwordHistory = await PasswordHistory.findAll({
                where: { userId: user.id },
                order: [['createdAt', 'DESC']],
                limit: config.security.passwordHistoryCount,
            });

            const historyHashes = passwordHistory.map(h => h.passwordHash);
            if (await passwordHasher.matchesAnyInHistory(newPassword, historyHashes)) {
                return {
                    success: false,
                    error: `Cannot reuse any of your last ${config.security.passwordHistoryCount} passwords`,
                };
            }

            // Hash new password
            const passwordHash = await passwordHasher.hash(newPassword);

            // Update user
            user.passwordHash = passwordHash;
            user.passwordChangedAt = new Date();
            user.passwordExpiryAt = new Date(
                Date.now() + config.security.passwordExpiryDays * 24 * 60 * 60 * 1000
            );
            await user.save();

            // Store in history
            await PasswordHistory.create({
                userId: user.id,
                passwordHash,
            });

            // Mark token as used
            await resetToken.markAsUsed();

            // Revoke all sessions (session fixation protection)
            await sessionManager.revokeAllUserSessions(user.id, 'password_reset');

            // Revoke all refresh tokens
            await RefreshToken.update(
                { revokedAt: new Date(), revokedReason: 'password_reset' },
                { where: { userId: user.id, revokedAt: null } }
            );

            // Send notification
            await emailService.sendPasswordChangedNotification(user.email, ip);

            await eventPublisher.publish('user.password.reset', {
                userId: user.id,
                ip,
                timestamp: new Date().toISOString(),
            });

            securityLogger.passwordChanged(user.id, ip);

            return { success: true };
        } catch (error) {
            logger.error('Password reset error', { error });
            return { success: false, error: 'Password reset failed' };
        }
    }

    /**
     * Change password (authenticated)
     */
    async changePassword(
        userId: string,
        currentPassword: string,
        newPassword: string,
        ip: string,
        currentSessionId?: string
    ): Promise<{ success: boolean; error?: string }> {
        try {
            const user = await User.findByPk(userId);
            if (!user) {
                return { success: false, error: 'User not found' };
            }

            // Verify current password
            if (!(await passwordHasher.verify(currentPassword, user.passwordHash))) {
                return { success: false, error: 'Current password is incorrect' };
            }

            // Same validation as resetPassword
            try {
                passwordHasher.validatePasswordStrength(newPassword);
            } catch (error) {
                if (error instanceof PasswordValidationError) {
                    return { success: false, error: error.errors.join('. ') };
                }
                throw error;
            }

            const breachResult = await breachChecker.isPasswordSecure(newPassword);
            if (!breachResult.secure) {
                return { success: false, error: breachResult.reason };
            }

            const passwordHistory = await PasswordHistory.findAll({
                where: { userId: user.id },
                order: [['createdAt', 'DESC']],
                limit: config.security.passwordHistoryCount,
            });

            if (await passwordHasher.matchesAnyInHistory(newPassword, passwordHistory.map(h => h.passwordHash))) {
                return {
                    success: false,
                    error: `Cannot reuse any of your last ${config.security.passwordHistoryCount} passwords`,
                };
            }

            // Update password
            const passwordHash = await passwordHasher.hash(newPassword);
            user.passwordHash = passwordHash;
            user.passwordChangedAt = new Date();
            user.passwordExpiryAt = new Date(
                Date.now() + config.security.passwordExpiryDays * 24 * 60 * 60 * 1000
            );
            await user.save();

            await PasswordHistory.create({
                userId: user.id,
                passwordHash,
            });

            // Revoke other sessions but keep current (session fixation protection with convenience)
            if (currentSessionId) {
                await sessionManager.revokeAllUserSessions(userId, 'password_change', currentSessionId);
                // Regenerate current session
                await sessionManager.regenerateSession(currentSessionId);
            } else {
                await sessionManager.revokeAllUserSessions(userId, 'password_change');
            }

            await emailService.sendPasswordChangedNotification(user.email, ip);

            await eventPublisher.publish('user.password.changed', {
                userId: user.id,
                ip,
                timestamp: new Date().toISOString(),
            });

            securityLogger.passwordChanged(userId, ip);

            return { success: true };
        } catch (error) {
            logger.error('Password change error', { error });
            return { success: false, error: 'Password change failed' };
        }
    }

    /**
     * Setup MFA for user
     */
    async setupMFA(userId: string): Promise<{
        success: boolean;
        secret?: string;
        qrCode?: string;
        backupCodes?: string[];
        error?: string;
    }> {
        try {
            const user = await User.findByPk(userId);
            if (!user) {
                return { success: false, error: 'User not found' };
            }

            if (user.mfaEnabled) {
                return { success: false, error: 'MFA is already enabled' };
            }

            const mfaSetup = await mfaService.setupMFA(user.email);

            return {
                success: true,
                secret: mfaSetup.secret,
                qrCode: mfaSetup.qrCodeDataUrl,
                backupCodes: mfaSetup.backupCodes,
            };
        } catch (error) {
            logger.error('MFA setup error', { error });
            return { success: false, error: 'MFA setup failed' };
        }
    }

    /**
     * Verify and enable MFA
     */
    async verifyAndEnableMFA(
        userId: string,
        secret: string,
        token: string,
        backupCodes: string[]
    ): Promise<{ success: boolean; error?: string }> {
        try {
            const user = await User.findByPk(userId);
            if (!user) {
                return { success: false, error: 'User not found' };
            }

            // Verify the token
            if (!mfaService.verifyToken(secret, token)) {
                return { success: false, error: 'Invalid verification code' };
            }

            // Enable MFA
            user.setEncryptedMfaSecret(secret);
            user.setBackupCodes(mfaService.hashBackupCodes(backupCodes));
            user.mfaEnabled = true;
            await user.save();

            await emailService.sendMFAEnabledNotification(user.email);

            await eventPublisher.publish('user.mfa.enabled', {
                userId: user.id,
                timestamp: new Date().toISOString(),
            });

            securityLogger.mfaEnabled(userId);

            return { success: true };
        } catch (error) {
            logger.error('MFA enable error', { error });
            return { success: false, error: 'Failed to enable MFA' };
        }
    }
}

// Export singleton
export const authService = new AuthService();
