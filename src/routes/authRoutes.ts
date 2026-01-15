import { Router, Request, Response } from 'express';
import { authService } from '../services/AuthService';
import { sessionManager } from '../services/SessionManager';
import { deviceManager } from '../services/DeviceManager';
import { jwtHandler } from '../utils/JWTHandler';
import { validate } from '../middleware/inputValidator';
import { asyncHandler, Errors } from '../middleware/errorHandler';
import { rateLimiter } from '../services/RateLimiter';

const router = Router();

/**
 * Helper to get client IP
 */
function getClientIp(req: Request): string {
    const forwarded = req.headers['x-forwarded-for'];
    if (typeof forwarded === 'string') {
        return forwarded.split(',')[0]?.trim() ?? req.ip ?? '0.0.0.0';
    }
    return req.ip ?? '0.0.0.0';
}

/**
 * Helper to get user agent
 */
function getUserAgent(req: Request): string {
    return req.headers['user-agent'] ?? 'Unknown';
}

/**
 * Middleware to verify access token
 */
async function authMiddleware(req: Request, _res: Response, next: Function): Promise<void> {
    const authHeader = req.headers.authorization;

    if (!authHeader || !authHeader.startsWith('Bearer ')) {
        throw Errors.unauthorized('Missing or invalid authorization header');
    }

    const token = authHeader.substring(7);

    try {
        const payload = jwtHandler.verifyAccessToken(token);

        // Validate session is still active
        const session = await sessionManager.validateSession(payload.sessionId);
        if (!session) {
            throw Errors.unauthorized('Session expired or revoked');
        }

        // Attach user info to request
        (req as AuthenticatedRequest).user = {
            id: payload.sub,
            email: payload.email,
            sessionId: payload.sessionId,
            deviceId: payload.deviceId,
        };

        next();
    } catch (error) {
        throw Errors.unauthorized('Invalid or expired token');
    }
}

/**
 * Extended request with user info
 */
interface AuthenticatedRequest extends Request {
    user: {
        id: string;
        email: string;
        sessionId: string;
        deviceId?: string;
    };
}

// ==================== PUBLIC ROUTES ====================

/**
 * POST /auth/register
 * Register a new user
 */
router.post(
    '/register',
    validate('register'),
    asyncHandler(async (req: Request, res: Response) => {
        const result = await authService.register(
            req.body,
            getClientIp(req),
            getUserAgent(req)
        );

        if (!result.success) {
            res.status(400).json({ success: false, error: result.error });
            return;
        }

        res.status(201).json({
            success: true,
            message: 'Registration successful. Please check your email to verify your account.',
            userId: result.userId,
        });
    })
);

/**
 * POST /auth/verify-email
 * Verify email address
 */
router.post(
    '/verify-email',
    validate('verifyEmail'),
    asyncHandler(async (req: Request, res: Response) => {
        const result = await authService.verifyEmail(req.body.token);

        if (!result.success) {
            res.status(400).json({ success: false, error: result.error });
            return;
        }

        res.json({
            success: true,
            message: 'Email verified successfully. You can now log in.',
        });
    })
);

/**
 * POST /auth/resend-verification
 * Resend verification email
 */
router.post(
    '/resend-verification',
    validate('resendVerification'),
    asyncHandler(async (req: Request, res: Response) => {
        const _result = await authService.resendVerificationEmail(
            req.body.email,
            getClientIp(req)
        );

        // Always return success to prevent email enumeration
        res.json({
            success: true,
            message: 'If an account exists with this email, a verification link has been sent.',
        });
    })
);

/**
 * POST /auth/login
 * Login user
 */
router.post(
    '/login',
    validate('login'),
    asyncHandler(async (req: Request, res: Response) => {
        // Check IP rate limit
        const ipLimit = await rateLimiter.checkIpRateLimit(getClientIp(req));
        if (!ipLimit.allowed) {
            res.status(429).json({
                success: false,
                error: 'Too many requests. Please try again later.',
                retryAfter: Math.ceil(ipLimit.retryAfterMs / 1000),
            });
            return;
        }

        const result = await authService.login(
            req.body,
            getClientIp(req),
            getUserAgent(req)
        );

        if (!result.success) {
            const statusCode = result.requiresMfa ? 200 : 401;
            res.status(statusCode).json(result);
            return;
        }

        res.json(result);
    })
);

/**
 * POST /auth/login/mfa
 * Complete login with MFA
 */
router.post(
    '/login/mfa',
    validate('mfaLogin'),
    asyncHandler(async (req: Request, res: Response) => {
        // Check IP rate limit
        const ipLimit = await rateLimiter.checkIpRateLimit(getClientIp(req));
        if (!ipLimit.allowed) {
            res.status(429).json({
                success: false,
                error: 'Too many requests. Please try again later.',
                retryAfter: Math.ceil(ipLimit.retryAfterMs / 1000),
            });
            return;
        }

        const result = await authService.verifyMfaLogin(
            req.body.tempToken,
            req.body.mfaToken,
            getClientIp(req),
            getUserAgent(req),
            req.body.deviceFingerprint
        );

        if (!result.success) {
            res.status(401).json(result);
            return;
        }

        res.json(result);
    })
);

/**
 * POST /auth/forgot-password
 * Request password reset
 */
router.post(
    '/forgot-password',
    validate('forgotPassword'),
    asyncHandler(async (req: Request, res: Response) => {
        await authService.forgotPassword(
            req.body.email,
            getClientIp(req),
            getUserAgent(req)
        );

        // Always return success to prevent email enumeration
        res.json({
            success: true,
            message: 'If an account exists with this email, a password reset link has been sent.',
        });
    })
);

/**
 * POST /auth/reset-password
 * Reset password with token
 */
router.post(
    '/reset-password',
    validate('resetPassword'),
    asyncHandler(async (req: Request, res: Response) => {
        const result = await authService.resetPassword(
            req.body.token,
            req.body.password,
            getClientIp(req)
        );

        if (!result.success) {
            res.status(400).json({ success: false, error: result.error });
            return;
        }

        res.json({
            success: true,
            message: 'Password reset successful. You can now log in with your new password.',
        });
    })
);

/**
 * POST /auth/refresh
 * Refresh access token
 */
router.post(
    '/refresh',
    validate('refreshToken'),
    asyncHandler(async (req: Request, res: Response) => {
        const result = await authService.refreshTokens(
            req.body.refreshToken,
            getClientIp(req),
            getUserAgent(req)
        );

        if (!result.success) {
            res.status(401).json({ success: false, error: result.error });
            return;
        }

        res.json({
            success: true,
            tokens: result.tokens,
        });
    })
);

// ==================== AUTHENTICATED ROUTES ====================

/**
 * POST /auth/logout
 * Logout current session
 */
router.post(
    '/logout',
    asyncHandler(async (req: Request, res: Response) => {
        await authMiddleware(req, res, async () => {
            const { user } = req as AuthenticatedRequest;

            await authService.logout(
                user.id,
                user.sessionId,
                req.body.refreshToken
            );

            res.json({
                success: true,
                message: 'Logged out successfully',
            });
        });
    })
);

/**
 * POST /auth/change-password
 * Change password (authenticated)
 */
router.post(
    '/change-password',
    validate('changePassword'),
    asyncHandler(async (req: Request, res: Response) => {
        await authMiddleware(req, res, async () => {
            const { user } = req as AuthenticatedRequest;

            const result = await authService.changePassword(
                user.id,
                req.body.currentPassword,
                req.body.newPassword,
                getClientIp(req),
                user.sessionId
            );

            if (!result.success) {
                res.status(400).json({ success: false, error: result.error });
                return;
            }

            res.json({
                success: true,
                message: 'Password changed successfully',
            });
        });
    })
);

/**
 * POST /auth/mfa/setup
 * Initialize MFA setup
 */
router.post(
    '/mfa/setup',
    asyncHandler(async (req: Request, res: Response) => {
        await authMiddleware(req, res, async () => {
            const { user } = req as AuthenticatedRequest;

            const result = await authService.setupMFA(user.id);

            if (!result.success) {
                res.status(400).json({ success: false, error: result.error });
                return;
            }

            res.json({
                success: true,
                secret: result.secret,
                qrCode: result.qrCode,
                backupCodes: result.backupCodes,
            });
        });
    })
);

/**
 * POST /auth/mfa/verify
 * Verify and enable MFA
 */
router.post(
    '/mfa/verify',
    validate('mfaVerify'),
    asyncHandler(async (req: Request, res: Response) => {
        await authMiddleware(req, res, async () => {
            const { user } = req as AuthenticatedRequest;

            const result = await authService.verifyAndEnableMFA(
                user.id,
                req.body.secret,
                req.body.token,
                req.body.backupCodes
            );

            if (!result.success) {
                res.status(400).json({ success: false, error: result.error });
                return;
            }

            res.json({
                success: true,
                message: 'MFA enabled successfully',
            });
        });
    })
);

/**
 * GET /auth/sessions
 * List active sessions
 */
router.get(
    '/sessions',
    asyncHandler(async (req: Request, res: Response) => {
        await authMiddleware(req, res, async () => {
            const { user } = req as AuthenticatedRequest;

            const sessions = await sessionManager.getUserSessions(user.id);

            res.json({
                success: true,
                sessions: sessions.map(s => ({
                    id: s.sessionId,
                    ip: s.data.ip,
                    userAgent: s.data.userAgent,
                    createdAt: new Date(s.data.createdAt).toISOString(),
                    lastActivityAt: new Date(s.data.lastActivityAt).toISOString(),
                    current: s.sessionId === user.sessionId,
                })),
            });
        });
    })
);

/**
 * DELETE /auth/sessions/:id
 * Revoke a specific session
 */
router.delete(
    '/sessions/:id',
    asyncHandler(async (req: Request, res: Response) => {
        await authMiddleware(req, res, async () => {
            const { user } = req as AuthenticatedRequest;
            const sessionId = req.params['id'];

            if (!sessionId) {
                res.status(400).json({ success: false, error: 'Session ID required' });
                return;
            }

            const revoked = await sessionManager.revokeSession(
                sessionId,
                user.id,
                'user_revoked'
            );

            if (!revoked) {
                res.status(404).json({ success: false, error: 'Session not found' });
                return;
            }

            res.json({
                success: true,
                message: 'Session revoked',
            });
        });
    })
);

/**
 * GET /auth/devices
 * List registered devices
 */
router.get(
    '/devices',
    asyncHandler(async (req: Request, res: Response) => {
        await authMiddleware(req, res, async () => {
            const { user } = req as AuthenticatedRequest;

            const devices = await deviceManager.getUserDevices(user.id);

            res.json({
                success: true,
                devices: devices.map(d => ({
                    id: d.id,
                    name: d.deviceName,
                    type: d.deviceType,
                    browser: d.browser,
                    os: d.os,
                    trusted: d.isTrusted(),
                    lastUsedAt: d.lastUsedAt?.toISOString(),
                    lastCountry: d.lastCountry,
                    current: d.id === user.deviceId,
                })),
            });
        });
    })
);

/**
 * DELETE /auth/devices/:id
 * Revoke a device
 */
router.delete(
    '/devices/:id',
    asyncHandler(async (req: Request, res: Response) => {
        await authMiddleware(req, res, async () => {
            const { user } = req as AuthenticatedRequest;
            const deviceId = req.params['id'];

            if (!deviceId) {
                res.status(400).json({ success: false, error: 'Device ID required' });
                return;
            }

            const revoked = await deviceManager.revokeDevice(user.id, deviceId);

            if (!revoked) {
                res.status(404).json({ success: false, error: 'Device not found' });
                return;
            }

            res.json({
                success: true,
                message: 'Device revoked',
            });
        });
    })
);

/**
 * POST /auth/devices/:id/trust
 * Trust a device
 */
router.post(
    '/devices/:id/trust',
    asyncHandler(async (req: Request, res: Response) => {
        await authMiddleware(req, res, async () => {
            const { user } = req as AuthenticatedRequest;
            const deviceId = req.params['id'];

            if (!deviceId) {
                res.status(400).json({ success: false, error: 'Device ID required' });
                return;
            }

            const device = await deviceManager.trustDevice(user.id, deviceId);

            if (!device) {
                res.status(404).json({ success: false, error: 'Device not found' });
                return;
            }

            res.json({
                success: true,
                message: 'Device trusted',
            });
        });
    })
);

/**
 * GET /health
 * Health check endpoint
 */
router.get('/health', (_req: Request, res: Response) => {
    res.json({
        status: 'healthy',
        service: 'banking-auth-service',
        timestamp: new Date().toISOString(),
    });
});

export default router;
