import { Request, Response, NextFunction } from 'express';
import { jwtHandler, TokenExpiredError, TokenVerificationError } from '../utils/JWTHandler';
import { sessionManager } from '../services/SessionManager';
import { tokenBlacklist } from '../services/TokenBlacklist';
import { rateLimiter } from '../services/RateLimiter';
import { ipBlockingService } from '../services/IPBlockingService';
import { Errors } from './errorHandler';
import { logger } from './requestLogger';
import crypto from 'crypto';

/**
 * Extended request with authenticated user info
 */
export interface AuthenticatedRequest extends Request {
    user: {
        id: string;
        email: string;
        sessionId: string;
        deviceId?: string;
    };
    tokenJti?: string;
}

/**
 * Get client IP from request
 */
function getClientIp(req: Request): string {
    const forwarded = req.headers['x-forwarded-for'];
    if (typeof forwarded === 'string') {
        return forwarded.split(',')[0]?.trim() ?? req.ip ?? '0.0.0.0';
    }
    return req.ip ?? '0.0.0.0';
}

/**
 * Authentication Middleware
 * - check IP against blocklist
 * - Verifies JWT token
 * - Checks token blacklist for revocation
 * - Validates session is still active
 * - Enforces per-JWT rate limiting
 */
export async function authenticationMiddleware(
    req: Request,
    res: Response,
    next: NextFunction
): Promise<void> {
    try {
        // Check IP blocking first (Fastest reject)
        const ip = getClientIp(req);
        const ipBlock = await ipBlockingService.isBlocked(ip);
        if (ipBlock.blocked) {
            throw Errors.forbidden(`Access Denied: IP blocked for security reasons. Reason: ${ipBlock.reason}`);
        }

        const authHeader = req.headers.authorization;

        if (!authHeader || !authHeader.startsWith('Bearer ')) {
            throw Errors.unauthorized('Missing or invalid authorization header');
        }

        const token = authHeader.substring(7);

        // Hash token for blacklist check
        const tokenHash = crypto.createHash('sha256').update(token).digest('hex');

        // Check if token is blacklisted
        if (await tokenBlacklist.isBlacklisted(tokenHash)) {
            logger.warn('Blacklisted token used', {
                tokenHash: tokenHash.substring(0, 16) + '...',
                ip: getClientIp(req),
            });
            throw Errors.unauthorized('Token has been revoked');
        }

        // Verify JWT
        let payload;
        try {
            payload = jwtHandler.verifyAccessToken(token);
        } catch (error) {
            if (error instanceof TokenExpiredError) {
                throw Errors.unauthorized('Token has expired');
            }
            if (error instanceof TokenVerificationError) {
                throw Errors.unauthorized('Invalid token');
            }
            throw error;
        }

        // Check if user is globally blocked (token theft response)
        if (await tokenBlacklist.isUserBlocked(payload.sub)) {
            logger.warn('Blocked user attempted access', {
                userId: payload.sub,
                ip: getClientIp(req),
            });
            throw Errors.unauthorized('Account temporarily blocked. Please reset your password.');
        }

        // Validate session is still active
        const session = await sessionManager.validateSession(payload.sessionId);
        if (!session) {
            throw Errors.unauthorized('Session expired or revoked');
        }

        // Check per-JWT rate limit
        if (payload.jti) {
            const jwtRateLimit = await rateLimiter.checkJwtRateLimit(payload.jti);
            if (!jwtRateLimit.allowed) {
                throw Errors.tooManyRequests('Too many requests with this token', jwtRateLimit.retryAfterMs / 1000);
            }
        }

        // Attach user info to request
        (req as AuthenticatedRequest).user = {
            id: payload.sub,
            email: payload.email,
            sessionId: payload.sessionId,
            deviceId: payload.deviceId,
        };
        (req as AuthenticatedRequest).tokenJti = payload.jti;

        next();
    } catch (error) {
        next(error);
    }
}

/**
 * Optional authentication - doesn't fail if no token
 */
export async function optionalAuthMiddleware(
    req: Request,
    res: Response,
    next: NextFunction
): Promise<void> {
    const authHeader = req.headers.authorization;

    if (!authHeader || !authHeader.startsWith('Bearer ')) {
        next();
        return;
    }

    // If token is provided, validate it
    await authenticationMiddleware(req, res, next);
}

/**
 * Require specific roles (placeholder for RBAC)
 */
export function requireRole(...roles: string[]) {
    return async (req: Request, res: Response, next: NextFunction): Promise<void> => {
        const authReq = req as AuthenticatedRequest;

        if (!authReq.user) {
            next(Errors.unauthorized('Authentication required'));
            return;
        }

        // TODO: Implement role checking from user profile or JWT claims
        // For now, allow all authenticated users
        next();
    };
}
