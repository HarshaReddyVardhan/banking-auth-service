import { Request, Response, NextFunction } from 'express';
import { AuditLog, AuditEventType } from '../models/AuditLog';
import { logger } from './requestLogger';

/**
 * Audit Logging Middleware
 * Automatically captures all requests in the audit log
 */

// Request types that should be audited
const AUDITABLE_METHODS = ['POST', 'PUT', 'PATCH', 'DELETE'];

// Paths that should skip audit logging
const SKIP_PATHS = ['/health', '/metrics', '/favicon.ico'];

// Map request paths to audit event types
const PATH_TO_EVENT: Record<string, AuditEventType> = {
    '/auth/register': AuditEventType.USER_REGISTERED,
    '/auth/login': AuditEventType.USER_LOGIN_SUCCESS,
    '/auth/logout': AuditEventType.USER_LOGOUT,
    '/auth/verify-email': AuditEventType.EMAIL_VERIFIED,
    '/auth/forgot-password': AuditEventType.PASSWORD_RESET_REQUESTED,
    '/auth/reset-password': AuditEventType.PASSWORD_RESET_COMPLETED,
    '/auth/change-password': AuditEventType.PASSWORD_CHANGED,
    '/auth/mfa/setup': AuditEventType.MFA_ENABLED,
    '/auth/mfa/verify': AuditEventType.MFA_VERIFIED,
    '/auth/refresh': AuditEventType.TOKEN_REFRESH,
};

// Sensitive fields to redact from audit payload
const SENSITIVE_FIELDS = [
    'password',
    'currentPassword',
    'newPassword',
    'mfaToken',
    'token',
    'refreshToken',
    'accessToken',
    'secret',
    'backupCodes',
];

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
 * Redact sensitive fields from object
 */
function redactSensitiveData(obj: Record<string, unknown>): Record<string, unknown> {
    const result: Record<string, unknown> = {};

    for (const [key, value] of Object.entries(obj)) {
        if (SENSITIVE_FIELDS.some(f => key.toLowerCase().includes(f.toLowerCase()))) {
            result[key] = '[REDACTED]';
        } else if (typeof value === 'object' && value !== null && !Array.isArray(value)) {
            result[key] = redactSensitiveData(value as Record<string, unknown>);
        } else {
            result[key] = value;
        }
    }

    return result;
}

/**
 * Audit logging middleware
 */
export function auditLoggingMiddleware(
    req: Request,
    res: Response,
    next: NextFunction
): void {
    // Skip non-auditable methods
    if (!AUDITABLE_METHODS.includes(req.method)) {
        next();
        return;
    }

    // Skip certain paths
    if (SKIP_PATHS.some(p => req.path.startsWith(p))) {
        next();
        return;
    }

    // Capture response on finish
    const originalSend = res.send;
    let responseBody: unknown;

    res.send = function (body: unknown): Response {
        responseBody = body;
        return originalSend.call(this, body);
    };

    res.on('finish', async () => {
        try {
            const eventType = PATH_TO_EVENT[req.path];

            // Only audit if we have a mapping or it's a sensitive operation
            if (!eventType && res.statusCode < 400) {
                return;
            }

            // Determine actual event type based on response status
            let actualEventType = eventType;
            if (req.path === '/auth/login' && res.statusCode !== 200) {
                actualEventType = AuditEventType.USER_LOGIN_FAILED;
            }

            // Get user info from request (set by auth middleware)
            const user = (req as { user?: { id: string; sessionId: string } }).user;
            const correlationId = (req as { correlationId?: string }).correlationId;

            // Build audit payload
            const payload = redactSensitiveData({
                method: req.method,
                path: req.path,
                query: req.query,
                body: req.body ?? {},
                statusCode: res.statusCode,
                correlationId,
                responseSuccess: res.statusCode < 400,
            });

            // Determine severity
            let severity: 'INFO' | 'WARNING' | 'CRITICAL' = 'INFO';
            if (res.statusCode >= 500) {
                severity = 'CRITICAL';
            } else if (res.statusCode >= 400) {
                severity = 'WARNING';
            } else if (actualEventType === AuditEventType.TOKEN_THEFT_DETECTED) {
                severity = 'CRITICAL';
            }

            // Log to audit trail (async, non-blocking)
            await AuditLog.log({
                eventType: actualEventType ?? AuditEventType.SETTINGS_CHANGED,
                userId: user?.id ?? null,
                actorId: user?.id ?? null,
                resourceType: 'auth',
                resourceId: req.path,
                payload,
                ipAddress: getClientIp(req),
                userAgent: req.headers['user-agent'] ?? null,
                sessionId: user?.sessionId ?? null,
                severity,
            });
        } catch (error) {
            // Don't fail the request if audit logging fails
            logger.error('Audit logging failed', { error, path: req.path });
        }
    });

    next();
}
