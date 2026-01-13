import { Request, Response, NextFunction } from 'express';
import crypto from 'crypto';
import { logger } from './requestLogger';

/**
 * Security Headers Middleware
 * Adds additional security headers beyond Helmet
 * 
 * These headers provide defense-in-depth security:
 * - Request ID tracking for audit trails
 * - Cache control for sensitive data
 * - Custom security policies
 */

/**
 * Generate a cryptographically secure request ID
 */
function generateRequestId(): string {
    return crypto.randomBytes(16).toString('hex');
}

/**
 * Security headers middleware for banking-grade protection
 */
export function securityHeadersMiddleware(req: Request, res: Response, next: NextFunction): void {
    // Generate unique request ID for correlation and audit
    const requestId = req.headers['x-request-id'] as string || generateRequestId();
    req.headers['x-request-id'] = requestId;
    res.setHeader('X-Request-ID', requestId);

    // Prevent caching of sensitive authentication responses
    res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, proxy-revalidate');
    res.setHeader('Pragma', 'no-cache');
    res.setHeader('Expires', '0');
    res.setHeader('Surrogate-Control', 'no-store');

    // Clear site data on logout (will be honored by browsers)
    if (req.path.includes('/logout')) {
        res.setHeader('Clear-Site-Data', '"cache", "cookies", "storage"');
    }

    // Permissions Policy (formerly Feature-Policy)
    // Disable unnecessary browser features
    res.setHeader('Permissions-Policy', [
        'accelerometer=()',
        'camera=()',
        'geolocation=()',
        'gyroscope=()',
        'magnetometer=()',
        'microphone=()',
        'payment=()',
        'usb=()',
        'interest-cohort=()', // Disable FLoC
    ].join(', '));

    // Cross-Origin policies for additional isolation
    res.setHeader('Cross-Origin-Opener-Policy', 'same-origin');
    res.setHeader('Cross-Origin-Resource-Policy', 'same-origin');
    res.setHeader('Cross-Origin-Embedder-Policy', 'require-corp');

    next();
}

/**
 * Request fingerprinting for anomaly detection
 * Creates a hash of request characteristics for tracking
 */
export function getRequestFingerprint(req: Request): string {
    const components = [
        req.headers['user-agent'] || '',
        req.headers['accept-language'] || '',
        req.headers['accept-encoding'] || '',
        req.ip || '',
    ];

    return crypto
        .createHash('sha256')
        .update(components.join('|'))
        .digest('hex')
        .substring(0, 16);
}

/**
 * Rate limit headers middleware
 * Adds standard rate limit headers to responses
 */
export function rateLimitHeadersMiddleware(
    limit: number,
    remaining: number,
    resetTime: number
) {
    return (_req: Request, res: Response, next: NextFunction): void => {
        res.setHeader('X-RateLimit-Limit', limit.toString());
        res.setHeader('X-RateLimit-Remaining', remaining.toString());
        res.setHeader('X-RateLimit-Reset', resetTime.toString());
        next();
    };
}

/**
 * Sensitive endpoint protection middleware
 * Adds extra security for critical operations
 */
export function sensitiveEndpointMiddleware(req: Request, res: Response, next: NextFunction): void {
    // Log access to sensitive endpoints
    logger.info('Sensitive endpoint accessed', {
        path: req.path,
        method: req.method,
        ip: req.ip,
        userAgent: req.headers['user-agent'],
        requestId: req.headers['x-request-id'],
    });

    // Require recent authentication for sensitive operations
    // This is handled by the auth middleware, but we add headers for client awareness
    res.setHeader('X-Sensitive-Operation', 'true');

    // Shorter cache control for sensitive data
    res.setHeader('Cache-Control', 'no-store, max-age=0');

    next();
}
