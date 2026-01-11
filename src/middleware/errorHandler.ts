import { Request, Response, NextFunction } from 'express';
import { logger } from './requestLogger';

/**
 * Custom application error
 */
export class AppError extends Error {
    public readonly statusCode: number;
    public readonly isOperational: boolean;
    public readonly code: string;

    constructor(
        message: string,
        statusCode: number = 500,
        code: string = 'INTERNAL_ERROR',
        isOperational: boolean = true
    ) {
        super(message);
        this.statusCode = statusCode;
        this.code = code;
        this.isOperational = isOperational;

        Error.captureStackTrace(this, this.constructor);
    }
}

/**
 * Common error types
 */
export const Errors = {
    unauthorized: (message = 'Unauthorized') =>
        new AppError(message, 401, 'UNAUTHORIZED'),

    forbidden: (message = 'Forbidden') =>
        new AppError(message, 403, 'FORBIDDEN'),

    notFound: (message = 'Not found') =>
        new AppError(message, 404, 'NOT_FOUND'),

    badRequest: (message = 'Bad request') =>
        new AppError(message, 400, 'BAD_REQUEST'),

    conflict: (message = 'Conflict') =>
        new AppError(message, 409, 'CONFLICT'),

    tooManyRequests: (message = 'Too many requests', retryAfter?: number) => {
        const error = new AppError(message, 429, 'TOO_MANY_REQUESTS');
        (error as { retryAfter?: number }).retryAfter = retryAfter;
        return error;
    },

    internal: (message = 'Internal server error') =>
        new AppError(message, 500, 'INTERNAL_ERROR', false),
};

/**
 * Error response structure
 */
interface ErrorResponse {
    success: false;
    error: {
        code: string;
        message: string;
        details?: unknown;
    };
    requestId?: string;
}

/**
 * Global error handler middleware
 */
export function errorHandler(
    err: Error,
    req: Request,
    res: Response,
    _next: NextFunction
): void {
    // Get correlation ID from request if available
    const requestId = (req as { correlationId?: string }).correlationId;

    // Determine error details
    let statusCode = 500;
    let code = 'INTERNAL_ERROR';
    let message = 'An unexpected error occurred';
    let isOperational = false;

    if (err instanceof AppError) {
        statusCode = err.statusCode;
        code = err.code;
        message = err.message;
        isOperational = err.isOperational;
    } else if (err.name === 'SyntaxError' && 'body' in err) {
        // JSON parse error
        statusCode = 400;
        code = 'INVALID_JSON';
        message = 'Invalid JSON in request body';
        isOperational = true;
    } else if (err.name === 'UnauthorizedError') {
        // JWT errors from express-jwt
        statusCode = 401;
        code = 'INVALID_TOKEN';
        message = 'Invalid or expired token';
        isOperational = true;
    }

    // Log error
    if (isOperational) {
        logger.warn('Operational error', {
            code,
            message,
            statusCode,
            requestId,
            path: req.path,
            method: req.method,
        });
    } else {
        logger.error('Unexpected error', {
            error: err.message,
            stack: err.stack,
            requestId,
            path: req.path,
            method: req.method,
        });
    }

    // Build response
    const response: ErrorResponse = {
        success: false,
        error: {
            code,
            // In production, don't expose internal error details
            message: process.env['NODE_ENV'] === 'production' && !isOperational
                ? 'An unexpected error occurred'
                : message,
        },
        requestId,
    };

    // Add retry-after header for rate limiting
    if (statusCode === 429 && 'retryAfter' in err) {
        res.setHeader('Retry-After', String((err as { retryAfter?: number }).retryAfter ?? 60));
    }

    res.status(statusCode).json(response);
}

/**
 * 404 handler for undefined routes
 */
export function notFoundHandler(req: Request, res: Response): void {
    res.status(404).json({
        success: false,
        error: {
            code: 'NOT_FOUND',
            message: `Route ${req.method} ${req.path} not found`,
        },
    });
}

/**
 * Async handler wrapper to catch errors in async route handlers
 */
export function asyncHandler(
    fn: (req: Request, res: Response, next: NextFunction) => Promise<void>
) {
    return (req: Request, res: Response, next: NextFunction): void => {
        Promise.resolve(fn(req, res, next)).catch(next);
    };
}
