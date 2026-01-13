import { Request, Response, NextFunction } from 'express';

/**
 * Input Sanitization Middleware
 * Sanitizes user input to prevent XSS and injection attacks
 * 
 * Security measures:
 * 1. Removes potential script injections
 * 2. Escapes HTML entities
 * 3. Trims whitespace
 * 4. Normalizes unicode to prevent homograph attacks
 */

/**
 * Patterns that should be sanitized (potential XSS vectors)
 */
const XSS_PATTERNS = [
    /<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>/gi,
    /javascript:/gi,
    /on\w+\s*=/gi, // onclick=, onerror=, etc.
    /data:\s*text\/html/gi,
    /<\s*iframe/gi,
    /<\s*object/gi,
    /<\s*embed/gi,
    /<\s*link/gi,
    /<\s*meta/gi,
];

/**
 * HTML entities to escape
 */
const HTML_ENTITIES: Record<string, string> = {
    '&': '&amp;',
    '<': '&lt;',
    '>': '&gt;',
    '"': '&quot;',
    "'": '&#x27;',
    '/': '&#x2F;',
    '`': '&#x60;',
};

/**
 * Escape HTML entities in a string
 */
function escapeHtml(str: string): string {
    return str.replace(/[&<>"'`/]/g, (char) => HTML_ENTITIES[char] || char);
}

/**
 * Remove XSS patterns from a string
 */
function removeXssPatterns(str: string): string {
    let result = str;
    for (const pattern of XSS_PATTERNS) {
        result = result.replace(pattern, '');
    }
    return result;
}

/**
 * Normalize unicode to prevent homograph attacks
 * Only normalize strings that appear to be identifiers/emails
 */
function normalizeUnicode(str: string): string {
    // Normalize to NFC form to prevent unicode lookalike attacks
    return str.normalize('NFC');
}

/**
 * Sanitize a single value
 */
function sanitizeValue(value: unknown, key?: string): unknown {
    if (typeof value === 'string') {
        let sanitized = value.trim();

        // Normalize unicode
        sanitized = normalizeUnicode(sanitized);

        // Remove XSS patterns
        sanitized = removeXssPatterns(sanitized);

        // Escape HTML entities (except for password fields)
        // Password fields should not be modified as they may contain special chars
        if (key !== 'password' && key !== 'currentPassword' && key !== 'newPassword') {
            sanitized = escapeHtml(sanitized);
        }

        return sanitized;
    }

    if (Array.isArray(value)) {
        return value.map((item) => sanitizeValue(item));
    }

    if (value !== null && typeof value === 'object') {
        return sanitizeObject(value as Record<string, unknown>);
    }

    return value;
}

/**
 * Sanitize an object recursively
 */
function sanitizeObject(obj: Record<string, unknown>): Record<string, unknown> {
    const sanitized: Record<string, unknown> = {};

    for (const [key, value] of Object.entries(obj)) {
        // Also sanitize the key (prevent prototype pollution)
        const sanitizedKey = key.replace(/[^a-zA-Z0-9_]/g, '');

        // Prevent prototype pollution
        if (sanitizedKey === '__proto__' || sanitizedKey === 'constructor' || sanitizedKey === 'prototype') {
            continue;
        }

        sanitized[sanitizedKey] = sanitizeValue(value, sanitizedKey);
    }

    return sanitized;
}

/**
 * Input sanitization middleware
 */
export function sanitizationMiddleware(req: Request, _res: Response, next: NextFunction): void {
    try {
        // Sanitize request body
        if (req.body && typeof req.body === 'object') {
            req.body = sanitizeObject(req.body as Record<string, unknown>);
        }

        // Sanitize query parameters
        if (req.query && typeof req.query === 'object') {
            req.query = sanitizeObject(req.query as Record<string, unknown>) as typeof req.query;
        }

        // Sanitize params
        if (req.params && typeof req.params === 'object') {
            req.params = sanitizeObject(req.params as Record<string, unknown>) as typeof req.params;
        }

        next();
    } catch {
        // If sanitization fails, reject the request
        next(new Error('Invalid input format'));
    }
}

/**
 * Strict mode sanitization - rejects requests with suspicious patterns
 * Use this for high-security endpoints
 */
export function strictSanitizationMiddleware(req: Request, res: Response, next: NextFunction): void {
    // Check for suspicious patterns in raw body
    const bodyStr = JSON.stringify(req.body || {});

    for (const pattern of XSS_PATTERNS) {
        if (pattern.test(bodyStr)) {
            res.status(400).json({
                success: false,
                error: 'Input contains potentially dangerous content',
            });
            return;
        }
    }

    // Apply normal sanitization
    sanitizationMiddleware(req, res, next);
}
