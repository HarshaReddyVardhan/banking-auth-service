import winston from 'winston';
import { config } from '../config/config';

// Custom log format for structured logging
const logFormat = winston.format.combine(
    winston.format.timestamp({ format: 'YYYY-MM-DD HH:mm:ss.SSS' }),
    winston.format.errors({ stack: true }),
    winston.format.metadata({ fillExcept: ['message', 'level', 'timestamp'] }),
    config.logging.format === 'json'
        ? winston.format.json()
        : winston.format.printf(({ level, message, timestamp, metadata }) => {
            const meta = Object.keys(metadata as object).length
                ? ` ${JSON.stringify(metadata)}`
                : '';
            return `${timestamp} [${level.toUpperCase()}]: ${message}${meta as any}`;
        })
);

// Sensitive fields to redact from logs
const SENSITIVE_FIELDS = [
    'password',
    'passwordHash',
    'token',
    'accessToken',
    'refreshToken',
    'mfaSecret',
    'mfaBackupCodes',
    'authorization',
    'cookie',
    'apiKey',
    'secret',
];

// Redact sensitive data from objects
function redactSensitiveData(obj: unknown): unknown {
    if (typeof obj !== 'object' || obj === null) {
        return obj;
    }

    if (Array.isArray(obj)) {
        return obj.map(item => redactSensitiveData(item));
    }

    const result: Record<string, unknown> = {};
    for (const [key, value] of Object.entries(obj)) {
        const lowerKey = key.toLowerCase();
        if (SENSITIVE_FIELDS.some(field => lowerKey.includes(field.toLowerCase()))) {
            result[key] = '[REDACTED]';
        } else if (typeof value === 'object' && value !== null) {
            result[key] = redactSensitiveData(value);
        } else {
            result[key] = value;
        }
    }
    return result;
}

// Create the logger
export const logger = winston.createLogger({
    level: config.logging.level,
    format: logFormat,
    defaultMeta: { service: 'banking-auth-service' },
    transports: [
        // Console transport
        new winston.transports.Console({
            handleExceptions: true,
            handleRejections: true,
        }),
        // File transport for errors (production)
        ...(config.isProduction()
            ? [
                new winston.transports.File({
                    filename: 'logs/error.log',
                    level: 'error',
                    maxsize: 10 * 1024 * 1024, // 10MB
                    maxFiles: 10,
                }),
                new winston.transports.File({
                    filename: 'logs/combined.log',
                    maxsize: 10 * 1024 * 1024,
                    maxFiles: 20,
                }),
            ]
            : []),
    ],
    exceptionHandlers: [
        new winston.transports.File({ filename: 'logs/exceptions.log' }),
    ],
    rejectionHandlers: [
        new winston.transports.File({ filename: 'logs/rejections.log' }),
    ],
});

// Security-specific logging functions
export const securityLogger = {
    loginSuccess: (userId: string, ip: string, deviceId?: string) => {
        logger.info('Login successful', {
            event: 'auth.login.success',
            userId,
            ip,
            deviceId,
        });
    },

    loginFailed: (email: string, ip: string, reason: string) => {
        logger.warn('Login failed', {
            event: 'auth.login.failed',
            email: email.replace(/(.{2}).*(@.*)/, '$1***$2'), // Partial redact
            ip,
            reason,
        });
    },

    accountLocked: (userId: string, ip: string) => {
        logger.warn('Account locked due to failed attempts', {
            event: 'auth.account.locked',
            userId,
            ip,
        });
    },

    suspiciousActivity: (userId: string, ip: string, reason: string, details: Record<string, unknown>) => {
        logger.error('Suspicious activity detected', {
            event: 'security.suspicious',
            userId,
            ip,
            reason,
            ...(redactSensitiveData(details) as any),
        });
    },

    tokenTheftDetected: (userId: string, familyId: string) => {
        logger.error('Token theft detected - refresh token reuse', {
            event: 'security.token_theft',
            userId,
            familyId,
        });
    },

    mfaEnabled: (userId: string) => {
        logger.info('MFA enabled', {
            event: 'auth.mfa.enabled',
            userId,
        });
    },

    passwordChanged: (userId: string, ip: string) => {
        logger.info('Password changed', {
            event: 'auth.password.changed',
            userId,
            ip,
        });
    },

    auditLog: (action: string, userId: string, details: Record<string, unknown>) => {
        logger.info(`Audit: ${action}`, {
            event: 'audit',
            action,
            userId,
            ...(redactSensitiveData(details) as any),
        });
    },
};

// Request logging middleware helper
export function createRequestLogData(
    method: string,
    url: string,
    statusCode: number,
    responseTime: number,
    ip: string,
    correlationId: string
): Record<string, unknown> {
    return {
        event: 'http.request',
        method,
        url: url.split('?')[0], // Remove query params
        statusCode,
        responseTime: `${responseTime}ms`,
        ip,
        correlationId,
    };
}
