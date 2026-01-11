import fs from 'fs';
import path from 'path';

// Validation helper
function requireEnv(name: string): string {
    const value = process.env[name];
    if (!value) {
        throw new Error(`Missing required environment variable: ${name}`);
    }
    return value;
}

function optionalEnv(name: string, defaultValue: string): string {
    return process.env[name] ?? defaultValue;
}

function optionalEnvInt(name: string, defaultValue: number): number {
    const value = process.env[name];
    return value ? parseInt(value, 10) : defaultValue;
}

function optionalEnvBool(name: string, defaultValue: boolean): boolean {
    const value = process.env[name];
    if (!value) return defaultValue;
    return value.toLowerCase() === 'true';
}

// Load JWT keys from files or environment
function loadJWTKey(keyPath: string | undefined, keyEnvVar: string): string {
    if (keyPath && fs.existsSync(keyPath)) {
        return fs.readFileSync(keyPath, 'utf8');
    }
    const envKey = process.env[keyEnvVar];
    if (envKey) {
        return envKey.replace(/\\n/g, '\n');
    }
    throw new Error(`JWT key not found: ${keyPath || keyEnvVar}`);
}

export const config = {
    // Server
    nodeEnv: optionalEnv('NODE_ENV', 'development'),
    port: optionalEnvInt('PORT', 3000),
    host: optionalEnv('HOST', '0.0.0.0'),

    // Database
    database: {
        host: requireEnv('DB_HOST'),
        port: optionalEnvInt('DB_PORT', 5432),
        name: requireEnv('DB_NAME'),
        user: requireEnv('DB_USER'),
        password: requireEnv('DB_PASSWORD'),
        ssl: optionalEnvBool('DB_SSL', true),
        sslRejectUnauthorized: optionalEnvBool('DB_SSL_REJECT_UNAUTHORIZED', true),
        pool: {
            min: optionalEnvInt('DB_POOL_MIN', 5),
            max: optionalEnvInt('DB_POOL_MAX', 20),
            acquire: optionalEnvInt('DB_POOL_ACQUIRE', 30000),
            idle: optionalEnvInt('DB_POOL_IDLE', 10000),
        },
    },

    // Redis
    redis: {
        host: requireEnv('REDIS_HOST'),
        port: optionalEnvInt('REDIS_PORT', 6379),
        password: process.env['REDIS_PASSWORD'],
        tls: optionalEnvBool('REDIS_TLS', false),
        db: optionalEnvInt('REDIS_DB', 0),
    },

    // JWT
    jwt: {
        privateKey: (): string =>
            loadJWTKey(process.env['JWT_PRIVATE_KEY_PATH'], 'JWT_PRIVATE_KEY'),
        publicKey: (): string =>
            loadJWTKey(process.env['JWT_PUBLIC_KEY_PATH'], 'JWT_PUBLIC_KEY'),
        accessTokenExpiry: optionalEnv('JWT_ACCESS_TOKEN_EXPIRY', '15m'),
        refreshTokenExpiry: optionalEnv('JWT_REFRESH_TOKEN_EXPIRY', '7d'),
        issuer: optionalEnv('JWT_ISSUER', 'banking-auth-service'),
        audience: optionalEnv('JWT_AUDIENCE', 'banking-api'),
        keyRotationDays: optionalEnvInt('JWT_KEY_ROTATION_DAYS', 90),
        keyGracePeriodDays: optionalEnvInt('JWT_KEY_GRACE_PERIOD_DAYS', 7),
    },

    // Security
    security: {
        bcryptRounds: optionalEnvInt('BCRYPT_ROUNDS', 12),
        passwordMinLength: optionalEnvInt('PASSWORD_MIN_LENGTH', 12),
        passwordHistoryCount: optionalEnvInt('PASSWORD_HISTORY_COUNT', 12),
        passwordExpiryDays: optionalEnvInt('PASSWORD_EXPIRY_DAYS', 90),
        maxLoginAttempts: optionalEnvInt('MAX_LOGIN_ATTEMPTS', 7),
        lockoutDurationMs: optionalEnvInt('LOCKOUT_DURATION_MS', 900000), // 15 min
        fieldEncryptionKey: requireEnv('FIELD_ENCRYPTION_KEY'),
    },

    // Session
    session: {
        maxConcurrent: optionalEnvInt('MAX_CONCURRENT_SESSIONS', 5),
        expiryHours: optionalEnvInt('SESSION_EXPIRY_HOURS', 24),
    },

    // Rate Limiting
    rateLimit: {
        windowMs: optionalEnvInt('RATE_LIMIT_WINDOW_MS', 900000), // 15 min
        maxRequests: optionalEnvInt('RATE_LIMIT_MAX_REQUESTS', 100),
        emailResendPerEmail: optionalEnvInt('EMAIL_RESEND_LIMIT_PER_EMAIL', 3),
        emailResendPerIP: optionalEnvInt('EMAIL_RESEND_LIMIT_PER_IP', 5),
        emailResendWindowHours: optionalEnvInt('EMAIL_RESEND_WINDOW_HOURS', 1),
    },

    // Progressive delay curve (ms) for failed login attempts
    progressiveDelay: {
        1: 0,
        2: 1000,
        3: 4000,
        4: 16000,
        5: 60000,
        6: 300000,
        7: 900000,
    } as Record<number, number>,

    // MFA
    mfa: {
        issuer: optionalEnv('MFA_ISSUER', 'BankingApp'),
        backupCodesCount: optionalEnvInt('MFA_BACKUP_CODES_COUNT', 10),
    },

    // Kafka
    kafka: {
        brokers: optionalEnv('KAFKA_BROKERS', 'localhost:9092').split(','),
        clientId: optionalEnv('KAFKA_CLIENT_ID', 'banking-auth-service'),
        securityTopic: optionalEnv('KAFKA_SECURITY_TOPIC', 'security-events'),
    },

    // Email
    email: {
        host: optionalEnv('SMTP_HOST', ''),
        port: optionalEnvInt('SMTP_PORT', 587),
        user: optionalEnv('SMTP_USER', ''),
        password: optionalEnv('SMTP_PASSWORD', ''),
        from: optionalEnv('SMTP_FROM', 'noreply@example.com'),
    },

    // Breach detection
    hibp: {
        apiKey: process.env['HIBP_API_KEY'],
    },

    // Logging
    logging: {
        level: optionalEnv('LOG_LEVEL', 'info'),
        format: optionalEnv('LOG_FORMAT', 'json'),
    },

    // Helper methods
    isProduction: (): boolean => config.nodeEnv === 'production',
    isDevelopment: (): boolean => config.nodeEnv === 'development',
};

export type Config = typeof config;
