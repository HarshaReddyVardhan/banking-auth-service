import jwt, { Algorithm, JwtPayload, SignOptions, VerifyOptions } from 'jsonwebtoken';
import crypto from 'crypto';
import { config } from '../config/config';
import { logger } from '../middleware/requestLogger';

/**
 * JWT Key configuration for multi-key rotation support
 */
interface JWTKey {
    kid: string;           // Key ID (included in JWT header)
    privateKey: string;    // RSA private key (PEM)
    publicKey: string;     // RSA public key (PEM)
    activatedAt: Date;     // When this key became active
    expiresAt: Date;       // When this key should stop being used for signing
    status: 'active' | 'rotating' | 'expired';
}

/**
 * Access token payload
 */
export interface AccessTokenPayload extends JwtPayload {
    sub: string;           // User ID
    email: string;
    sessionId: string;
    deviceId?: string;
    type: 'access';
}

/**
 * Refresh token payload
 */
export interface RefreshTokenPayload extends JwtPayload {
    sub: string;           // User ID
    sessionId: string;
    familyId: string;      // Token family for rotation tracking
    type: 'refresh';
}

/**
 * Token pair returned after authentication
 */
export interface TokenPair {
    accessToken: string;
    refreshToken: string;
    accessTokenExpiresAt: Date;
    refreshTokenExpiresAt: Date;
}

/**
 * JWT Handler with banking-grade security
 * - RS256 algorithm with 3072-bit RSA keys
 * - Key ID (kid) in header for multi-key support
 * - 90-day key rotation with grace period
 * - Token type enforcement (access vs refresh)
 */
export class JWTHandler {
    private readonly algorithm: Algorithm = 'RS256';
    private keys: Map<string, JWTKey> = new Map();
    private activeKeyId: string | null = null;

    constructor() {
        // Load keys on initialization
        this.loadKeys();
    }

    /**
     * Load JWT keys from configuration
     * In production, these should come from a secrets manager
     */
    private loadKeys(): void {
        try {
            const privateKey = config.jwt.privateKey();
            const publicKey = config.jwt.publicKey();

            // Generate a key ID based on key fingerprint
            const kid = this.generateKeyId(publicKey);

            const key: JWTKey = {
                kid,
                privateKey,
                publicKey,
                activatedAt: new Date(),
                expiresAt: new Date(Date.now() + config.jwt.keyRotationDays * 24 * 60 * 60 * 1000),
                status: 'active',
            };

            this.keys.set(kid, key);
            this.activeKeyId = kid;

            logger.info(`JWT key loaded: ${kid}`);
        } catch (error) {
            logger.error('Failed to load JWT keys:', error);
            throw error;
        }
    }

    /**
     * Generate a deterministic key ID from public key
     */
    private generateKeyId(publicKey: string): string {
        const hash = crypto.createHash('sha256').update(publicKey).digest('hex');
        return `key-${hash.substring(0, 16)}`;
    }

    /**
     * Get the active signing key
     */
    private getActiveKey(): JWTKey {
        if (!this.activeKeyId) {
            throw new Error('No active JWT key available');
        }

        const key = this.keys.get(this.activeKeyId);
        if (!key) {
            throw new Error('Active JWT key not found');
        }

        // Check if key is expiring soon and needs rotation
        const gracePeriodStart = new Date(
            key.expiresAt.getTime() - config.jwt.keyGracePeriodDays * 24 * 60 * 60 * 1000
        );

        if (new Date() > gracePeriodStart && key.status === 'active') {
            key.status = 'rotating';
            logger.warn(`JWT key ${key.kid} entering rotation grace period`);
            // In production, trigger key rotation event here
        }

        return key;
    }

    /**
     * Get a key by ID (for verification)
     */
    private getKeyById(kid: string): JWTKey | undefined {
        return this.keys.get(kid);
    }

    /**
     * Sign an access token
     */
    signAccessToken(payload: Omit<AccessTokenPayload, 'type' | 'iat' | 'exp' | 'iss' | 'aud'>): string {
        const key = this.getActiveKey();

        const fullPayload = {
            ...payload,
            type: 'access' as const,
        } as AccessTokenPayload;

        const options: SignOptions = {
            algorithm: this.algorithm,
            expiresIn: config.jwt.accessTokenExpiry as jwt.SignOptions['expiresIn'],
            issuer: config.jwt.issuer,
            audience: config.jwt.audience,
            keyid: key.kid,
            jwtid: crypto.randomUUID(), // JTI for replay attack prevention and per-JWT rate limiting
        };

        return jwt.sign(fullPayload, key.privateKey, options);
    }

    /**
     * Sign a refresh token
     */
    signRefreshToken(payload: Omit<RefreshTokenPayload, 'type' | 'iat' | 'exp' | 'iss' | 'aud'>): string {
        const key = this.getActiveKey();

        const fullPayload = {
            ...payload,
            type: 'refresh' as const,
        } as RefreshTokenPayload;

        const options: SignOptions = {
            algorithm: this.algorithm,
            expiresIn: config.jwt.refreshTokenExpiry as jwt.SignOptions['expiresIn'],
            issuer: config.jwt.issuer,
            audience: config.jwt.audience,
            keyid: key.kid,
        };

        return jwt.sign(fullPayload, key.privateKey, options);
    }

    /**
     * Verify and decode an access token
     */
    verifyAccessToken(token: string): AccessTokenPayload {
        const decoded = this.verifyToken(token);

        if (decoded.type !== 'access') {
            throw new TokenTypeError('Expected access token');
        }

        return decoded as AccessTokenPayload;
    }

    /**
     * Verify and decode a refresh token
     */
    verifyRefreshToken(token: string): RefreshTokenPayload {
        const decoded = this.verifyToken(token);

        if (decoded.type !== 'refresh') {
            throw new TokenTypeError('Expected refresh token');
        }

        return decoded as RefreshTokenPayload;
    }

    /**
     * Internal token verification with multi-key support
     */
    private verifyToken(token: string): JwtPayload {
        // Decode header to get key ID
        const decoded = jwt.decode(token, { complete: true });

        if (!decoded || typeof decoded === 'string') {
            throw new TokenVerificationError('Invalid token format');
        }

        const kid = decoded.header.kid;
        if (!kid) {
            throw new TokenVerificationError('Token missing key ID (kid)');
        }

        // Get the key used to sign this token
        const key = this.getKeyById(kid);
        if (!key) {
            throw new TokenVerificationError(`Unknown key ID: ${kid}`);
        }

        const options: VerifyOptions = {
            algorithms: [this.algorithm],
            issuer: config.jwt.issuer,
            audience: config.jwt.audience,
        };

        try {
            const payload = jwt.verify(token, key.publicKey, options) as JwtPayload;
            return payload;
        } catch (error) {
            if (error instanceof jwt.TokenExpiredError) {
                throw new TokenExpiredError('Token has expired');
            }
            if (error instanceof jwt.JsonWebTokenError) {
                throw new TokenVerificationError(error.message);
            }
            throw error;
        }
    }

    /**
     * Generate a token pair (access + refresh)
     */
    generateTokenPair(
        userId: string,
        email: string,
        sessionId: string,
        familyId: string,
        deviceId?: string
    ): TokenPair {
        const now = new Date();

        // Calculate expiry times
        const accessTokenExpiresAt = new Date(now.getTime() + this.parseExpiry(config.jwt.accessTokenExpiry));
        const refreshTokenExpiresAt = new Date(now.getTime() + this.parseExpiry(config.jwt.refreshTokenExpiry));

        const accessToken = this.signAccessToken({
            sub: userId,
            email,
            sessionId,
            deviceId,
        });

        const refreshToken = this.signRefreshToken({
            sub: userId,
            sessionId,
            familyId,
        });

        return {
            accessToken,
            refreshToken,
            accessTokenExpiresAt,
            refreshTokenExpiresAt,
        };
    }

    /**
     * Parse expiry string (e.g., "15m", "7d") to milliseconds
     */
    private parseExpiry(expiry: string): number {
        const match = expiry.match(/^(\d+)([smhd])$/);
        if (!match) {
            throw new Error(`Invalid expiry format: ${expiry}`);
        }

        const value = parseInt(match[1] ?? '0', 10);
        const unit = match[2];

        switch (unit) {
            case 's': return value * 1000;
            case 'm': return value * 60 * 1000;
            case 'h': return value * 60 * 60 * 1000;
            case 'd': return value * 24 * 60 * 60 * 1000;
            default: throw new Error(`Unknown time unit: ${unit}`);
        }
    }

    /**
     * Add a new key for rotation
     * Called when preparing for key rotation
     */
    addRotationKey(privateKey: string, publicKey: string): string {
        const kid = this.generateKeyId(publicKey);

        const key: JWTKey = {
            kid,
            privateKey,
            publicKey,
            activatedAt: new Date(),
            expiresAt: new Date(Date.now() + config.jwt.keyRotationDays * 24 * 60 * 60 * 1000),
            status: 'active',
        };

        this.keys.set(kid, key);

        // Mark old key as rotating
        if (this.activeKeyId) {
            const oldKey = this.keys.get(this.activeKeyId);
            if (oldKey) {
                oldKey.status = 'rotating';
            }
        }

        this.activeKeyId = kid;

        logger.info(`New JWT key activated: ${kid}`);
        return kid;
    }

    /**
     * Remove an expired key
     */
    removeExpiredKey(kid: string): void {
        const key = this.keys.get(kid);
        if (key && key.kid !== this.activeKeyId) {
            this.keys.delete(kid);
            logger.info(`Expired JWT key removed: ${kid}`);
        }
    }

    /**
     * Get current key status for monitoring
     */
    getKeyStatus(): Array<{ kid: string; status: string; expiresAt: Date }> {
        return Array.from(this.keys.values()).map(key => ({
            kid: key.kid,
            status: key.status,
            expiresAt: key.expiresAt,
        }));
    }
}

/**
 * Custom JWT errors
 */
export class TokenVerificationError extends Error {
    constructor(message: string) {
        super(message);
        this.name = 'TokenVerificationError';
    }
}

export class TokenExpiredError extends Error {
    constructor(message: string) {
        super(message);
        this.name = 'TokenExpiredError';
    }
}

export class TokenTypeError extends Error {
    constructor(message: string) {
        super(message);
        this.name = 'TokenTypeError';
    }
}

// Export singleton instance
export const jwtHandler = new JWTHandler();
