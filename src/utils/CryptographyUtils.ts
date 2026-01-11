import crypto from 'crypto';
import { config } from '../config/config';

/**
 * Field-level encryption utilities using AES-256-GCM
 * For encrypting PII data (emails, phone numbers, addresses)
 */

const ALGORITHM = 'aes-256-gcm';
const IV_LENGTH = 16; // 128 bits
const AUTH_TAG_LENGTH = 16; // 128 bits
const SALT_LENGTH = 32;

/**
 * Derive encryption key from master key using PBKDF2
 */
function deriveKey(masterKey: string, salt: Buffer): Buffer {
    return crypto.pbkdf2Sync(masterKey, salt, 100000, 32, 'sha256');
}

/**
 * Encrypt a string value using AES-256-GCM
 */
export function encryptField(plaintext: string, additionalData?: string): string {
    const salt = crypto.randomBytes(SALT_LENGTH);
    const key = deriveKey(config.security.fieldEncryptionKey, salt);
    const iv = crypto.randomBytes(IV_LENGTH);

    const cipher = crypto.createCipheriv(ALGORITHM, key, iv, {
        authTagLength: AUTH_TAG_LENGTH,
    });

    if (additionalData) {
        cipher.setAAD(Buffer.from(additionalData, 'utf8'));
    }

    let encrypted = cipher.update(plaintext, 'utf8', 'base64');
    encrypted += cipher.final('base64');
    const authTag = cipher.getAuthTag();

    // Format: salt:iv:authTag:ciphertext (all base64)
    return [
        salt.toString('base64'),
        iv.toString('base64'),
        authTag.toString('base64'),
        encrypted,
    ].join(':');
}

/**
 * Decrypt a string value encrypted with encryptField
 */
export function decryptField(encryptedData: string, additionalData?: string): string {
    const parts = encryptedData.split(':');
    if (parts.length !== 4) {
        throw new Error('Invalid encrypted data format');
    }

    const [saltB64, ivB64, authTagB64, ciphertext] = parts;

    if (!saltB64 || !ivB64 || !authTagB64 || !ciphertext) {
        throw new Error('Invalid encrypted data format');
    }

    const salt = Buffer.from(saltB64, 'base64');
    const iv = Buffer.from(ivB64, 'base64');
    const authTag = Buffer.from(authTagB64, 'base64');
    const key = deriveKey(config.security.fieldEncryptionKey, salt);

    const decipher = crypto.createDecipheriv(ALGORITHM, key, iv, {
        authTagLength: AUTH_TAG_LENGTH,
    });

    decipher.setAuthTag(authTag);

    if (additionalData) {
        decipher.setAAD(Buffer.from(additionalData, 'utf8'));
    }

    let decrypted = decipher.update(ciphertext, 'base64', 'utf8');
    decrypted += decipher.final('utf8');

    return decrypted;
}

/**
 * Generate a cryptographically secure random string
 */
export function generateSecureRandom(length: number = 32): string {
    return crypto.randomBytes(length).toString('base64url');
}

/**
 * Generate a secure token for various purposes
 */
export function generateSecureToken(length: number = 32): string {
    return crypto.randomBytes(length).toString('hex');
}

/**
 * Hash a value for secure storage (one-way)
 */
export function hashValue(value: string, salt?: string): string {
    const actualSalt = salt ?? crypto.randomBytes(16).toString('hex');
    const hash = crypto.createHmac('sha256', actualSalt).update(value).digest('hex');
    return `${actualSalt}:${hash}`;
}

/**
 * Verify a hashed value
 */
export function verifyHash(value: string, storedHash: string): boolean {
    const [salt, hash] = storedHash.split(':');
    if (!salt || !hash) return false;

    const newHash = crypto.createHmac('sha256', salt).update(value).digest('hex');

    // Timing-safe comparison
    return crypto.timingSafeEqual(Buffer.from(hash, 'hex'), Buffer.from(newHash, 'hex'));
}

/**
 * Hash a device fingerprint consistently
 */
export function hashDeviceFingerprint(fingerprint: Record<string, unknown>): string {
    const normalized = JSON.stringify(fingerprint, Object.keys(fingerprint).sort());
    return crypto.createHash('sha256').update(normalized).digest('hex');
}

/**
 * Mask an email for display (show first 2 chars and domain)
 */
export function maskEmail(email: string): string {
    const [local, domain] = email.split('@');
    if (!local || !domain) return '***@***.***';

    const maskedLocal = local.slice(0, 2) + '***';
    return `${maskedLocal}@${domain}`;
}

/**
 * Mask sensitive data for logging
 */
export function maskSensitiveData(data: string, visibleChars: number = 4): string {
    if (data.length <= visibleChars * 2) {
        return '*'.repeat(data.length);
    }
    return data.slice(0, visibleChars) + '*'.repeat(data.length - visibleChars * 2) + data.slice(-visibleChars);
}
