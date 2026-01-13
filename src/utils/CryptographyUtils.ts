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

/**
 * Decrypt legacy data encrypted with CryptoJS (AES-CBC)
 * using native Node.js crypto
 */
export function decryptLegacyField(encrypted: string): string {
    const key = config.security.fieldEncryptionKey; // This was used as passphrase in CryptoJS

    // CryptoJS default format: "Salted__" + 8 bytes salt + ciphertext (base64)
    const buffer = Buffer.from(encrypted, 'base64');

    // Check for "Salted__" header (OpenSSL format)
    const saltHeader = buffer.subarray(0, 8);
    if (saltHeader.toString('utf8') !== 'Salted__') {
        // If not salted or different format, try direct decryption or return as is
        // But for this specific migration, we assume standard CryptoJS format
        return encrypted;
    }

    const salt = buffer.subarray(8, 16);
    const ciphertext = buffer.subarray(16);

    // Derive key and IV using OpenSSL compatible KDF (EVP_BytesToKey)
    // CryptoJS uses MD5, 1 iteration by default
    const kdf = evpBytesToKey(key, salt, 32, 16);

    const decipher = crypto.createDecipheriv('aes-256-cbc', kdf.key, kdf.iv);
    let decrypted = decipher.update(ciphertext);
    decrypted = Buffer.concat([decrypted, decipher.final()]);

    return decrypted.toString('utf8');
}

/**
 * OpenSSL's EVP_BytesToKey implementation (MD5)
 * Used for compatibility with CryptoJS default key derivation
 */
function evpBytesToKey(password: string, salt: Buffer, keyLen: number, ivLen: number): { key: Buffer, iv: Buffer } {
    const passwordBuffer = Buffer.from(password, 'utf8');
    const requiredLen = keyLen + ivLen;
    let currentHash = Buffer.alloc(0);
    let result = Buffer.alloc(0);

    while (result.length < requiredLen) {
        const hash = crypto.createHash('md5');

        if (currentHash.length > 0) {
            hash.update(currentHash);
        }

        hash.update(passwordBuffer);
        hash.update(salt);

        currentHash = hash.digest();
        result = Buffer.concat([result, currentHash]);
    }

    return {
        key: result.subarray(0, keyLen),
        iv: result.subarray(keyLen, keyLen + ivLen)
    };
}
