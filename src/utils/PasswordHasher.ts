import bcrypt from 'bcrypt';
import { config } from '../config/config';

/**
 * Password Hasher with banking-grade security
 * - bcrypt with cost factor 12+ (PCI-DSS compliant)
 * - Async operations to prevent event loop blocking
 * - Constant-time comparison (timing attack prevention - built into bcrypt)
 */
export class PasswordHasher {
    private readonly saltRounds: number;

    constructor() {
        this.saltRounds = config.security.bcryptRounds;

        // Validate cost factor meets PCI-DSS requirements
        if (this.saltRounds < 12) {
            throw new Error('bcrypt cost factor must be at least 12 for PCI-DSS compliance');
        }
    }

    /**
     * Hash a password using bcrypt
     * Uses async version to prevent blocking the event loop
     */
    async hash(password: string): Promise<string> {
        // Validate password before hashing
        this.validatePasswordStrength(password);

        // Generate salt and hash
        const hash = await bcrypt.hash(password, this.saltRounds);
        return hash;
    }

    /**
     * Verify a password against a hash
     * bcrypt.compare uses constant-time comparison (timing attack safe)
     */
    async verify(password: string, hash: string): Promise<boolean> {
        try {
            return await bcrypt.compare(password, hash);
        } catch {
            // Return false on any error (e.g., invalid hash format)
            return false;
        }
    }

    /**
     * Validate password meets complexity requirements
     * PCI-DSS: Minimum 12 characters, mixed case, numbers, symbols
     */
    validatePasswordStrength(password: string): void {
        const minLength = config.security.passwordMinLength;
        const errors: string[] = [];

        if (password.length < minLength) {
            errors.push(`Password must be at least ${minLength} characters`);
        }

        if (!/[a-z]/.test(password)) {
            errors.push('Password must contain at least one lowercase letter');
        }

        if (!/[A-Z]/.test(password)) {
            errors.push('Password must contain at least one uppercase letter');
        }

        if (!/[0-9]/.test(password)) {
            errors.push('Password must contain at least one number');
        }

        if (!/[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?]/.test(password)) {
            errors.push('Password must contain at least one special character');
        }

        // Check for common weak patterns
        if (/^(.)\1+$/.test(password)) {
            errors.push('Password cannot consist of repeated characters');
        }

        // Check for numeric sequences
        if (/^(012|123|234|345|456|567|678|789|890)+$/.test(password)) {
            errors.push('Password cannot be a simple sequence');
        }

        // Check for keyboard patterns (qwerty, etc.)
        const keyboardPatterns = [
            'qwerty', 'qwertz', 'azerty', 'asdf', 'zxcv', 'qazwsx', 'poiuy',
            '1qaz', '2wsx', '3edc', '4rfv', '5tgb', '6yhn', '7ujm', '8ik', '9ol',
        ];
        const lowerPassword = password.toLowerCase();
        for (const pattern of keyboardPatterns) {
            if (lowerPassword.includes(pattern) || lowerPassword.includes(pattern.split('').reverse().join(''))) {
                errors.push('Password cannot contain keyboard patterns');
                break;
            }
        }

        // Check for sequential letters (abc, xyz, etc.)
        if (/abc|bcd|cde|def|efg|fgh|ghi|hij|ijk|jkl|klm|lmn|mno|nop|opq|pqr|qrs|rst|stu|tuv|uvw|vwx|wxy|xyz/i.test(password)) {
            errors.push('Password cannot contain sequential letters');
        }

        // Check for common password patterns
        const commonPatterns = [
            'password', 'passwd', 'pass', 'admin', 'login', 'welcome', 'master',
            'letmein', 'trustno1', 'dragon', 'monkey', 'shadow', 'sunshine',
        ];
        for (const pattern of commonPatterns) {
            if (lowerPassword.includes(pattern)) {
                errors.push('Password contains a commonly used word');
                break;
            }
        }

        if (errors.length > 0) {
            throw new PasswordValidationError(errors);
        }
    }

    /**
     * Check if password matches any in history (for reuse prevention)
     */
    async matchesAnyInHistory(password: string, historyHashes: string[]): Promise<boolean> {
        for (const hash of historyHashes) {
            if (await this.verify(password, hash)) {
                return true;
            }
        }
        return false;
    }
}

/**
 * Custom error for password validation failures
 */
export class PasswordValidationError extends Error {
    public readonly errors: string[];

    constructor(errors: string[]) {
        super(`Password validation failed: ${errors.join(', ')}`);
        this.name = 'PasswordValidationError';
        this.errors = errors;
    }
}

// Export singleton instance
export const passwordHasher = new PasswordHasher();
