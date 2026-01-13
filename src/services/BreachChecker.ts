import crypto from 'crypto';
import { config } from '../config/config';
import { logger } from '../middleware/requestLogger';

/**
 * Breach check result
 */
export interface BreachCheckResult {
    isBreached: boolean;
    occurrences?: number;
}

/**
 * Breach Checker Service
 * Checks passwords against known breach databases using k-anonymity
 * (HaveIBeenPwned API - privacy-safe, no full password transmitted)
 */
export class BreachChecker {
    private readonly hibpApiUrl = 'https://api.pwnedpasswords.com/range/';
    private readonly userAgent = 'BankingAuthService';

    /**
     * Check if a password has been involved in a data breach
     * Uses k-anonymity: only first 5 chars of SHA-1 hash are sent
     */
    async checkPassword(password: string): Promise<BreachCheckResult> {
        try {
            // Generate SHA-1 hash of password
            const sha1Hash = crypto
                .createHash('sha1')
                .update(password)
                .digest('hex')
                .toUpperCase();

            // k-anonymity: send only first 5 chars
            const prefix = sha1Hash.substring(0, 5);
            const suffix = sha1Hash.substring(5);

            // Timeout controller
            const controller = new AbortController();
            const timeoutId = setTimeout(() => controller.abort(), 5000);

            // Query HaveIBeenPwned API
            const response = await fetch(`${this.hibpApiUrl}${prefix}`, {
                headers: {
                    'User-Agent': this.userAgent,
                    // Add API key if available for enhanced rate limits
                    ...(config.hibp.apiKey ? { 'hibp-api-key': config.hibp.apiKey } : {}),
                },
                signal: controller.signal,
            }).finally(() => clearTimeout(timeoutId));

            if (!response.ok) {
                logger.warn('HIBP API returned non-OK status', { status: response.status });
                // Fail open - allow the password if API is unavailable
                return { isBreached: false };
            }

            const text = await response.text();

            // Parse response - format: SUFFIX:COUNT
            const lines = text.split('\r\n');

            for (const line of lines) {
                const [hashSuffix, count] = line.split(':');

                if (hashSuffix?.toUpperCase() === suffix) {
                    const occurrences = parseInt(count ?? '0', 10);

                    logger.warn('Password found in breach database', {
                        occurrences,
                        // Never log the actual password or full hash
                    });

                    return {
                        isBreached: true,
                        occurrences,
                    };
                }
            }

            return { isBreached: false };
        } catch (error) {
            logger.error('Error checking password against breach database', { error });
            // Fail open - don't block users if service is unavailable
            return { isBreached: false };
        }
    }

    /**
     * Check if password is in local list of common/breached passwords
     * This is a fallback/supplement to the HIBP API
     */
    isCommonPassword(password: string): boolean {
        // Top 100 most common passwords (simplified list)
        const commonPasswords = [
            '123456', 'password', '123456789', '12345678', '12345',
            '1234567', 'password1', 'password123', 'admin', 'letmein',
            'welcome', 'monkey', '1234567890', 'qwerty', 'abc123',
            '111111', 'dragon', 'master', 'sunshine', 'princess',
            'login', 'welcome1', 'qwerty123', 'password1!', 'iloveyou',
        ];

        return commonPasswords.includes(password.toLowerCase());
    }

    /**
     * Full password security check
     * Combines breach check with common password check
     */
    async isPasswordSecure(password: string): Promise<{ secure: boolean; reason?: string }> {
        // Check common passwords first (fast, no API call)
        if (this.isCommonPassword(password)) {
            return {
                secure: false,
                reason: 'This password is too common and easily guessed',
            };
        }

        // Check breach database
        const breachResult = await this.checkPassword(password);

        if (breachResult.isBreached) {
            return {
                secure: false,
                reason: `This password was found in ${breachResult.occurrences?.toLocaleString() ?? 'multiple'} data breaches. Please choose a different password.`,
            };
        }

        return { secure: true };
    }
}

// Export singleton
export const breachChecker = new BreachChecker();
