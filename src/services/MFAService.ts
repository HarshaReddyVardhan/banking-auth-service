import { authenticator } from 'otplib';
import QRCode from 'qrcode';
import crypto from 'crypto';
import { config } from '../config/config';
import { logger } from '../middleware/requestLogger';

/**
 * MFA setup result
 */
export interface MFASetupResult {
    secret: string;
    qrCodeDataUrl: string;
    backupCodes: string[];
}

/**
 * MFA Service for TOTP authentication with backup codes
 */
export class MFAService {
    private readonly issuer: string;
    private readonly backupCodeCount: number;

    constructor() {
        this.issuer = config.mfa.issuer;
        this.backupCodeCount = config.mfa.backupCodesCount;

        // Configure otplib
        authenticator.options = {
            window: 1, // Allow 1 step tolerance (30 seconds before/after)
        };
    }

    /**
     * Generate a new TOTP secret
     */
    generateSecret(): string {
        return authenticator.generateSecret();
    }

    /**
     * Generate QR code for authenticator app
     */
    async generateQRCode(secret: string, email: string): Promise<string> {
        const otpauth = authenticator.keyuri(email, this.issuer, secret);

        try {
            const qrCodeDataUrl = await QRCode.toDataURL(otpauth, {
                width: 256,
                margin: 2,
                color: {
                    dark: '#000000',
                    light: '#ffffff',
                },
            });
            return qrCodeDataUrl;
        } catch (error) {
            logger.error('Failed to generate QR code', { error });
            throw new Error('Failed to generate QR code');
        }
    }

    /**
     * Complete MFA setup - generates secret, QR code, and backup codes
     */
    async setupMFA(email: string): Promise<MFASetupResult> {
        const secret = this.generateSecret();
        const qrCodeDataUrl = await this.generateQRCode(secret, email);
        const backupCodes = this.generateBackupCodes();

        return {
            secret,
            qrCodeDataUrl,
            backupCodes,
        };
    }

    /**
     * Verify a TOTP token
     */
    verifyToken(secret: string, token: string): boolean {
        try {
            // Clean the token (remove spaces/dashes)
            const cleanToken = token.replace(/[\s-]/g, '');

            if (!/^\d{6}$/.test(cleanToken)) {
                return false;
            }

            return authenticator.verify({ token: cleanToken, secret });
        } catch (error) {
            logger.error('TOTP verification error', { error });
            return false;
        }
    }

    /**
     * Generate backup codes
     * Each code is 8 characters, alphanumeric, grouped for readability
     */
    generateBackupCodes(): string[] {
        const codes: string[] = [];
        const charset = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789'; // Exclude confusing chars (0, O, 1, I)

        for (let i = 0; i < this.backupCodeCount; i++) {
            const bytes = crypto.randomBytes(8);
            let code = '';

            for (let j = 0; j < 8; j++) {
                const byte = bytes[j];
                if (byte !== undefined) {
                    code += charset[byte % charset.length];
                }
            }

            // Format as XXXX-XXXX for readability
            codes.push(`${code.slice(0, 4)}-${code.slice(4, 8)}`);
        }

        return codes;
    }

    /**
     * Hash a backup code for storage
     */
    hashBackupCode(code: string): string {
        const normalized = code.replace(/-/g, '').toUpperCase();
        return crypto.createHash('sha256').update(normalized).digest('hex');
    }

    /**
     * Verify a backup code against stored hashes
     */
    verifyBackupCode(code: string, hashedCodes: string[]): { valid: boolean; index: number } {
        const hashedInput = this.hashBackupCode(code);

        for (let i = 0; i < hashedCodes.length; i++) {
            // Use timing-safe comparison
            const storedHash = hashedCodes[i];
            if (storedHash && crypto.timingSafeEqual(
                Buffer.from(hashedInput, 'hex'),
                Buffer.from(storedHash, 'hex')
            )) {
                return { valid: true, index: i };
            }
        }

        return { valid: false, index: -1 };
    }

    /**
     * Hash all backup codes for storage
     */
    hashBackupCodes(codes: string[]): string[] {
        return codes.map(code => this.hashBackupCode(code));
    }

    /**
     * Generate a recovery secret for backup code generation
     */
    generateRecoverySecret(): string {
        return crypto.randomBytes(32).toString('hex');
    }
}

// Export singleton
export const mfaService = new MFAService();
