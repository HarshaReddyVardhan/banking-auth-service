import { MFAService } from '../../src/services/MFAService';
import { authenticator } from 'otplib';

describe('MFAService', () => {
    let mfaService: MFAService;

    beforeEach(() => {
        mfaService = new MFAService();
    });

    describe('generateSecret', () => {
        it('should generate a valid secret', () => {
            const secret = mfaService.generateSecret();

            expect(secret).toBeDefined();
            expect(secret.length).toBeGreaterThan(0);
        });

        it('should generate unique secrets', () => {
            const secret1 = mfaService.generateSecret();
            const secret2 = mfaService.generateSecret();

            expect(secret1).not.toBe(secret2);
        });
    });

    describe('verifyToken', () => {
        it('should verify valid TOTP token', () => {
            const secret = mfaService.generateSecret();
            const token = authenticator.generate(secret);

            const isValid = mfaService.verifyToken(secret, token);
            expect(isValid).toBe(true);
        });

        it('should reject invalid TOTP token', () => {
            const secret = mfaService.generateSecret();

            const isValid = mfaService.verifyToken(secret, '000000');
            expect(isValid).toBe(false);
        });

        it('should reject malformed token', () => {
            const secret = mfaService.generateSecret();

            expect(mfaService.verifyToken(secret, 'abc123')).toBe(false);
            expect(mfaService.verifyToken(secret, '12345')).toBe(false);
            expect(mfaService.verifyToken(secret, '1234567')).toBe(false);
        });

        it('should handle token with spaces/dashes', () => {
            const secret = mfaService.generateSecret();
            const token = authenticator.generate(secret);
            const formattedToken = `${token.slice(0, 3)} ${token.slice(3)}`;

            const isValid = mfaService.verifyToken(secret, formattedToken);
            expect(isValid).toBe(true);
        });
    });

    describe('generateBackupCodes', () => {
        it('should generate the correct number of codes', () => {
            const codes = mfaService.generateBackupCodes();

            expect(codes).toHaveLength(10); // Default count
        });

        it('should generate unique codes', () => {
            const codes = mfaService.generateBackupCodes();
            const uniqueCodes = new Set(codes);

            expect(uniqueCodes.size).toBe(codes.length);
        });

        it('should generate codes in correct format', () => {
            const codes = mfaService.generateBackupCodes();

            for (const code of codes) {
                expect(code).toMatch(/^[A-Z0-9]{4}-[A-Z0-9]{4}$/);
            }
        });
    });

    describe('backup code verification', () => {
        it('should verify valid backup code', () => {
            const codes = mfaService.generateBackupCodes();
            const hashedCodes = mfaService.hashBackupCodes(codes);

            const result = mfaService.verifyBackupCode(codes[0]!, hashedCodes);
            expect(result.valid).toBe(true);
            expect(result.index).toBe(0);
        });

        it('should reject invalid backup code', () => {
            const codes = mfaService.generateBackupCodes();
            const hashedCodes = mfaService.hashBackupCodes(codes);

            const result = mfaService.verifyBackupCode('AAAA-BBBB', hashedCodes);
            expect(result.valid).toBe(false);
            expect(result.index).toBe(-1);
        });

        it('should verify code regardless of case', () => {
            const codes = mfaService.generateBackupCodes();
            const hashedCodes = mfaService.hashBackupCodes(codes);

            const lowerCode = codes[0]!.toLowerCase();
            const result = mfaService.verifyBackupCode(lowerCode, hashedCodes);
            expect(result.valid).toBe(true);
        });
    });

    describe('setupMFA', () => {
        it('should return complete setup data', async () => {
            const email = 'test@example.com';
            const setup = await mfaService.setupMFA(email);

            expect(setup.secret).toBeDefined();
            expect(setup.qrCodeDataUrl).toMatch(/^data:image\/png;base64,/);
            expect(setup.backupCodes).toHaveLength(10);
        });
    });
});
