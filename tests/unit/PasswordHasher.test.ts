import { PasswordHasher, PasswordValidationError } from '../../src/utils/PasswordHasher';

describe('PasswordHasher', () => {
    let hasher: PasswordHasher;

    beforeEach(() => {
        hasher = new PasswordHasher();
    });

    describe('hash', () => {
        it('should hash a valid password', async () => {
            const password = 'SecureP@ssword123!';
            const hash = await hasher.hash(password);

            expect(hash).toBeDefined();
            expect(hash).not.toBe(password);
            expect(hash.startsWith('$2b$')).toBe(true);
        });

        it('should generate different hashes for the same password', async () => {
            const password = 'SecureP@ssword123!';
            const hash1 = await hasher.hash(password);
            const hash2 = await hasher.hash(password);

            expect(hash1).not.toBe(hash2);
        });

        it('should reject weak passwords', async () => {
            const weakPasswords = [
                'short',           // Too short
                'nouppercase123!', // No uppercase
                'NOLOWERCASE123!', // No lowercase
                'NoNumbers!!!!',   // No numbers
                'NoSpecialChar123', // No special chars
            ];

            for (const password of weakPasswords) {
                await expect(hasher.hash(password)).rejects.toThrow(PasswordValidationError);
            }
        });
    });

    describe('verify', () => {
        it('should verify correct password', async () => {
            const password = 'SecureP@ssword123!';
            const hash = await hasher.hash(password);

            const isValid = await hasher.verify(password, hash);
            expect(isValid).toBe(true);
        });

        it('should reject incorrect password', async () => {
            const password = 'SecureP@ssword123!';
            const hash = await hasher.hash(password);

            const isValid = await hasher.verify('WrongPassword123!', hash);
            expect(isValid).toBe(false);
        });

        it('should handle invalid hash format gracefully', async () => {
            const isValid = await hasher.verify('password', 'invalid-hash');
            expect(isValid).toBe(false);
        });
    });

    describe('validatePasswordStrength', () => {
        it('should accept strong passwords', () => {
            const strongPasswords = [
                'SecureP@ssword123!',
                'MyB@nkingP@ss2024',
                'C0mpl3x!P@ssw0rd',
            ];

            for (const password of strongPasswords) {
                expect(() => hasher.validatePasswordStrength(password)).not.toThrow();
            }
        });

        it('should reject passwords without lowercase', () => {
            expect(() => hasher.validatePasswordStrength('ALLUPPERCASE123!')).toThrow();
        });

        it('should reject passwords without uppercase', () => {
            expect(() => hasher.validatePasswordStrength('alllowercase123!')).toThrow();
        });

        it('should reject passwords without numbers', () => {
            expect(() => hasher.validatePasswordStrength('NoNumbersHere!')).toThrow();
        });

        it('should reject passwords without special characters', () => {
            expect(() => hasher.validatePasswordStrength('NoSpecialChars123')).toThrow();
        });

        it('should reject passwords shorter than minimum length', () => {
            expect(() => hasher.validatePasswordStrength('Short1!')).toThrow();
        });
    });

    describe('matchesAnyInHistory', () => {
        it('should detect password in history', async () => {
            const password = 'SecureP@ssword123!';
            const hash = await hasher.hash(password);

            const matches = await hasher.matchesAnyInHistory(password, [hash]);
            expect(matches).toBe(true);
        });

        it('should not match different password', async () => {
            const password = 'SecureP@ssword123!';
            const hash = await hasher.hash(password);

            const matches = await hasher.matchesAnyInHistory('DifferentP@ss123!', [hash]);
            expect(matches).toBe(false);
        });

        it('should check multiple hashes in history', async () => {
            const passwords = [
                'FirstP@ssword123!',
                'SecondP@ssword123!',
                'ThirdP@ssword123!',
            ];

            const hashes = await Promise.all(passwords.map(p => hasher.hash(p)));

            // Should match second password
            const matches = await hasher.matchesAnyInHistory('SecondP@ssword123!', hashes);
            expect(matches).toBe(true);
        });
    });
});
