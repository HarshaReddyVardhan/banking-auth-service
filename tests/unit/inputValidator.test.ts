import { validationSchemas } from '../../src/middleware/inputValidator';

describe('Input Validation Schemas', () => {
    describe('register schema', () => {
        const schema = validationSchemas.register;

        it('should accept valid registration data', () => {
            const { error } = schema.validate({
                email: 'test@example.com',
                password: 'SecureP@ssword123!',
            });

            expect(error).toBeUndefined();
        });

        it('should reject invalid email', () => {
            const { error } = schema.validate({
                email: 'not-an-email',
                password: 'SecureP@ssword123!',
            });

            expect(error).toBeDefined();
            expect(error?.details[0]?.path).toContain('email');
        });

        it('should reject weak password', () => {
            const { error } = schema.validate({
                email: 'test@example.com',
                password: 'weak',
            });

            expect(error).toBeDefined();
            expect(error?.details[0]?.path).toContain('password');
        });

        it('should reject password without uppercase', () => {
            const { error } = schema.validate({
                email: 'test@example.com',
                password: 'alllowercase123!',
            });

            expect(error).toBeDefined();
        });

        it('should reject password without special character', () => {
            const { error } = schema.validate({
                email: 'test@example.com',
                password: 'NoSpecialChars123',
            });

            expect(error).toBeDefined();
        });

        it('should normalize email to lowercase', () => {
            const { value } = schema.validate({
                email: 'TEST@EXAMPLE.COM',
                password: 'SecureP@ssword123!',
            });

            expect(value.email).toBe('test@example.com');
        });
    });

    describe('login schema', () => {
        const schema = validationSchemas.login;

        it('should accept valid login without MFA', () => {
            const { error } = schema.validate({
                email: 'test@example.com',
                password: 'anypassword',
            });

            expect(error).toBeUndefined();
        });

        it('should accept login with TOTP token', () => {
            const { error } = schema.validate({
                email: 'test@example.com',
                password: 'anypassword',
                mfaToken: '123456',
            });

            expect(error).toBeUndefined();
        });

        it('should accept login with backup code', () => {
            const { error } = schema.validate({
                email: 'test@example.com',
                password: 'anypassword',
                mfaToken: 'ABCD-1234',
            });

            expect(error).toBeUndefined();
        });

        it('should accept login with device fingerprint', () => {
            const { error } = schema.validate({
                email: 'test@example.com',
                password: 'anypassword',
                deviceFingerprint: {
                    userAgent: 'Mozilla/5.0...',
                    screenResolution: '1920x1080',
                    timezone: 'America/New_York',
                },
            });

            expect(error).toBeUndefined();
        });
    });

    describe('resetPassword schema', () => {
        const schema = validationSchemas.resetPassword;

        it('should accept valid reset data', () => {
            const { error } = schema.validate({
                token: 'a'.repeat(64), // 64 hex chars
                password: 'NewSecureP@ss123!',
            });

            expect(error).toBeUndefined();
        });

        it('should reject invalid token format', () => {
            const { error } = schema.validate({
                token: 'short-token',
                password: 'NewSecureP@ss123!',
            });

            expect(error).toBeDefined();
            expect(error?.details[0]?.path).toContain('token');
        });
    });

    describe('mfaVerify schema', () => {
        const schema = validationSchemas.mfaVerify;

        it('should accept valid MFA verification data', () => {
            const { error } = schema.validate({
                secret: 'JBSWY3DPEHPK3PXP',
                token: '123456',
                backupCodes: Array(10).fill('ABCD-1234'),
            });

            expect(error).toBeUndefined();
        });

        it('should reject invalid TOTP format', () => {
            const { error } = schema.validate({
                secret: 'JBSWY3DPEHPK3PXP',
                token: '12345', // Only 5 digits
                backupCodes: Array(10).fill('ABCD-1234'),
            });

            expect(error).toBeDefined();
        });

        it('should require minimum backup codes', () => {
            const { error } = schema.validate({
                secret: 'JBSWY3DPEHPK3PXP',
                token: '123456',
                backupCodes: ['ABCD-1234'], // Only 1 code
            });

            expect(error).toBeDefined();
        });
    });
});
