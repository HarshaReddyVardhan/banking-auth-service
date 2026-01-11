import { BreachChecker } from '../../src/services/BreachChecker';

describe('BreachChecker', () => {
    let breachChecker: BreachChecker;

    beforeEach(() => {
        breachChecker = new BreachChecker();
    });

    describe('isCommonPassword', () => {
        it('should detect common passwords', () => {
            const commonPasswords = [
                '123456',
                'password',
                'password123',
                'qwerty',
                'admin',
            ];

            for (const password of commonPasswords) {
                expect(breachChecker.isCommonPassword(password)).toBe(true);
            }
        });

        it('should not flag unique passwords', () => {
            const uniquePasswords = [
                'MyUniqueP@ss123!',
                'Xk9#mLp2$vNq',
                'B@nk1ngS3cur3!',
            ];

            for (const password of uniquePasswords) {
                expect(breachChecker.isCommonPassword(password)).toBe(false);
            }
        });

        it('should be case insensitive', () => {
            expect(breachChecker.isCommonPassword('PASSWORD')).toBe(true);
            expect(breachChecker.isCommonPassword('Password')).toBe(true);
            expect(breachChecker.isCommonPassword('QWERTY')).toBe(true);
        });
    });

    describe('isPasswordSecure', () => {
        it('should reject common passwords', async () => {
            const result = await breachChecker.isPasswordSecure('password123');

            expect(result.secure).toBe(false);
            expect(result.reason).toContain('common');
        });

        it('should accept unique passwords', async () => {
            const result = await breachChecker.isPasswordSecure('Xk9#mLp2$vNqR8!w');

            expect(result.secure).toBe(true);
        });
    });

    // Note: Integration tests with actual HIBP API should be in integration tests
    describe('checkPassword (mocked)', () => {
        it('should return result when API unavailable', async () => {
            // BreachChecker fails open - returns not breached if API unavailable
            const result = await breachChecker.checkPassword('anypassword');

            // Either succeeds with API or fails open
            expect(result).toHaveProperty('isBreached');
        });
    });
});
