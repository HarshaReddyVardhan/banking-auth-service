import { AuthService } from '../../src/services/AuthService';
import { User, UserStatus, KycStatus } from '../../src/models/User';
import { sessionManager } from '../../src/services/SessionManager';
import { eventPublisher } from '../../src/kafka/EventPublisher';
import { ipBlockingService } from '../../src/services/IPBlockingService';
import { rateLimiter } from '../../src/services/RateLimiter';
import { mfaService } from '../../src/services/MFAService';
import { jwtHandler } from '../../src/utils/JWTHandler';
import { RefreshToken } from '../../src/models/RefreshToken';
import { deviceManager } from '../../src/services/DeviceManager';

// Mock dependencies
jest.mock('../../src/models/User');
jest.mock('../../src/services/SessionManager');
jest.mock('../../src/kafka/EventPublisher');
jest.mock('../../src/services/IPBlockingService');
jest.mock('../../src/services/RateLimiter');
jest.mock('../../src/services/MFAService');
jest.mock('../../src/utils/JWTHandler');
jest.mock('../../src/models/RefreshToken');
jest.mock('../../src/services/DeviceManager');
jest.mock('../../src/models/PasswordHistory');
jest.mock('../../src/services/EmailService');
jest.mock('../../src/utils/PasswordHasher');
jest.mock('../../src/services/BreachChecker', () => ({
    breachChecker: {
        isPasswordSecure: jest.fn().mockResolvedValue({ secure: true })
    }
}));
jest.mock('../../src/services/AnomalyDetector', () => ({
    anomalyDetector: {
        recordLoginAttempt: jest.fn(),
        analyzeLogin: jest.fn().mockResolvedValue({ shouldBlock: false, isAnomaly: false })
    }
}));

describe('AuthService', () => {
    let authService: AuthService;

    beforeEach(() => {
        jest.clearAllMocks();
        authService = new AuthService();
    });

    describe('verifyMfaLogin', () => {
        const mockUser = {
            id: 'user-123',
            email: 'test@example.com',
            emailVerified: true,
            mfaEnabled: true,
            kycStatus: KycStatus.VERIFIED,
            getDecryptedMfaSecret: jest.fn(),
            useBackupCode: jest.fn(),
            resetFailedAttempts: jest.fn(),
            recordLogin: jest.fn(),
        };

        const mockTempToken = 'temp-token-123';
        const mockMfaToken = '123456';
        const mockIp = '127.0.0.1';
        const mockUserAgent = 'TestAgent';

        it('should successfully verify MFA and return tokens', async () => {
            // Setup mocks
            (sessionManager.getTempToken as jest.Mock).mockResolvedValue({ userId: mockUser.id });
            (User.findByPk as jest.Mock).mockResolvedValue(mockUser);
            mockUser.getDecryptedMfaSecret.mockReturnValue('secret');
            (mfaService.verifyToken as jest.Mock).mockReturnValue(true);
            (sessionManager.createSession as jest.Mock).mockResolvedValue('session-123');
            (jwtHandler.generateTokenPair as jest.Mock).mockReturnValue({
                accessToken: 'access-token',
                refreshToken: 'refresh-token',
                expiresIn: 3600,
                refreshTokenExpiresAt: 1234567890
            });

            // Execute
            const result = await authService.verifyMfaLogin(
                mockTempToken,
                mockMfaToken,
                mockIp,
                mockUserAgent
            );

            // Assert
            expect(result.success).toBe(true);
            expect(result.sessionId).toBe('session-123');
            expect(sessionManager.getTempToken).toHaveBeenCalledWith(mockTempToken);
            expect(eventPublisher.publish).toHaveBeenCalledWith('user.login.success', expect.anything());
        });

        it('should fail with invalid temp token', async () => {
            (sessionManager.getTempToken as jest.Mock).mockResolvedValue(null);

            const result = await authService.verifyMfaLogin(
                'invalid-token',
                mockMfaToken,
                mockIp,
                mockUserAgent
            );

            expect(result.success).toBe(false);
            expect(result.error).toContain('Invalid or expired');
        });

        it('should fail with invalid MFA code', async () => {
            (sessionManager.getTempToken as jest.Mock).mockResolvedValue({ userId: mockUser.id });
            (User.findByPk as jest.Mock).mockResolvedValue(mockUser);
            mockUser.getDecryptedMfaSecret.mockReturnValue('secret');
            (mfaService.verifyToken as jest.Mock).mockReturnValue(false); // Invalid TOTP
            mockUser.useBackupCode.mockResolvedValue(false); // Invalid backup code

            const result = await authService.verifyMfaLogin(
                mockTempToken,
                'wrong-code',
                mockIp,
                mockUserAgent
            );

            expect(result.success).toBe(false);
            expect(result.error).toBe('Invalid MFA code');
            expect(ipBlockingService.recordFailedAttempt).toHaveBeenCalled();
        });
    });
});
