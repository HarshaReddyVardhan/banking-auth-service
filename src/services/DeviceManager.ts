import crypto from 'crypto';
import UAParser from 'ua-parser-js';
import geoip from 'geoip-lite';
import { Device, DeviceType, DeviceTrustLevel } from '../models/Device';
import { logger } from '../middleware/requestLogger';

/**
 * Device fingerprint data collected from client
 */
export interface DeviceFingerprintData {
    userAgent: string;
    screenResolution?: string;
    timezone?: string;
    language?: string;
    platform?: string;
    colorDepth?: number;
    hardwareConcurrency?: number;
    deviceMemory?: number;
    canvas?: string;      // Canvas fingerprint hash
    webgl?: string;       // WebGL renderer info
    audioContext?: string; // Audio fingerprint
}

/**
 * Parsed device info
 */
export interface DeviceInfo {
    fingerprint: string;
    deviceType: DeviceType;
    browser: string;
    browserVersion: string;
    os: string;
    osVersion: string;
    deviceName: string;
}

/**
 * Device Manager for secure device fingerprinting and trust scoring
 */
export class DeviceManager {
    /**
     * Generate a secure device fingerprint from collected data
     */
    generateFingerprint(data: DeviceFingerprintData): string {
        // Combine stable device characteristics
        const fingerprintSource = [
            data.userAgent,
            data.screenResolution ?? '',
            data.timezone ?? '',
            data.language ?? '',
            data.platform ?? '',
            data.colorDepth?.toString() ?? '',
            data.hardwareConcurrency?.toString() ?? '',
            data.canvas ?? '',
            data.webgl ?? '',
            data.audioContext ?? '',
        ].join('|');

        // Generate SHA-256 hash of combined data
        return crypto.createHash('sha256').update(fingerprintSource).digest('hex');
    }

    /**
     * Parse user agent to extract device info
     */
    parseUserAgent(userAgent: string): Omit<DeviceInfo, 'fingerprint'> {
        const parser = new UAParser(userAgent);
        const result = parser.getResult();

        // Determine device type
        let deviceType: DeviceType;
        const deviceTypeStr = result.device.type?.toLowerCase();

        if (deviceTypeStr === 'mobile') {
            deviceType = DeviceType.MOBILE;
        } else if (deviceTypeStr === 'tablet') {
            deviceType = DeviceType.TABLET;
        } else {
            deviceType = DeviceType.DESKTOP;
        }

        // Create human-readable device name
        const deviceName = this.generateDeviceName(result);

        return {
            deviceType,
            browser: result.browser.name ?? 'Unknown',
            browserVersion: result.browser.version ?? '',
            os: result.os.name ?? 'Unknown',
            osVersion: result.os.version ?? '',
            deviceName,
        };
    }

    /**
     * Generate a human-readable device name
     */
    private generateDeviceName(uaResult: UAParser.IResult): string {
        const parts: string[] = [];

        if (uaResult.device.vendor) {
            parts.push(uaResult.device.vendor);
        }
        if (uaResult.device.model) {
            parts.push(uaResult.device.model);
        }
        if (parts.length === 0 && uaResult.os.name) {
            parts.push(uaResult.os.name);
        }
        if (uaResult.browser.name) {
            parts.push(`(${uaResult.browser.name})`);
        }

        return parts.join(' ') || 'Unknown Device';
    }

    /**
     * Register a new device or update existing one
     */
    async registerDevice(
        userId: string,
        fingerprintData: DeviceFingerprintData,
        ip: string
    ): Promise<Device> {
        const fingerprint = this.generateFingerprint(fingerprintData);
        const deviceInfo = this.parseUserAgent(fingerprintData.userAgent);

        // Get geolocation
        const geo = geoip.lookup(ip);

        // Check if device already exists
        let device = await Device.findOne({
            where: {
                userId,
                fingerprint,
                revokedAt: null,
            },
        });

        if (device) {
            // Update existing device
            device.lastUsedAt = new Date();
            device.lastUsedIp = ip;
            device.loginCount = (device.loginCount ?? 0) + 1;
            device.lastCountry = geo?.country ?? null;
            device.lastCity = geo?.city ?? null;

            // Increase trust score slightly for returning device
            if (device.trustScore < 100 && device.trustLevel !== DeviceTrustLevel.BLOCKED) {
                device.trustScore = Math.min(100, device.trustScore + 5);
            }

            await device.save();

            logger.info('Known device used', {
                userId,
                deviceId: device.id,
                trustScore: device.trustScore,
            });
        } else {
            // Create new device
            device = await Device.create({
                userId,
                fingerprint,
                deviceName: deviceInfo.deviceName,
                deviceType: deviceInfo.deviceType,
                browser: deviceInfo.browser,
                browserVersion: deviceInfo.browserVersion,
                os: deviceInfo.os,
                osVersion: deviceInfo.osVersion,
                trustLevel: DeviceTrustLevel.UNTRUSTED,
                trustScore: 20, // Initial trust score
                lastUsedAt: new Date(),
                lastUsedIp: ip,
                loginCount: 1,
                lastCountry: geo?.country ?? null,
                lastCity: geo?.city ?? null,
            });

            logger.info('New device registered', {
                userId,
                deviceId: device.id,
                deviceType: device.deviceType,
            });
        }

        return device;
    }

    /**
     * Get all devices for a user
     */
    async getUserDevices(userId: string): Promise<Device[]> {
        return Device.findAll({
            where: {
                userId,
                revokedAt: null,
            },
            order: [['lastUsedAt', 'DESC']],
        });
    }

    /**
     * Trust a device (after MFA verification)
     */
    async trustDevice(userId: string, deviceId: string): Promise<Device | null> {
        const device = await Device.findOne({
            where: {
                id: deviceId,
                userId,
                revokedAt: null,
            },
        });

        if (!device) {
            return null;
        }

        device.trustLevel = DeviceTrustLevel.TRUSTED;
        device.trustScore = 100;
        device.trustedAt = new Date();
        device.trustedByUserId = userId;
        await device.save();

        logger.info('Device trusted', {
            userId,
            deviceId,
        });

        return device;
    }

    /**
     * Revoke a device
     */
    async revokeDevice(userId: string, deviceId: string): Promise<boolean> {
        const device = await Device.findOne({
            where: {
                id: deviceId,
                userId,
                revokedAt: null,
            },
        });

        if (!device) {
            return false;
        }

        device.revokedAt = new Date();
        await device.save();

        logger.info('Device revoked', {
            userId,
            deviceId,
        });

        return true;
    }

    /**
     * Block a suspicious device
     */
    async blockDevice(userId: string, deviceId: string, reason: string): Promise<boolean> {
        const device = await Device.findOne({
            where: {
                id: deviceId,
                userId,
            },
        });

        if (!device) {
            return false;
        }

        device.trustLevel = DeviceTrustLevel.BLOCKED;
        device.trustScore = 0;
        await device.save();

        logger.warn('Device blocked', {
            userId,
            deviceId,
            reason,
        });

        return true;
    }

    /**
     * Check if a device is known and trusted
     */
    async isDeviceTrusted(userId: string, fingerprint: string): Promise<{ known: boolean; trusted: boolean; device?: Device }> {
        const device = await Device.findOne({
            where: {
                userId,
                fingerprint,
                revokedAt: null,
            },
        });

        if (!device) {
            return { known: false, trusted: false };
        }

        if (device.trustLevel === DeviceTrustLevel.BLOCKED) {
            return { known: true, trusted: false, device };
        }

        return {
            known: true,
            trusted: device.isTrusted(),
            device,
        };
    }

    /**
     * Calculate trust score based on device history and behavior
     */
    calculateTrustScore(device: Device): number {
        let score = device.trustScore;

        // Boost for login count (familiarity)
        if (device.loginCount > 10) score += 10;
        if (device.loginCount > 50) score += 10;

        // Boost for being explicitly trusted
        if (device.trustLevel === DeviceTrustLevel.TRUSTED) score += 20;

        // Cap at 100
        return Math.min(100, Math.max(0, score));
    }
}

// Export singleton
export const deviceManager = new DeviceManager();
