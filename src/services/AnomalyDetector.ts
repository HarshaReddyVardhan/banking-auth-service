import geoip from 'geoip-lite';
import { LoginHistory, LoginResult } from '../models/LoginHistory';
import { logger as _logger, securityLogger } from '../middleware/requestLogger';
import { Op } from 'sequelize';

/**
 * Anomaly detection result
 */
export interface AnomalyResult {
    isAnomaly: boolean;
    riskScore: number; // 0-100
    reasons: string[];
    shouldChallenge: boolean; // Require MFA even if not normally required
    shouldBlock: boolean; // Block login entirely
}

/**
 * Location data
 */
interface LocationData {
    country: string | null;
    city: string | null;
    latitude: number | null;
    longitude: number | null;
}

/**
 * Anomaly Detector Service
 * Detects suspicious login patterns and potential fraud
 */
export class AnomalyDetector {
    // Risk thresholds
    private readonly CHALLENGE_THRESHOLD = 40; // Require additional verification
    private readonly BLOCK_THRESHOLD = 80; // Block login

    // Time windows
    private readonly IMPOSSIBLE_TRAVEL_HOURS = 2;
    private readonly PATTERN_ANALYSIS_DAYS = 30;

    /**
     * Analyze a login attempt for anomalies
     */
    async analyzeLogin(
        userId: string,
        email: string,
        ip: string,
        userAgent: string,
        deviceFingerprint?: string
    ): Promise<AnomalyResult> {
        const reasons: string[] = [];
        let riskScore = 0;

        // Get location data
        const location = this.getLocationFromIp(ip);

        // Get user's login history
        const recentLogins = await this.getRecentLogins(userId);
        const successfulLogins = recentLogins.filter(
            l => l.loginResult === LoginResult.SUCCESS
        );

        // 1. Check for impossible travel
        const impossibleTravel = this.checkImpossibleTravel(location, successfulLogins);
        if (impossibleTravel.detected) {
            riskScore += 50;
            reasons.push(`Impossible travel detected: ${impossibleTravel.reason}`);
        }

        // 2. Check for new country
        const newCountry = this.checkNewCountry(location, successfulLogins);
        if (newCountry) {
            riskScore += 25;
            reasons.push(`First login from country: ${location.country}`);
        }

        // 3. Check for unusual hour
        const unusualHour = this.checkUnusualHour(userId, successfulLogins);
        if (unusualHour) {
            riskScore += 15;
            reasons.push('Login at unusual time');
        }

        // 4. Check for rapid login attempts
        const rapidAttempts = await this.checkRapidAttempts(email, ip);
        if (rapidAttempts.detected) {
            riskScore += rapidAttempts.score;
            reasons.push(rapidAttempts.reason);
        }

        // 5. Check for new device (if fingerprint provided)
        if (deviceFingerprint) {
            const newDevice = this.checkNewDevice(deviceFingerprint, successfulLogins);
            if (newDevice) {
                riskScore += 10;
                reasons.push('Login from new/unknown device');
            }
        }

        // 6. Check for suspicious user agent patterns
        const suspiciousUA = this.checkSuspiciousUserAgent(userAgent);
        if (suspiciousUA.detected) {
            riskScore += 20;
            reasons.push(suspiciousUA.reason);
        }

        // 7. Check for TOR/VPN exit nodes (simplified)
        const anonymousNetwork = await this.checkAnonymousNetwork(ip);
        if (anonymousNetwork) {
            riskScore += 30;
            reasons.push('Login from anonymous network (VPN/Tor)');
        }

        // Cap risk score at 100
        riskScore = Math.min(100, riskScore);

        const result: AnomalyResult = {
            isAnomaly: reasons.length > 0,
            riskScore,
            reasons,
            shouldChallenge: riskScore >= this.CHALLENGE_THRESHOLD,
            shouldBlock: riskScore >= this.BLOCK_THRESHOLD,
        };

        // Log anomalies
        if (result.isAnomaly) {
            securityLogger.suspiciousActivity(userId, ip, 'login_anomaly', {
                riskScore,
                reasons,
                shouldBlock: result.shouldBlock,
            });
        }

        return result;
    }

    /**
     * Get location data from IP address
     */
    getLocationFromIp(ip: string): LocationData {
        const geo = geoip.lookup(ip);

        if (!geo) {
            return {
                country: null,
                city: null,
                latitude: null,
                longitude: null,
            };
        }

        return {
            country: geo.country,
            city: geo.city,
            latitude: geo.ll?.[0] ?? null,
            longitude: geo.ll?.[1] ?? null,
        };
    }

    /**
     * Get recent login history for a user
     */
    private async getRecentLogins(userId: string): Promise<LoginHistory[]> {
        const since = new Date();
        since.setDate(since.getDate() - this.PATTERN_ANALYSIS_DAYS);

        return LoginHistory.findAll({
            where: {
                userId,
                createdAt: { [Op.gte]: since },
            },
            order: [['createdAt', 'DESC']],
            limit: 100,
        });
    }

    /**
     * Check for impossible travel (login from distant location too quickly)
     */
    private checkImpossibleTravel(
        currentLocation: LocationData,
        recentLogins: LoginHistory[]
    ): { detected: boolean; reason: string } {
        if (!currentLocation.latitude || !currentLocation.longitude) {
            return { detected: false, reason: '' };
        }

        const cutoffTime = new Date();
        cutoffTime.setHours(cutoffTime.getHours() - this.IMPOSSIBLE_TRAVEL_HOURS);

        for (const login of recentLogins) {
            if (new Date(login.createdAt) < cutoffTime) break;
            if (!login.latitude || !login.longitude) continue;

            const distance = this.calculateDistance(
                currentLocation.latitude,
                currentLocation.longitude,
                Number(login.latitude),
                Number(login.longitude)
            );

            // If more than 500km in less than 2 hours = impossible
            // (Average commercial flight: ~900 km/h, so 500km in 2h is generous)
            if (distance > 500) {
                const timeDiffHours = (Date.now() - new Date(login.createdAt).getTime()) / (1000 * 60 * 60);
                const requiredSpeed = distance / timeDiffHours;

                if (requiredSpeed > 500) { // km/h
                    return {
                        detected: true,
                        reason: `${Math.round(distance)}km from last login in ${Math.round(timeDiffHours * 60)}min`,
                    };
                }
            }
        }

        return { detected: false, reason: '' };
    }

    /**
     * Calculate distance between two points (Haversine formula)
     */
    private calculateDistance(
        lat1: number,
        lon1: number,
        lat2: number,
        lon2: number
    ): number {
        const R = 6371; // Earth's radius in km
        const dLat = this.toRad(lat2 - lat1);
        const dLon = this.toRad(lon2 - lon1);
        const a =
            Math.sin(dLat / 2) * Math.sin(dLat / 2) +
            Math.cos(this.toRad(lat1)) *
            Math.cos(this.toRad(lat2)) *
            Math.sin(dLon / 2) *
            Math.sin(dLon / 2);
        const c = 2 * Math.atan2(Math.sqrt(a), Math.sqrt(1 - a));
        return R * c;
    }

    private toRad(deg: number): number {
        return deg * (Math.PI / 180);
    }

    /**
     * Check if this is the first login from this country
     */
    private checkNewCountry(
        currentLocation: LocationData,
        recentLogins: LoginHistory[]
    ): boolean {
        if (!currentLocation.country) return false;

        const knownCountries = new Set(
            recentLogins.map(l => l.country).filter(Boolean)
        );

        return !knownCountries.has(currentLocation.country);
    }

    /**
     * Check if login is at an unusual hour for this user
     */
    private checkUnusualHour(
        _userId: string,
        recentLogins: LoginHistory[]
    ): boolean {
        if (recentLogins.length < 10) return false; // Not enough data

        const currentHour = new Date().getHours();
        const loginHours = recentLogins.map(l => new Date(l.createdAt).getHours());

        // Calculate mean and stddev of login hours
        const mean = loginHours.reduce((a, b) => a + b, 0) / loginHours.length;
        const variance =
            loginHours.reduce((sum, h) => sum + Math.pow(h - mean, 2), 0) /
            loginHours.length;
        const stdDev = Math.sqrt(variance);

        // If current hour is more than 2 standard deviations from mean
        return Math.abs(currentHour - mean) > 2 * stdDev;
    }

    /**
     * Check for rapid login attempts (potential brute force)
     */
    private async checkRapidAttempts(
        email: string,
        ip: string
    ): Promise<{ detected: boolean; score: number; reason: string }> {
        const oneMinuteAgo = new Date();
        oneMinuteAgo.setMinutes(oneMinuteAgo.getMinutes() - 1);

        const recentAttempts = await LoginHistory.count({
            where: {
                [Op.or]: [{ email }, { ipAddress: ip }],
                createdAt: { [Op.gte]: oneMinuteAgo },
            },
        });

        if (recentAttempts > 10) {
            return {
                detected: true,
                score: 40,
                reason: `${recentAttempts} login attempts in last minute`,
            };
        }

        if (recentAttempts > 5) {
            return {
                detected: true,
                score: 20,
                reason: `${recentAttempts} login attempts in last minute`,
            };
        }

        return { detected: false, score: 0, reason: '' };
    }

    /**
     * Check if device fingerprint is new
     */
    private checkNewDevice(
        fingerprint: string,
        recentLogins: LoginHistory[]
    ): boolean {
        const knownFingerprints = new Set(
            recentLogins.map(l => l.deviceFingerprint).filter(Boolean)
        );

        return !knownFingerprints.has(fingerprint);
    }

    /**
     * Check for suspicious user agent patterns
     */
    private checkSuspiciousUserAgent(
        userAgent: string
    ): { detected: boolean; reason: string } {
        const ua = userAgent.toLowerCase();

        // Check for automation tools
        if (
            ua.includes('curl') ||
            ua.includes('wget') ||
            ua.includes('python') ||
            ua.includes('scrapy') ||
            ua.includes('bot') ||
            ua.includes('crawler')
        ) {
            return { detected: true, reason: 'Automated/bot user agent detected' };
        }

        // Check for very old browsers (often spoofed)
        if (ua.includes('msie 6') || ua.includes('msie 7') || ua.includes('msie 8')) {
            return { detected: true, reason: 'Outdated browser (potential spoofing)' };
        }

        // Empty or very short user agent
        if (userAgent.length < 10) {
            return { detected: true, reason: 'Missing or invalid user agent' };
        }

        return { detected: false, reason: '' };
    }

    /**
     * Check if IP is from anonymous network (TOR/VPN)
     * This is a simplified check - production should use a threat intelligence service
     */
    private async checkAnonymousNetwork(ip: string): Promise<boolean> {
        // In production, integrate with services like:
        // - MaxMind GeoIP2 Anonymous IP
        // - IPQualityScore
        // - IP2Location

        // For now, just check for known TOR exit patterns
        // This is NOT comprehensive - use a real service in production
        const _geo = geoip.lookup(ip);

        // Some VPN/hosting providers (simplified check)
        const _suspiciousASNs = ['AS9009', 'AS16276', 'AS24940', 'AS208622'];

        return false; // Placeholder - implement with real service
    }

    /**
     * Record login attempt with anomaly data
     */
    async recordLoginAttempt(
        userId: string | null,
        email: string,
        ip: string,
        userAgent: string,
        result: LoginResult,
        anomalyResult?: AnomalyResult,
        sessionId?: string,
        deviceId?: string,
        deviceFingerprint?: string
    ): Promise<LoginHistory> {
        const location = this.getLocationFromIp(ip);

        return LoginHistory.create({
            userId,
            email,
            ipAddress: ip,
            userAgent,
            deviceId,
            deviceFingerprint,
            loginResult: result,
            country: location.country,
            city: location.city,
            latitude: location.latitude,
            longitude: location.longitude,
            isAnomaly: anomalyResult?.isAnomaly ?? false,
            anomalyReasons: anomalyResult?.reasons
                ? JSON.stringify(anomalyResult.reasons)
                : null,
            sessionId,
        });
    }
}

// Export singleton
export const anomalyDetector = new AnomalyDetector();
