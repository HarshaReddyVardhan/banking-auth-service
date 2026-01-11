import {
    Model,
    DataTypes,
    InferAttributes,
    InferCreationAttributes,
    CreationOptional,
} from 'sequelize';
import { sequelize } from './index';
import crypto from 'crypto';

/**
 * Email Verification OTP - 6-digit crypto-random
 * SHA-256 hashed, 15-minute expiry, max 3 attempts
 */
export class EmailVerificationOTP extends Model<
    InferAttributes<EmailVerificationOTP>,
    InferCreationAttributes<EmailVerificationOTP>
> {
    declare id: CreationOptional<string>;
    declare userId: string;
    declare email: string;
    declare otpHash: string; // SHA-256 of the OTP
    declare expiresAt: Date;
    declare attempts: CreationOptional<number>;
    declare maxAttempts: CreationOptional<number>;
    declare verifiedAt: CreationOptional<Date | null>;
    declare createdAt: CreationOptional<Date>;

    /**
     * Generate a cryptographically secure 6-digit OTP
     */
    static generateOTP(): string {
        // Generate random bytes and convert to 6-digit number
        const bytes = crypto.randomBytes(4);
        const num = bytes.readUInt32BE(0) % 1000000;
        return num.toString().padStart(6, '0');
    }

    /**
     * Hash OTP for storage
     */
    static hashOTP(otp: string): string {
        return crypto.createHash('sha256').update(otp).digest('hex');
    }

    /**
     * Create a new OTP for email verification
     */
    static async createOTP(
        userId: string,
        email: string,
        expiryMinutes: number = 15
    ): Promise<{ otpRecord: EmailVerificationOTP; plainOTP: string }> {
        // Invalidate any existing OTPs for this user/email
        await EmailVerificationOTP.update(
            { expiresAt: new Date() },
            { where: { userId, email, verifiedAt: null } }
        );

        const plainOTP = EmailVerificationOTP.generateOTP();
        const otpHash = EmailVerificationOTP.hashOTP(plainOTP);
        const expiresAt = new Date();
        expiresAt.setMinutes(expiresAt.getMinutes() + expiryMinutes);

        const otpRecord = await EmailVerificationOTP.create({
            userId,
            email,
            otpHash,
            expiresAt,
            attempts: 0,
            maxAttempts: 3,
        });

        return { otpRecord, plainOTP };
    }

    /**
     * Verify an OTP
     */
    static async verifyOTP(
        userId: string,
        email: string,
        otp: string
    ): Promise<{ valid: boolean; error?: string }> {
        const record = await EmailVerificationOTP.findOne({
            where: {
                userId,
                email: email.toLowerCase(),
                verifiedAt: null,
            },
            order: [['createdAt', 'DESC']],
        });

        if (!record) {
            return { valid: false, error: 'No OTP found. Please request a new one.' };
        }

        // Check expiry
        if (new Date() > record.expiresAt) {
            return { valid: false, error: 'OTP has expired. Please request a new one.' };
        }

        // Check attempts
        if (record.attempts >= record.maxAttempts) {
            return { valid: false, error: 'Too many attempts. Please request a new OTP.' };
        }

        // Increment attempts
        record.attempts += 1;
        await record.save();

        // Verify OTP using timing-safe comparison
        const inputHash = EmailVerificationOTP.hashOTP(otp);
        const isValid = crypto.timingSafeEqual(
            Buffer.from(inputHash, 'hex'),
            Buffer.from(record.otpHash, 'hex')
        );

        if (!isValid) {
            const remainingAttempts = record.maxAttempts - record.attempts;
            return {
                valid: false,
                error: `Invalid OTP. ${remainingAttempts} attempts remaining.`,
            };
        }

        // Mark as verified
        record.verifiedAt = new Date();
        await record.save();

        return { valid: true };
    }

    /**
     * Check rate limit for OTP requests
     */
    static async checkRateLimit(
        email: string,
        maxPerHour: number = 3
    ): Promise<{ allowed: boolean; retryAfterMinutes?: number }> {
        const oneHourAgo = new Date();
        oneHourAgo.setHours(oneHourAgo.getHours() - 1);

        const count = await EmailVerificationOTP.count({
            where: {
                email: email.toLowerCase(),
                createdAt: { $gte: oneHourAgo },
            },
        });

        if (count >= maxPerHour) {
            // Find oldest OTP in window to calculate retry time
            const oldest = await EmailVerificationOTP.findOne({
                where: {
                    email: email.toLowerCase(),
                    createdAt: { $gte: oneHourAgo },
                },
                order: [['createdAt', 'ASC']],
            });

            if (oldest) {
                const retryAt = new Date(oldest.createdAt);
                retryAt.setHours(retryAt.getHours() + 1);
                const retryAfterMinutes = Math.ceil((retryAt.getTime() - Date.now()) / 60000);
                return { allowed: false, retryAfterMinutes };
            }

            return { allowed: false, retryAfterMinutes: 60 };
        }

        return { allowed: true };
    }
}

EmailVerificationOTP.init(
    {
        id: {
            type: DataTypes.UUID,
            defaultValue: DataTypes.UUIDV4,
            primaryKey: true,
        },
        userId: {
            type: DataTypes.UUID,
            allowNull: false,
        },
        email: {
            type: DataTypes.STRING(255),
            allowNull: false,
            set(value: string) {
                this.setDataValue('email', value.toLowerCase().trim());
            },
        },
        otpHash: {
            type: DataTypes.STRING(64),
            allowNull: false,
        },
        expiresAt: {
            type: DataTypes.DATE,
            allowNull: false,
        },
        attempts: {
            type: DataTypes.INTEGER,
            allowNull: false,
            defaultValue: 0,
        },
        maxAttempts: {
            type: DataTypes.INTEGER,
            allowNull: false,
            defaultValue: 3,
        },
        verifiedAt: {
            type: DataTypes.DATE,
            allowNull: true,
        },
        createdAt: {
            type: DataTypes.DATE,
            allowNull: false,
            defaultValue: DataTypes.NOW,
        },
    },
    {
        sequelize,
        tableName: 'email_verification_otps',
        modelName: 'EmailVerificationOTP',
        timestamps: false,
        indexes: [
            { fields: ['user_id'] },
            { fields: ['email'] },
            { fields: ['expires_at'] },
            { fields: ['user_id', 'email', 'verified_at'] },
        ],
    }
);
