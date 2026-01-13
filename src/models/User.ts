import {
    Model,
    DataTypes,
    InferAttributes,
    InferCreationAttributes,
    CreationOptional,
} from 'sequelize';
import { sequelize } from './index';
import CryptoJS from 'crypto-js';
import { encryptField as secureEncrypt, decryptField as secureDecrypt } from '../utils/CryptographyUtils';
import { config } from '../config/config';

// Encryption helpers for sensitive fields
// Supports migration from CryptoJS to native AES-256-GCM
function encryptField(value: string): string {
    return secureEncrypt(value);
}

function decryptField(encrypted: string): string {
    // New format (AES-256-GCM) uses colons
    if (encrypted.includes(':')) {
        return secureDecrypt(encrypted);
    }

    // Legacy format (CryptoJS AES-CBC)
    try {
        const bytes = CryptoJS.AES.decrypt(encrypted, config.security.fieldEncryptionKey);
        const decrypted = bytes.toString(CryptoJS.enc.Utf8);
        return decrypted || encrypted;
    } catch {
        return encrypted;
    }
}

// User status enum
export enum UserStatus {
    PENDING_VERIFICATION = 'PENDING_VERIFICATION',
    ACTIVE = 'ACTIVE',
    SUSPENDED = 'SUSPENDED',
    LOCKED = 'LOCKED',
    DEACTIVATED = 'DEACTIVATED',
}

// KYC status enum
export enum KycStatus {
    NOT_STARTED = 'NOT_STARTED',
    PENDING = 'PENDING',
    SUBMITTED = 'SUBMITTED',
    VERIFIED = 'VERIFIED',
    REJECTED = 'REJECTED',
    EXPIRED = 'EXPIRED',
}

export class User extends Model<
    InferAttributes<User>,
    InferCreationAttributes<User>
> {
    // Primary key
    declare id: CreationOptional<string>;

    // Authentication
    declare email: string;
    declare passwordHash: string;
    declare passwordChangedAt: CreationOptional<Date>;
    declare passwordExpiryAt: CreationOptional<Date>;

    // Account status
    declare status: CreationOptional<UserStatus>;
    declare failedLoginAttempts: CreationOptional<number>;
    declare lockedUntil: CreationOptional<Date | null>;
    declare lastFailedLoginAt: CreationOptional<Date | null>;

    // Email verification
    declare emailVerified: CreationOptional<boolean>;
    declare emailVerificationToken: CreationOptional<string | null>;
    declare emailVerificationExpiry: CreationOptional<Date | null>;

    // KYC
    declare kycStatus: CreationOptional<KycStatus>;
    declare kycVerifiedAt: CreationOptional<Date | null>;
    declare kycDocumentId: CreationOptional<string | null>;

    // MFA
    declare mfaEnabled: CreationOptional<boolean>;
    declare mfaSecret: CreationOptional<string | null>;
    declare mfaBackupCodes: CreationOptional<string | null>; // Encrypted JSON array

    // Audit
    declare lastLoginAt: CreationOptional<Date | null>;
    declare lastLoginIp: CreationOptional<string | null>;
    declare lastLoginDeviceId: CreationOptional<string | null>;

    // Timestamps
    declare createdAt: CreationOptional<Date>;
    declare updatedAt: CreationOptional<Date>;
    declare deletedAt: CreationOptional<Date | null>;

    // Instance methods

    // Check if account is locked
    isLocked(): boolean {
        if (!this.lockedUntil) return false;
        return new Date() < this.lockedUntil;
    }

    // Check if password is expired
    isPasswordExpired(): boolean {
        if (!this.passwordExpiryAt) return false;
        return new Date() > this.passwordExpiryAt;
    }

    // Check if email is verified
    isEmailVerified(): boolean {
        return this.emailVerified === true;
    }

    // Check if MFA is enabled
    isMfaEnabled(): boolean {
        return this.mfaEnabled === true && this.mfaSecret !== null;
    }

    // Get decrypted MFA secret
    getDecryptedMfaSecret(): string | null {
        if (!this.mfaSecret) return null;
        return decryptField(this.mfaSecret);
    }

    // Set encrypted MFA secret
    setEncryptedMfaSecret(secret: string): void {
        this.mfaSecret = encryptField(secret);
    }

    // Get backup codes as array
    getBackupCodes(): string[] {
        if (!this.mfaBackupCodes) return [];
        try {
            const decrypted = decryptField(this.mfaBackupCodes);
            return JSON.parse(decrypted) as string[];
        } catch {
            return [];
        }
    }

    // Set backup codes (encrypted)
    setBackupCodes(codes: string[]): void {
        const encrypted = encryptField(JSON.stringify(codes));
        this.mfaBackupCodes = encrypted;
    }

    // Remove a used backup code
    async useBackupCode(code: string): Promise<boolean> {
        const codes = this.getBackupCodes();
        const index = codes.indexOf(code);
        if (index === -1) return false;

        codes.splice(index, 1);
        this.setBackupCodes(codes);
        await this.save();
        return true;
    }

    // Increment failed login attempts
    async incrementFailedAttempts(): Promise<void> {
        this.failedLoginAttempts = (this.failedLoginAttempts ?? 0) + 1;
        this.lastFailedLoginAt = new Date();

        // Lock account after max attempts
        if (this.failedLoginAttempts >= config.security.maxLoginAttempts) {
            this.lockedUntil = new Date(Date.now() + config.security.lockoutDurationMs);
            this.status = UserStatus.LOCKED;
        }

        await this.save();
    }

    // Reset failed login attempts on successful login
    async resetFailedAttempts(): Promise<void> {
        this.failedLoginAttempts = 0;
        this.lastFailedLoginAt = null;
        this.lockedUntil = null;
        if (this.status === UserStatus.LOCKED) {
            this.status = UserStatus.ACTIVE;
        }
        await this.save();
    }

    // Update last login info
    async recordLogin(ip: string, deviceId: string): Promise<void> {
        this.lastLoginAt = new Date();
        this.lastLoginIp = ip;
        this.lastLoginDeviceId = deviceId;
        await this.save();
    }
}

// Model initialization
User.init(
    {
        id: {
            type: DataTypes.UUID,
            defaultValue: DataTypes.UUIDV4,
            primaryKey: true,
        },
        email: {
            type: DataTypes.STRING(255),
            allowNull: false,
            unique: true,
            validate: {
                isEmail: true,
            },
            set(value: string) {
                // Store email in lowercase
                this.setDataValue('email', value.toLowerCase().trim());
            },
        },
        passwordHash: {
            type: DataTypes.STRING(255),
            allowNull: false,
        },
        passwordChangedAt: {
            type: DataTypes.DATE,
            allowNull: false,
            defaultValue: DataTypes.NOW,
        },
        passwordExpiryAt: {
            type: DataTypes.DATE,
            allowNull: false,
            defaultValue: () => {
                const expiry = new Date();
                expiry.setDate(expiry.getDate() + config.security.passwordExpiryDays);
                return expiry;
            },
        },
        status: {
            type: DataTypes.ENUM(...Object.values(UserStatus)),
            allowNull: false,
            defaultValue: UserStatus.PENDING_VERIFICATION,
        },
        failedLoginAttempts: {
            type: DataTypes.INTEGER,
            allowNull: false,
            defaultValue: 0,
        },
        lockedUntil: {
            type: DataTypes.DATE,
            allowNull: true,
        },
        lastFailedLoginAt: {
            type: DataTypes.DATE,
            allowNull: true,
        },
        emailVerified: {
            type: DataTypes.BOOLEAN,
            allowNull: false,
            defaultValue: false,
        },
        emailVerificationToken: {
            type: DataTypes.STRING(255),
            allowNull: true,
        },
        emailVerificationExpiry: {
            type: DataTypes.DATE,
            allowNull: true,
        },
        kycStatus: {
            type: DataTypes.ENUM(...Object.values(KycStatus)),
            allowNull: false,
            defaultValue: KycStatus.NOT_STARTED,
        },
        kycVerifiedAt: {
            type: DataTypes.DATE,
            allowNull: true,
        },
        kycDocumentId: {
            type: DataTypes.STRING(255),
            allowNull: true,
        },
        mfaEnabled: {
            type: DataTypes.BOOLEAN,
            allowNull: false,
            defaultValue: false,
        },
        mfaSecret: {
            type: DataTypes.TEXT, // Encrypted
            allowNull: true,
        },
        mfaBackupCodes: {
            type: DataTypes.TEXT, // Encrypted JSON array
            allowNull: true,
        },
        lastLoginAt: {
            type: DataTypes.DATE,
            allowNull: true,
        },
        lastLoginIp: {
            type: DataTypes.STRING(45), // IPv6 max length
            allowNull: true,
        },
        lastLoginDeviceId: {
            type: DataTypes.UUID,
            allowNull: true,
        },
        createdAt: {
            type: DataTypes.DATE,
            allowNull: false,
            defaultValue: DataTypes.NOW,
        },
        updatedAt: {
            type: DataTypes.DATE,
            allowNull: false,
            defaultValue: DataTypes.NOW,
        },
        deletedAt: {
            type: DataTypes.DATE,
            allowNull: true,
        },
    },
    {
        sequelize,
        tableName: 'users',
        modelName: 'User',
        timestamps: true,
        paranoid: true, // Soft deletes
        indexes: [
            {
                unique: true,
                fields: ['email'],
                where: { deleted_at: null },
            },
            {
                fields: ['status'],
            },
            {
                fields: ['kyc_status'],
            },
            {
                fields: ['last_login_at'],
            },
        ],
    }
);
