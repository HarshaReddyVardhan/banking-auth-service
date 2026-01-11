import {
    Model,
    DataTypes,
    InferAttributes,
    InferCreationAttributes,
    CreationOptional,
    ForeignKey,
} from 'sequelize';
import { sequelize } from './index';

// Device type enum
export enum DeviceType {
    MOBILE = 'MOBILE',
    TABLET = 'TABLET',
    DESKTOP = 'DESKTOP',
    UNKNOWN = 'UNKNOWN',
}

// Device trust level
export enum DeviceTrustLevel {
    UNTRUSTED = 'UNTRUSTED',
    PENDING = 'PENDING',
    TRUSTED = 'TRUSTED',
    BLOCKED = 'BLOCKED',
}

export class Device extends Model<
    InferAttributes<Device>,
    InferCreationAttributes<Device>
> {
    declare id: CreationOptional<string>;
    declare userId: ForeignKey<string>;

    // Device identification
    declare fingerprint: string; // Unique device fingerprint hash
    declare deviceName: CreationOptional<string>;
    declare deviceType: CreationOptional<DeviceType>;

    // Browser/OS info
    declare browser: CreationOptional<string | null>;
    declare browserVersion: CreationOptional<string | null>;
    declare os: CreationOptional<string | null>;
    declare osVersion: CreationOptional<string | null>;

    // Trust status
    declare trustLevel: CreationOptional<DeviceTrustLevel>;
    declare trustScore: CreationOptional<number>; // 0-100
    declare trustedAt: CreationOptional<Date | null>;
    declare trustedByUserId: CreationOptional<string | null>; // User who trusted it

    // Activity tracking
    declare lastUsedAt: CreationOptional<Date>;
    declare lastUsedIp: CreationOptional<string | null>;
    declare loginCount: CreationOptional<number>;

    // Location (last known)
    declare lastCountry: CreationOptional<string | null>;
    declare lastCity: CreationOptional<string | null>;

    // Timestamps
    declare createdAt: CreationOptional<Date>;
    declare updatedAt: CreationOptional<Date>;
    declare revokedAt: CreationOptional<Date | null>;

    // Helper methods
    isTrusted(): boolean {
        return this.trustLevel === DeviceTrustLevel.TRUSTED && this.trustScore >= 80;
    }

    isBlocked(): boolean {
        return this.trustLevel === DeviceTrustLevel.BLOCKED;
    }

    isRevoked(): boolean {
        return this.revokedAt !== null;
    }
}

Device.init(
    {
        id: {
            type: DataTypes.UUID,
            defaultValue: DataTypes.UUIDV4,
            primaryKey: true,
        },
        userId: {
            type: DataTypes.UUID,
            allowNull: false,
            references: {
                model: 'users',
                key: 'id',
            },
        },
        fingerprint: {
            type: DataTypes.STRING(255),
            allowNull: false,
        },
        deviceName: {
            type: DataTypes.STRING(255),
            allowNull: true,
            defaultValue: 'Unknown Device',
        },
        deviceType: {
            type: DataTypes.ENUM(...Object.values(DeviceType)),
            allowNull: false,
            defaultValue: DeviceType.UNKNOWN,
        },
        browser: {
            type: DataTypes.STRING(100),
            allowNull: true,
        },
        browserVersion: {
            type: DataTypes.STRING(50),
            allowNull: true,
        },
        os: {
            type: DataTypes.STRING(100),
            allowNull: true,
        },
        osVersion: {
            type: DataTypes.STRING(50),
            allowNull: true,
        },
        trustLevel: {
            type: DataTypes.ENUM(...Object.values(DeviceTrustLevel)),
            allowNull: false,
            defaultValue: DeviceTrustLevel.UNTRUSTED,
        },
        trustScore: {
            type: DataTypes.INTEGER,
            allowNull: false,
            defaultValue: 0,
            validate: {
                min: 0,
                max: 100,
            },
        },
        trustedAt: {
            type: DataTypes.DATE,
            allowNull: true,
        },
        trustedByUserId: {
            type: DataTypes.UUID,
            allowNull: true,
        },
        lastUsedAt: {
            type: DataTypes.DATE,
            allowNull: false,
            defaultValue: DataTypes.NOW,
        },
        lastUsedIp: {
            type: DataTypes.STRING(45),
            allowNull: true,
        },
        loginCount: {
            type: DataTypes.INTEGER,
            allowNull: false,
            defaultValue: 1,
        },
        lastCountry: {
            type: DataTypes.STRING(100),
            allowNull: true,
        },
        lastCity: {
            type: DataTypes.STRING(100),
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
        revokedAt: {
            type: DataTypes.DATE,
            allowNull: true,
        },
    },
    {
        sequelize,
        tableName: 'devices',
        modelName: 'Device',
        timestamps: true,
        indexes: [
            {
                unique: true,
                fields: ['user_id', 'fingerprint'],
                where: { revoked_at: null },
            },
            {
                fields: ['user_id'],
            },
            {
                fields: ['fingerprint'],
            },
            {
                fields: ['trust_level'],
            },
            {
                fields: ['last_used_at'],
            },
        ],
    }
);
