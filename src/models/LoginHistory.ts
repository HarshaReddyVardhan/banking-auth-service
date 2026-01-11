import {
    Model,
    DataTypes,
    InferAttributes,
    InferCreationAttributes,
    CreationOptional,
    ForeignKey,
} from 'sequelize';
import { sequelize } from './index';

// Login result enum
export enum LoginResult {
    SUCCESS = 'SUCCESS',
    FAILED_INVALID_PASSWORD = 'FAILED_INVALID_PASSWORD',
    FAILED_USER_NOT_FOUND = 'FAILED_USER_NOT_FOUND',
    FAILED_ACCOUNT_LOCKED = 'FAILED_ACCOUNT_LOCKED',
    FAILED_EMAIL_NOT_VERIFIED = 'FAILED_EMAIL_NOT_VERIFIED',
    FAILED_MFA_REQUIRED = 'FAILED_MFA_REQUIRED',
    FAILED_MFA_INVALID = 'FAILED_MFA_INVALID',
    FAILED_PASSWORD_EXPIRED = 'FAILED_PASSWORD_EXPIRED',
    FAILED_RATE_LIMITED = 'FAILED_RATE_LIMITED',
    FAILED_SUSPICIOUS_ACTIVITY = 'FAILED_SUSPICIOUS_ACTIVITY',
    LOGOUT = 'LOGOUT',
    SESSION_EXPIRED = 'SESSION_EXPIRED',
    SESSION_REVOKED = 'SESSION_REVOKED',
}

export class LoginHistory extends Model<
    InferAttributes<LoginHistory>,
    InferCreationAttributes<LoginHistory>
> {
    declare id: CreationOptional<string>;
    declare userId: ForeignKey<string> | null;
    declare email: string; // Store email even if user doesn't exist (for failed attempts)
    declare ipAddress: string;
    declare userAgent: string;
    declare deviceId: CreationOptional<string | null>;
    declare deviceFingerprint: CreationOptional<string | null>;
    declare loginResult: LoginResult;
    declare failureReason: CreationOptional<string | null>;

    // Geolocation data
    declare country: CreationOptional<string | null>;
    declare city: CreationOptional<string | null>;
    declare latitude: CreationOptional<number | null>;
    declare longitude: CreationOptional<number | null>;

    // Anomaly detection flags
    declare isAnomaly: CreationOptional<boolean>;
    declare anomalyReasons: CreationOptional<string | null>; // JSON array

    // Session info
    declare sessionId: CreationOptional<string | null>;

    declare createdAt: CreationOptional<Date>;
}

LoginHistory.init(
    {
        id: {
            type: DataTypes.UUID,
            defaultValue: DataTypes.UUIDV4,
            primaryKey: true,
        },
        userId: {
            type: DataTypes.UUID,
            allowNull: true, // Null for failed attempts with unknown user
            references: {
                model: 'users',
                key: 'id',
            },
        },
        email: {
            type: DataTypes.STRING(255),
            allowNull: false,
        },
        ipAddress: {
            type: DataTypes.STRING(45), // IPv6 max
            allowNull: false,
        },
        userAgent: {
            type: DataTypes.TEXT,
            allowNull: false,
        },
        deviceId: {
            type: DataTypes.UUID,
            allowNull: true,
        },
        deviceFingerprint: {
            type: DataTypes.STRING(255),
            allowNull: true,
        },
        loginResult: {
            type: DataTypes.ENUM(...Object.values(LoginResult)),
            allowNull: false,
        },
        failureReason: {
            type: DataTypes.TEXT,
            allowNull: true,
        },
        country: {
            type: DataTypes.STRING(100),
            allowNull: true,
        },
        city: {
            type: DataTypes.STRING(100),
            allowNull: true,
        },
        latitude: {
            type: DataTypes.DECIMAL(10, 8),
            allowNull: true,
        },
        longitude: {
            type: DataTypes.DECIMAL(11, 8),
            allowNull: true,
        },
        isAnomaly: {
            type: DataTypes.BOOLEAN,
            allowNull: false,
            defaultValue: false,
        },
        anomalyReasons: {
            type: DataTypes.TEXT, // JSON array of reasons
            allowNull: true,
        },
        sessionId: {
            type: DataTypes.UUID,
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
        tableName: 'login_history',
        modelName: 'LoginHistory',
        timestamps: false, // Only createdAt, no updates
        indexes: [
            {
                fields: ['user_id'],
            },
            {
                fields: ['email'],
            },
            {
                fields: ['ip_address'],
            },
            {
                fields: ['login_result'],
            },
            {
                fields: ['created_at'],
            },
            {
                fields: ['is_anomaly'],
            },
            {
                // Composite index for user login pattern analysis
                fields: ['user_id', 'created_at', 'login_result'],
            },
        ],
    }
);
