import {
    Model,
    DataTypes,
    InferAttributes,
    InferCreationAttributes,
    CreationOptional,
} from 'sequelize';
import { sequelize } from './index';
import crypto from 'crypto';
import { config } from '../config/config';
import CryptoJS from 'crypto-js';

/**
 * Audit event types
 */
export enum AuditEventType {
    // Authentication
    USER_REGISTERED = 'USER_REGISTERED',
    USER_LOGIN_SUCCESS = 'USER_LOGIN_SUCCESS',
    USER_LOGIN_FAILED = 'USER_LOGIN_FAILED',
    USER_LOGOUT = 'USER_LOGOUT',
    USER_LOCKED = 'USER_LOCKED',
    USER_UNLOCKED = 'USER_UNLOCKED',

    // Password
    PASSWORD_CHANGED = 'PASSWORD_CHANGED',
    PASSWORD_RESET_REQUESTED = 'PASSWORD_RESET_REQUESTED',
    PASSWORD_RESET_COMPLETED = 'PASSWORD_RESET_COMPLETED',
    PASSWORD_EXPIRED = 'PASSWORD_EXPIRED',

    // Email
    EMAIL_VERIFICATION_SENT = 'EMAIL_VERIFICATION_SENT',
    EMAIL_VERIFIED = 'EMAIL_VERIFIED',

    // MFA
    MFA_ENABLED = 'MFA_ENABLED',
    MFA_DISABLED = 'MFA_DISABLED',
    MFA_VERIFIED = 'MFA_VERIFIED',
    MFA_FAILED = 'MFA_FAILED',
    BACKUP_CODE_USED = 'BACKUP_CODE_USED',

    // Sessions
    SESSION_CREATED = 'SESSION_CREATED',
    SESSION_REVOKED = 'SESSION_REVOKED',
    SESSION_EXPIRED = 'SESSION_EXPIRED',
    ALL_SESSIONS_REVOKED = 'ALL_SESSIONS_REVOKED',

    // Tokens
    TOKEN_REFRESH = 'TOKEN_REFRESH',
    TOKEN_REVOKED = 'TOKEN_REVOKED',
    TOKEN_THEFT_DETECTED = 'TOKEN_THEFT_DETECTED',

    // Devices
    DEVICE_REGISTERED = 'DEVICE_REGISTERED',
    DEVICE_TRUSTED = 'DEVICE_TRUSTED',
    DEVICE_REVOKED = 'DEVICE_REVOKED',
    DEVICE_BLOCKED = 'DEVICE_BLOCKED',

    // Security
    ANOMALY_DETECTED = 'ANOMALY_DETECTED',
    RATE_LIMIT_EXCEEDED = 'RATE_LIMIT_EXCEEDED',
    SUSPICIOUS_ACTIVITY = 'SUSPICIOUS_ACTIVITY',

    // Admin
    USER_SUSPENDED = 'USER_SUSPENDED',
    USER_REACTIVATED = 'USER_REACTIVATED',
    SETTINGS_CHANGED = 'SETTINGS_CHANGED',
}

/**
 * Immutable Audit Log - PCI-DSS 10.1 compliant
 * Write-once design with hash chain for tamper detection
 */
export class AuditLog extends Model<
    InferAttributes<AuditLog>,
    InferCreationAttributes<AuditLog>
> {
    declare id: CreationOptional<string>;
    declare eventType: AuditEventType;
    declare userId: string | null;
    declare actorId: string | null; // Who performed the action (may differ from userId)
    declare resourceType: string;
    declare resourceId: string | null;
    declare encryptedPayload: string; // AES-256 encrypted JSON
    declare ipAddress: string;
    declare userAgent: string | null;
    declare sessionId: string | null;
    declare previousHash: string | null; // Hash chain link
    declare hash: string; // SHA-256 of record
    declare severity: CreationOptional<'INFO' | 'WARNING' | 'CRITICAL'>;
    declare createdAt: CreationOptional<Date>;

    /**
     * Encrypt payload for storage
     */
    static encryptPayload(payload: Record<string, unknown>): string {
        const json = JSON.stringify(payload);
        return CryptoJS.AES.encrypt(json, config.security.fieldEncryptionKey).toString();
    }

    /**
     * Decrypt payload (for authorized access only)
     */
    static decryptPayload(encrypted: string): Record<string, unknown> {
        const bytes = CryptoJS.AES.decrypt(encrypted, config.security.fieldEncryptionKey);
        return JSON.parse(bytes.toString(CryptoJS.enc.Utf8));
    }

    /**
     * Calculate hash for tamper detection
     */
    static calculateHash(
        eventType: string,
        userId: string | null,
        resourceType: string,
        resourceId: string | null,
        encryptedPayload: string,
        ipAddress: string,
        previousHash: string | null,
        timestamp: Date
    ): string {
        const data = [
            eventType,
            userId ?? '',
            resourceType,
            resourceId ?? '',
            encryptedPayload,
            ipAddress,
            previousHash ?? '',
            timestamp.toISOString(),
        ].join('|');

        return crypto.createHash('sha256').update(data).digest('hex');
    }

    /**
     * Create an immutable audit log entry
     */
    static async log(params: {
        eventType: AuditEventType;
        userId?: string | null;
        actorId?: string | null;
        resourceType: string;
        resourceId?: string | null;
        payload: Record<string, unknown>;
        ipAddress: string;
        userAgent?: string | null;
        sessionId?: string | null;
        severity?: 'INFO' | 'WARNING' | 'CRITICAL';
    }): Promise<AuditLog> {
        // Get previous hash for chain
        const lastEntry = await AuditLog.findOne({
            order: [['createdAt', 'DESC']],
            attributes: ['hash'],
        });
        const previousHash = lastEntry?.hash ?? null;

        // Encrypt payload
        const encryptedPayload = AuditLog.encryptPayload(params.payload);

        // Calculate hash
        const timestamp = new Date();
        const hash = AuditLog.calculateHash(
            params.eventType,
            params.userId ?? null,
            params.resourceType,
            params.resourceId ?? null,
            encryptedPayload,
            params.ipAddress,
            previousHash,
            timestamp
        );

        // Create entry (immutable - no updates allowed)
        return AuditLog.create({
            eventType: params.eventType,
            userId: params.userId ?? null,
            actorId: params.actorId ?? null,
            resourceType: params.resourceType,
            resourceId: params.resourceId ?? null,
            encryptedPayload,
            ipAddress: params.ipAddress,
            userAgent: params.userAgent ?? null,
            sessionId: params.sessionId ?? null,
            previousHash,
            hash,
            severity: params.severity ?? 'INFO',
            createdAt: timestamp,
        });
    }

    /**
     * Verify hash chain integrity
     */
    static async verifyIntegrity(startId?: string, limit: number = 1000): Promise<{
        valid: boolean;
        invalidEntries: string[];
        checkedCount: number;
    }> {
        const where = startId ? { id: { $gt: startId } } : {};
        const entries = await AuditLog.findAll({
            where,
            order: [['createdAt', 'ASC']],
            limit,
        });

        const invalidEntries: string[] = [];
        let prevHash: string | null = null;

        for (const entry of entries) {
            // Recalculate hash
            const expectedHash = AuditLog.calculateHash(
                entry.eventType,
                entry.userId,
                entry.resourceType,
                entry.resourceId,
                entry.encryptedPayload,
                entry.ipAddress,
                entry.previousHash,
                entry.createdAt
            );

            if (entry.hash !== expectedHash) {
                invalidEntries.push(entry.id);
            }

            if (prevHash !== null && entry.previousHash !== prevHash) {
                invalidEntries.push(entry.id);
            }

            prevHash = entry.hash;
        }

        return {
            valid: invalidEntries.length === 0,
            invalidEntries,
            checkedCount: entries.length,
        };
    }
}

AuditLog.init(
    {
        id: {
            type: DataTypes.UUID,
            defaultValue: DataTypes.UUIDV4,
            primaryKey: true,
        },
        eventType: {
            type: DataTypes.STRING(50),
            allowNull: false,
        },
        userId: {
            type: DataTypes.UUID,
            allowNull: true,
        },
        actorId: {
            type: DataTypes.UUID,
            allowNull: true,
        },
        resourceType: {
            type: DataTypes.STRING(50),
            allowNull: false,
        },
        resourceId: {
            type: DataTypes.STRING(255),
            allowNull: true,
        },
        encryptedPayload: {
            type: DataTypes.TEXT,
            allowNull: false,
        },
        ipAddress: {
            type: DataTypes.STRING(45),
            allowNull: false,
        },
        userAgent: {
            type: DataTypes.TEXT,
            allowNull: true,
        },
        sessionId: {
            type: DataTypes.UUID,
            allowNull: true,
        },
        previousHash: {
            type: DataTypes.STRING(64),
            allowNull: true,
        },
        hash: {
            type: DataTypes.STRING(64),
            allowNull: false,
        },
        severity: {
            type: DataTypes.ENUM('INFO', 'WARNING', 'CRITICAL'),
            allowNull: false,
            defaultValue: 'INFO',
        },
        createdAt: {
            type: DataTypes.DATE,
            allowNull: false,
            defaultValue: DataTypes.NOW,
        },
    },
    {
        sequelize,
        tableName: 'audit_logs',
        modelName: 'AuditLog',
        timestamps: false, // Only createdAt, manually set
        // CRITICAL: Disable updates and deletes
        hooks: {
            beforeUpdate: () => {
                throw new Error('AuditLog entries are immutable and cannot be updated');
            },
            beforeDestroy: () => {
                throw new Error('AuditLog entries are immutable and cannot be deleted');
            },
        },
        indexes: [
            { fields: ['event_type'] },
            { fields: ['user_id'] },
            { fields: ['resource_type', 'resource_id'] },
            { fields: ['created_at'] },
            { fields: ['severity'] },
            { fields: ['session_id'] },
            // Composite for date range queries
            { fields: ['event_type', 'created_at'] },
            { fields: ['user_id', 'created_at'] },
        ],
    }
);
