import {
    Model,
    DataTypes,
    InferAttributes,
    InferCreationAttributes,
    CreationOptional,
} from 'sequelize';
import { sequelize } from './index';

/**
 * Security Event Severity Levels
 */
export enum SecurityEventSeverity {
    LOW = 'LOW',
    MEDIUM = 'MEDIUM',
    HIGH = 'HIGH',
    CRITICAL = 'CRITICAL',
}

/**
 * Security Event Categories
 */
export enum SecurityEventCategory {
    AUTHENTICATION = 'AUTHENTICATION',
    AUTHORIZATION = 'AUTHORIZATION',
    TOKEN = 'TOKEN',
    SESSION = 'SESSION',
    ANOMALY = 'ANOMALY',
    RATE_LIMIT = 'RATE_LIMIT',
    DATA_ACCESS = 'DATA_ACCESS',
    CONFIGURATION = 'CONFIGURATION',
}

/**
 * Security Event - Centralized security event logging
 */
export class SecurityEvent extends Model<
    InferAttributes<SecurityEvent>,
    InferCreationAttributes<SecurityEvent>
> {
    declare id: CreationOptional<string>;
    declare category: SecurityEventCategory;
    declare severity: SecurityEventSeverity;
    declare eventType: string;
    declare description: string;
    declare userId: string | null;
    declare ipAddress: string;
    declare userAgent: string | null;
    declare sessionId: string | null;
    declare deviceId: string | null;
    declare metadata: CreationOptional<string | null>; // JSON
    declare resolved: CreationOptional<boolean>;
    declare resolvedAt: CreationOptional<Date | null>;
    declare resolvedBy: CreationOptional<string | null>;
    declare createdAt: CreationOptional<Date>;

    /**
     * Log a security event
     */
    static async log(params: {
        category: SecurityEventCategory;
        severity: SecurityEventSeverity;
        eventType: string;
        description: string;
        userId?: string | null;
        ipAddress: string;
        userAgent?: string | null;
        sessionId?: string | null;
        deviceId?: string | null;
        metadata?: Record<string, unknown>;
    }): Promise<SecurityEvent> {
        return SecurityEvent.create({
            category: params.category,
            severity: params.severity,
            eventType: params.eventType,
            description: params.description,
            userId: params.userId ?? null,
            ipAddress: params.ipAddress,
            userAgent: params.userAgent ?? null,
            sessionId: params.sessionId ?? null,
            deviceId: params.deviceId ?? null,
            metadata: params.metadata ? JSON.stringify(params.metadata) : null,
        });
    }

    /**
     * Get unresolved critical events
     */
    static async getUnresolvedCritical(): Promise<SecurityEvent[]> {
        return SecurityEvent.findAll({
            where: {
                severity: SecurityEventSeverity.CRITICAL,
                resolved: false,
            },
            order: [['createdAt', 'DESC']],
        });
    }
}

SecurityEvent.init(
    {
        id: {
            type: DataTypes.UUID,
            defaultValue: DataTypes.UUIDV4,
            primaryKey: true,
        },
        category: {
            type: DataTypes.ENUM(...Object.values(SecurityEventCategory)),
            allowNull: false,
        },
        severity: {
            type: DataTypes.ENUM(...Object.values(SecurityEventSeverity)),
            allowNull: false,
        },
        eventType: {
            type: DataTypes.STRING(100),
            allowNull: false,
        },
        description: {
            type: DataTypes.TEXT,
            allowNull: false,
        },
        userId: {
            type: DataTypes.UUID,
            allowNull: true,
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
        deviceId: {
            type: DataTypes.UUID,
            allowNull: true,
        },
        metadata: {
            type: DataTypes.TEXT,
            allowNull: true,
        },
        resolved: {
            type: DataTypes.BOOLEAN,
            allowNull: false,
            defaultValue: false,
        },
        resolvedAt: {
            type: DataTypes.DATE,
            allowNull: true,
        },
        resolvedBy: {
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
        tableName: 'security_events',
        modelName: 'SecurityEvent',
        timestamps: false,
        indexes: [
            { fields: ['category'] },
            { fields: ['severity'] },
            { fields: ['event_type'] },
            { fields: ['user_id'] },
            { fields: ['created_at'] },
            { fields: ['resolved'] },
            { fields: ['severity', 'resolved', 'created_at'] },
        ],
    }
);
