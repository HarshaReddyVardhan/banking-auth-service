import {
    Model,
    DataTypes,
    InferAttributes,
    InferCreationAttributes,
    CreationOptional,
    ForeignKey,
} from 'sequelize';
import { sequelize } from './index';
import crypto from 'crypto';

// Refresh token for rotation tracking and theft detection
export class RefreshToken extends Model<
    InferAttributes<RefreshToken>,
    InferCreationAttributes<RefreshToken>
> {
    declare id: CreationOptional<string>;
    declare userId: ForeignKey<string>;

    // Token tracking (for rotation)
    declare familyId: string; // Groups tokens in same refresh chain
    declare tokenHash: string; // SHA-256 of current token
    declare parentTokenHash: CreationOptional<string | null>; // Previous token in chain

    // Session binding
    declare sessionId: string;
    declare deviceId: CreationOptional<string | null>;

    // Usage tracking
    declare usedAt: CreationOptional<Date | null>; // Token reuse detection
    declare expiresAt: Date;

    // Revocation
    declare revokedAt: CreationOptional<Date | null>;
    declare revokedReason: CreationOptional<string | null>;

    // Metadata
    declare issuedIp: string;
    declare issuedUserAgent: string;

    declare createdAt: CreationOptional<Date>;

    // Static method to hash a token
    static hashToken(token: string): string {
        return crypto.createHash('sha256').update(token).digest('hex');
    }

    // Generate a new family ID for fresh login
    static generateFamilyId(): string {
        return crypto.randomUUID();
    }

    // Check if token is expired
    isExpired(): boolean {
        return new Date() > this.expiresAt;
    }

    // Check if token is revoked
    isRevoked(): boolean {
        return this.revokedAt !== null;
    }

    // Check if token was already used (reuse = theft)
    wasUsed(): boolean {
        return this.usedAt !== null;
    }

    // Check if token is valid for use
    isValid(): boolean {
        return !this.isExpired() && !this.isRevoked() && !this.wasUsed();
    }

    // Mark token as used (before rotating)
    async markAsUsed(): Promise<void> {
        this.usedAt = new Date();
        await this.save();
    }

    // Revoke token
    async revoke(reason: string): Promise<void> {
        this.revokedAt = new Date();
        this.revokedReason = reason;
        await this.save();
    }
}

RefreshToken.init(
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
        familyId: {
            type: DataTypes.UUID,
            allowNull: false,
        },
        tokenHash: {
            type: DataTypes.STRING(64), // SHA-256
            allowNull: false,
            unique: true,
        },
        parentTokenHash: {
            type: DataTypes.STRING(64),
            allowNull: true, // Null for first token in family
        },
        sessionId: {
            type: DataTypes.UUID,
            allowNull: false,
        },
        deviceId: {
            type: DataTypes.UUID,
            allowNull: true,
        },
        usedAt: {
            type: DataTypes.DATE,
            allowNull: true,
        },
        expiresAt: {
            type: DataTypes.DATE,
            allowNull: false,
        },
        revokedAt: {
            type: DataTypes.DATE,
            allowNull: true,
        },
        revokedReason: {
            type: DataTypes.STRING(255),
            allowNull: true,
        },
        issuedIp: {
            type: DataTypes.STRING(45),
            allowNull: false,
        },
        issuedUserAgent: {
            type: DataTypes.TEXT,
            allowNull: false,
        },
        createdAt: {
            type: DataTypes.DATE,
            allowNull: false,
            defaultValue: DataTypes.NOW,
        },
    },
    {
        sequelize,
        tableName: 'refresh_tokens',
        modelName: 'RefreshToken',
        timestamps: false,
        indexes: [
            {
                fields: ['user_id'],
            },
            {
                unique: true,
                fields: ['token_hash'],
            },
            {
                fields: ['family_id'],
            },
            {
                fields: ['session_id'],
            },
            {
                fields: ['expires_at'],
            },
            {
                fields: ['revoked_at'],
            },
            {
                // For token theft detection
                fields: ['family_id', 'used_at'],
            },
        ],
    }
);
