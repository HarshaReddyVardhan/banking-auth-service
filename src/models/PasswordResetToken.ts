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

export class PasswordResetToken extends Model<
    InferAttributes<PasswordResetToken>,
    InferCreationAttributes<PasswordResetToken>
> {
    declare id: CreationOptional<string>;
    declare userId: ForeignKey<string>;
    declare tokenHash: string; // SHA-256 hash of the token
    declare expiresAt: Date;
    declare usedAt: CreationOptional<Date | null>;
    declare requestedIp: string;
    declare requestedUserAgent: string;
    declare createdAt: CreationOptional<Date>;

    // Static method to hash a token
    static hashToken(token: string): string {
        return crypto.createHash('sha256').update(token).digest('hex');
    }

    // Check if token is expired
    isExpired(): boolean {
        return new Date() > this.expiresAt;
    }

    // Check if token is already used
    isUsed(): boolean {
        return this.usedAt !== null;
    }

    // Check if token is valid (not expired, not used)
    isValid(): boolean {
        return !this.isExpired() && !this.isUsed();
    }

    // Mark token as used
    async markAsUsed(): Promise<void> {
        this.usedAt = new Date();
        await this.save();
    }
}

PasswordResetToken.init(
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
        tokenHash: {
            type: DataTypes.STRING(64), // SHA-256 produces 64 hex chars
            allowNull: false,
            unique: true,
        },
        expiresAt: {
            type: DataTypes.DATE,
            allowNull: false,
        },
        usedAt: {
            type: DataTypes.DATE,
            allowNull: true,
        },
        requestedIp: {
            type: DataTypes.STRING(45),
            allowNull: false,
        },
        requestedUserAgent: {
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
        tableName: 'password_reset_tokens',
        modelName: 'PasswordResetToken',
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
                fields: ['expires_at'],
            },
            {
                fields: ['created_at'],
            },
        ],
    }
);
