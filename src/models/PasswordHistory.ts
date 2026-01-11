import {
    Model,
    DataTypes,
    InferAttributes,
    InferCreationAttributes,
    CreationOptional,
    ForeignKey,
} from 'sequelize';
import { sequelize } from './index';

// PCI-DSS requires password history to prevent reuse
export class PasswordHistory extends Model<
    InferAttributes<PasswordHistory>,
    InferCreationAttributes<PasswordHistory>
> {
    declare id: CreationOptional<string>;
    declare userId: ForeignKey<string>;
    declare passwordHash: string;
    declare createdAt: CreationOptional<Date>;
}

PasswordHistory.init(
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
        passwordHash: {
            type: DataTypes.STRING(255),
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
        tableName: 'password_history',
        modelName: 'PasswordHistory',
        timestamps: false,
        indexes: [
            {
                fields: ['user_id'],
            },
            {
                fields: ['created_at'],
            },
            {
                // For efficient lookup of recent passwords
                fields: ['user_id', 'created_at'],
            },
        ],
    }
);
