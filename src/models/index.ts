import { Sequelize, Options } from 'sequelize';
import { config } from '../config/config';
import { logger } from '../middleware/requestLogger';

// Database connection options with security settings
const sequelizeOptions: Options = {
    host: config.database.host,
    port: config.database.port,
    dialect: 'postgres',
    logging: (msg) => logger.debug(msg),

    // Connection pool for high throughput
    pool: {
        min: config.database.pool.min,
        max: config.database.pool.max,
        acquire: config.database.pool.acquire,
        idle: config.database.pool.idle,
    },

    // SSL/TLS for production
    dialectOptions: config.database.ssl
        ? {
            ssl: {
                require: true,
                rejectUnauthorized: config.database.sslRejectUnauthorized,
            },
        }
        : {},

    // Additional security settings
    define: {
        timestamps: true,
        underscored: true, // Use snake_case for columns
        paranoid: true, // Soft deletes (deleted_at)
    },

    // Query timeout
    retry: {
        max: 3,
    },
};

// Create Sequelize instance
export const sequelize = new Sequelize(
    config.database.name,
    config.database.user,
    config.database.password,
    sequelizeOptions
);

// Database initialization
export async function initializeDatabase(): Promise<void> {
    try {
        // Test connection
        await sequelize.authenticate();
        logger.info('Database connection established successfully');

        // Sync models (only in development - use migrations in production)
        if (config.isDevelopment()) {
            await sequelize.sync({ alter: true });
            logger.info('Database models synchronized');
        }
    } catch (error) {
        logger.error('Unable to connect to database:', error);
        throw error;
    }
}

// Graceful shutdown
export async function closeDatabase(): Promise<void> {
    try {
        await sequelize.close();
        logger.info('Database connection closed');
    } catch (error) {
        logger.error('Error closing database connection:', error);
        throw error;
    }
}

// Export models
export { User } from './User';
export { LoginHistory } from './LoginHistory';
export { Device } from './Device';
export { PasswordResetToken } from './PasswordResetToken';
export { PasswordHistory } from './PasswordHistory';
export { RefreshToken } from './RefreshToken';
export { AuditLog, AuditEventType } from './AuditLog';
export { EmailVerificationOTP } from './EmailVerificationOTP';
export { SecurityEvent, SecurityEventSeverity, SecurityEventCategory } from './SecurityEvent';

