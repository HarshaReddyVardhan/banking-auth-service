import express from 'express';
import helmet from 'helmet';
import cors from 'cors';
import compression from 'compression';
import { v4 as uuidv4 } from 'uuid';
import { config } from './config/config';
import { initializeDatabase, closeDatabase } from './models/index';
import authRoutes from './routes/authRoutes';
import { errorHandler, notFoundHandler } from './middleware/errorHandler';
import { logger, createRequestLogData } from './middleware/requestLogger';
import { auditLoggingMiddleware } from './middleware/auditLoggingMiddleware';
import { eventPublisher } from './kafka/EventPublisher';
import { sessionManager } from './services/SessionManager';
import { rateLimiter } from './services/RateLimiter';
import { tokenBlacklist } from './services/TokenBlacklist';

// Create Express app
const app = express();

// Trust proxy for X-Forwarded-* headers (required for rate limiting behind load balancer)
app.set('trust proxy', 1);

// ==================== SECURITY MIDDLEWARE ====================

// Helmet for security headers
app.use(helmet({
    contentSecurityPolicy: {
        directives: {
            defaultSrc: ["'self'"],
            scriptSrc: ["'self'"],
            styleSrc: ["'self'"],
            imgSrc: ["'self'", 'data:'],
            frameAncestors: ["'none'"], // Clickjacking protection
            formAction: ["'self'"], // Form submission protection
            upgradeInsecureRequests: [], // Upgrade HTTP to HTTPS
        },
    },
    hsts: {
        maxAge: 31536000,
        includeSubDomains: true,
        preload: true,
    },
    referrerPolicy: { policy: 'strict-origin-when-cross-origin' },
    noSniff: true, // X-Content-Type-Options: nosniff
    xssFilter: true, // X-XSS-Protection (legacy browsers)
    dnsPrefetchControl: { allow: false }, // X-DNS-Prefetch-Control: off
    permittedCrossDomainPolicies: { permittedPolicies: 'none' }, // X-Permitted-Cross-Domain-Policies
    frameguard: { action: 'deny' }, // X-Frame-Options: DENY
    originAgentCluster: true, // Origin-Agent-Cluster header
}));

// CORS configuration
app.use(cors({
    origin: config.isProduction()
        ? process.env['ALLOWED_ORIGINS']?.split(',') ?? []
        : '*',
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization', 'X-Correlation-ID'],
    credentials: true,
    maxAge: 86400, // 24 hours
}));

// Compression
app.use(compression());

// Body parsing
app.use(express.json({ limit: '10kb' })); // Limit body size
app.use(express.urlencoded({ extended: true, limit: '10kb' }));

// ==================== INPUT SANITIZATION ====================
// Import inline to avoid circular dependency issues
import { sanitizationMiddleware } from './middleware/sanitizationMiddleware';
import { securityHeadersMiddleware } from './middleware/securityHeadersMiddleware';

// Sanitize all incoming requests (XSS/Injection prevention)
app.use(sanitizationMiddleware);

// Additional security headers (cache control, permissions policy, CORP, COOP, COEP)
app.use(securityHeadersMiddleware);

// ==================== REQUEST LOGGING ====================

// Add correlation ID to each request
app.use((req, _res, next) => {
    const correlationId = req.headers['x-correlation-id'] as string ?? uuidv4();
    (req as { correlationId?: string }).correlationId = correlationId;
    next();
});

// Request logging
app.use((req, res, next) => {
    const startTime = Date.now();
    const correlationId = (req as { correlationId?: string }).correlationId ?? '';

    res.on('finish', () => {
        const responseTime = Date.now() - startTime;
        const logData = createRequestLogData(
            req.method,
            req.originalUrl,
            res.statusCode,
            responseTime,
            req.ip ?? '0.0.0.0',
            correlationId
        );

        // Log at appropriate level based on status
        if (res.statusCode >= 500) {
            logger.error('Request completed', logData);
        } else if (res.statusCode >= 400) {
            logger.warn('Request completed', logData);
        } else {
            logger.info('Request completed', logData);
        }
    });

    next();
});

// Audit logging middleware (PCI-DSS compliance)
app.use(auditLoggingMiddleware);

// ==================== ROUTES ====================

// Auth routes
app.use('/auth', authRoutes);

// Health check (also accessible without /auth prefix)
app.get('/health', (_req, res) => {
    res.json({
        status: 'healthy',
        service: 'banking-auth-service',
        timestamp: new Date().toISOString(),
        version: process.env['npm_package_version'] ?? '1.0.0',
    });
});

// ==================== ERROR HANDLING ====================

// 404 handler
app.use(notFoundHandler);

// Global error handler
app.use(errorHandler);

// ==================== GRACEFUL SHUTDOWN ====================

async function shutdown(signal: string): Promise<void> {
    logger.info(`Received ${signal}. Starting graceful shutdown...`);

    // Stop accepting new connections
    server.close(async () => {
        logger.info('HTTP server closed');

        try {
            // Close database connection
            await closeDatabase();

            // Close Redis connections
            await sessionManager.close();
            await rateLimiter.close();
            await tokenBlacklist.close();

            // Close Kafka producer
            await eventPublisher.disconnect();

            logger.info('Graceful shutdown complete');
            process.exit(0);
        } catch (error) {
            logger.error('Error during shutdown', { error });
            process.exit(1);
        }
    });

    // Force shutdown after 30 seconds
    setTimeout(() => {
        logger.error('Forced shutdown after timeout');
        process.exit(1);
    }, 30000);
}

// ==================== STARTUP ====================

let server: ReturnType<typeof app.listen>;

async function start(): Promise<void> {
    try {
        // Initialize database
        await initializeDatabase();

        // Connect to Kafka
        await eventPublisher.connect();

        // Start HTTP server
        server = app.listen(config.port, config.host, () => {
            logger.info(`Banking Auth Service started`, {
                port: config.port,
                host: config.host,
                environment: config.nodeEnv,
            });
        });

        // Handle graceful shutdown
        process.on('SIGTERM', () => shutdown('SIGTERM'));
        process.on('SIGINT', () => shutdown('SIGINT'));

        // Handle unhandled rejections
        process.on('unhandledRejection', (reason, promise) => {
            logger.error('Unhandled Rejection', { reason, promise });
        });

        // Handle uncaught exceptions
        process.on('uncaughtException', (error) => {
            logger.error('Uncaught Exception', { error });
            shutdown('uncaughtException');
        });

    } catch (error) {
        logger.error('Failed to start server', { error });
        process.exit(1);
    }
}

// Start the application
start();

export default app;
