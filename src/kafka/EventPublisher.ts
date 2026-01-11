import { Kafka, Producer, Partitioners, CompressionTypes } from 'kafkajs';
import { config } from '../config/config';
import { logger } from '../middleware/requestLogger';

/**
 * Security event types
 */
export type SecurityEventType =
    | 'user.registered'
    | 'user.email.verified'
    | 'user.login.success'
    | 'user.login.failed'
    | 'user.locked'
    | 'user.password.changed'
    | 'user.password.reset_requested'
    | 'user.password.reset'
    | 'user.mfa.enabled'
    | 'user.mfa.disabled'
    | 'user.device.registered'
    | 'user.device.revoked'
    | 'session.created'
    | 'session.terminated'
    | 'jwt.key.rotated'
    | 'security.token_theft'
    | 'security.anomaly_detected'
    | 'security.account_compromised'
    | 'security.all_tokens_revoked';

/**
 * Base event structure
 */
interface SecurityEvent {
    eventType: SecurityEventType;
    timestamp: string;
    service: string;
    version: string;
    correlationId?: string;
    payload: Record<string, unknown>;
}

/**
 * Kafka Event Publisher for security events
 */
export class EventPublisher {
    private kafka: Kafka;
    private producer: Producer | null = null;
    private isConnected: boolean = false;
    private readonly serviceName = 'banking-auth-service';
    private readonly eventVersion = '1.0';

    constructor() {
        this.kafka = new Kafka({
            clientId: config.kafka.clientId,
            brokers: config.kafka.brokers,
            retry: {
                initialRetryTime: 100,
                retries: 5,
            },
        });
    }

    /**
     * Initialize and connect the producer
     */
    async connect(): Promise<void> {
        if (this.isConnected) return;

        try {
            this.producer = this.kafka.producer({
                createPartitioner: Partitioners.DefaultPartitioner,
                allowAutoTopicCreation: true,
                transactionTimeout: 30000,
            });

            await this.producer.connect();
            this.isConnected = true;
            logger.info('Kafka producer connected');
        } catch (error) {
            logger.error('Failed to connect Kafka producer', { error });
            // Don't throw - allow service to run without Kafka
        }
    }

    /**
     * Disconnect the producer
     */
    async disconnect(): Promise<void> {
        if (this.producer && this.isConnected) {
            await this.producer.disconnect();
            this.isConnected = false;
            logger.info('Kafka producer disconnected');
        }
    }

    /**
     * Publish a security event
     */
    async publish(
        eventType: SecurityEventType,
        payload: Record<string, unknown>,
        correlationId?: string
    ): Promise<void> {
        if (!this.producer || !this.isConnected) {
            // Log event locally if Kafka not available
            logger.info('Security event (Kafka offline)', {
                eventType,
                ...payload,
            });
            return;
        }

        const event: SecurityEvent = {
            eventType,
            timestamp: new Date().toISOString(),
            service: this.serviceName,
            version: this.eventVersion,
            correlationId,
            payload,
        };

        try {
            await this.producer.send({
                topic: config.kafka.securityTopic,
                compression: CompressionTypes.GZIP,
                messages: [
                    {
                        key: payload['userId'] as string | undefined ?? eventType,
                        value: JSON.stringify(event),
                        headers: {
                            'event-type': eventType,
                            'event-version': this.eventVersion,
                            'source-service': this.serviceName,
                        },
                    },
                ],
            });

            logger.debug('Security event published', { eventType, correlationId });
        } catch (error) {
            logger.error('Failed to publish security event', {
                eventType,
                error,
            });
            // Don't throw - log error and continue
        }
    }

    /**
     * Publish JWT key rotation event
     * This is critical for other services to update their key cache
     */
    async publishKeyRotation(
        newKeyId: string,
        oldKeyId: string,
        gracePeriodEnds: Date
    ): Promise<void> {
        await this.publish('jwt.key.rotated', {
            newKeyId,
            oldKeyId,
            gracePeriodEnds: gracePeriodEnds.toISOString(),
            action: 'KEY_ROTATION',
            priority: 'HIGH',
        });

        logger.info('JWT key rotation event published', {
            newKeyId,
            oldKeyId,
        });
    }

    /**
     * Publish security alert
     */
    async publishSecurityAlert(
        userId: string,
        alertType: 'token_theft' | 'anomaly_detected' | 'account_compromised',
        details: Record<string, unknown>
    ): Promise<void> {
        const eventType: SecurityEventType = `security.${alertType}` as SecurityEventType;

        await this.publish(eventType, {
            userId,
            alertType,
            severity: 'HIGH',
            ...details,
        });
    }
}

// Export singleton
export const eventPublisher = new EventPublisher();
