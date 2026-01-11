import { Transaction } from 'sequelize';
import { sequelize } from '../models/index';
import { logger } from '../middleware/requestLogger';

/**
 * Database Transaction Wrapper
 * Ensures atomic operations with proper rollback handling
 */

/**
 * Execute a function within a database transaction
 * Automatically commits on success, rolls back on error
 */
export async function withTransaction<T>(
    callback: (transaction: Transaction) => Promise<T>
): Promise<T> {
    const transaction = await sequelize.transaction();

    try {
        const result = await callback(transaction);
        await transaction.commit();
        return result;
    } catch (error) {
        await transaction.rollback();
        logger.error('Transaction rolled back', { error });
        throw error;
    }
}

/**
 * Execute multiple operations atomically
 */
export async function executeAtomic<T>(
    operations: Array<(transaction: Transaction) => Promise<unknown>>,
    finalResult: (transaction: Transaction) => Promise<T>
): Promise<T> {
    return withTransaction(async (transaction) => {
        for (const operation of operations) {
            await operation(transaction);
        }
        return finalResult(transaction);
    });
}

/**
 * Retry a transaction on deadlock/lock timeout
 */
export async function withTransactionRetry<T>(
    callback: (transaction: Transaction) => Promise<T>,
    maxRetries: number = 3,
    delayMs: number = 100
): Promise<T> {
    let lastError: Error | undefined;

    for (let attempt = 1; attempt <= maxRetries; attempt++) {
        try {
            return await withTransaction(callback);
        } catch (error) {
            lastError = error as Error;

            // Check if it's a retryable error (deadlock, lock timeout)
            const errorMessage = lastError.message.toLowerCase();
            const isRetryable =
                errorMessage.includes('deadlock') ||
                errorMessage.includes('lock wait timeout') ||
                errorMessage.includes('could not obtain lock');

            if (!isRetryable || attempt === maxRetries) {
                throw lastError;
            }

            logger.warn('Transaction retry due to lock conflict', {
                attempt,
                maxRetries,
                error: lastError.message,
            });

            // Exponential backoff
            await new Promise((resolve) => setTimeout(resolve, delayMs * attempt));
        }
    }

    throw lastError;
}

/**
 * Transaction options helper
 */
export function getTransactionOptions(transaction: Transaction) {
    return { transaction };
}
