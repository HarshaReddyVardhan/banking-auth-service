import Joi from 'joi';
import { Request, Response, NextFunction } from 'express';

/**
 * Password validation rules (PCI-DSS compliant)
 */
const passwordSchema = Joi.string()
    .min(12)
    .max(128)
    .pattern(/[a-z]/, 'lowercase')
    .pattern(/[A-Z]/, 'uppercase')
    .pattern(/[0-9]/, 'number')
    .pattern(/[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?]/, 'special')
    .required()
    .messages({
        'string.min': 'Password must be at least 12 characters',
        'string.max': 'Password cannot exceed 128 characters',
        'string.pattern.name': 'Password must contain at least one {#name} character',
    });

/**
 * Email validation
 */
const emailSchema = Joi.string()
    .email()
    .max(255)
    .lowercase()
    .trim()
    .required();

/**
 * MFA token validation (6 digits or backup code format)
 */
const mfaTokenSchema = Joi.alternatives().try(
    Joi.string().pattern(/^\d{6}$/), // TOTP
    Joi.string().pattern(/^[A-Z0-9]{4}-[A-Z0-9]{4}$/i) // Backup code
);

/**
 * Validation schemas for all endpoints
 */
export const validationSchemas = {
    register: Joi.object({
        email: emailSchema,
        password: passwordSchema,
    }),

    login: Joi.object({
        email: emailSchema,
        password: Joi.string().required(),
        mfaToken: mfaTokenSchema.optional(),
        deviceFingerprint: Joi.object({
            userAgent: Joi.string().required(),
            screenResolution: Joi.string().optional(),
            timezone: Joi.string().optional(),
            language: Joi.string().optional(),
            platform: Joi.string().optional(),
            colorDepth: Joi.number().optional(),
            hardwareConcurrency: Joi.number().optional(),
            deviceMemory: Joi.number().optional(),
            canvas: Joi.string().optional(),
            webgl: Joi.string().optional(),
            audioContext: Joi.string().optional(),
        }).optional(),
    }),

    verifyEmail: Joi.object({
        token: Joi.string().hex().length(64).required(),
    }),

    resendVerification: Joi.object({
        email: emailSchema,
    }),

    forgotPassword: Joi.object({
        email: emailSchema,
    }),

    resetPassword: Joi.object({
        token: Joi.string().hex().length(64).required(),
        password: passwordSchema,
    }),

    changePassword: Joi.object({
        currentPassword: Joi.string().required(),
        newPassword: passwordSchema,
    }),

    refreshToken: Joi.object({
        refreshToken: Joi.string().required(),
    }),

    mfaSetup: Joi.object({}),

    mfaVerify: Joi.object({
        secret: Joi.string().required(),
        token: Joi.string().pattern(/^\d{6}$/).required(),
        backupCodes: Joi.array().items(Joi.string()).min(10).required(),
    }),

    mfaToken: Joi.object({
        token: mfaTokenSchema.required(),
    }),

    revokeSession: Joi.object({
        sessionId: Joi.string().uuid().required(),
    }),

    revokeDevice: Joi.object({
        deviceId: Joi.string().uuid().required(),
    }),

    trustDevice: Joi.object({
        deviceId: Joi.string().uuid().required(),
    }),
};

/**
 * Validation middleware factory
 */
export function validate(schemaName: keyof typeof validationSchemas) {
    return (req: Request, res: Response, next: NextFunction): void => {
        const schema = validationSchemas[schemaName];

        const { error, value } = schema.validate(req.body, {
            abortEarly: false,
            stripUnknown: true,
        });

        if (error) {
            const errors = error.details.map((detail) => ({
                field: detail.path.join('.'),
                message: detail.message,
            }));

            res.status(400).json({
                success: false,
                error: 'Validation failed',
                details: errors,
            });
            return;
        }

        // Replace body with validated/sanitized value
        req.body = value;
        next();
    };
}

/**
 * Query param validation
 */
export function validateQuery(schema: Joi.ObjectSchema) {
    return (req: Request, res: Response, next: NextFunction): void => {
        const { error, value } = schema.validate(req.query, {
            abortEarly: false,
            stripUnknown: true,
        });

        if (error) {
            const errors = error.details.map((detail) => ({
                field: detail.path.join('.'),
                message: detail.message,
            }));

            res.status(400).json({
                success: false,
                error: 'Validation failed',
                details: errors,
            });
            return;
        }

        req.query = value;
        next();
    };
}
