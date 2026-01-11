import nodemailer from 'nodemailer';
import { config } from '../config/config';
import { logger } from '../middleware/requestLogger';

/**
 * Email templates
 */
interface EmailTemplate {
    subject: string;
    html: string;
    text: string;
}

/**
 * Email Service for sending verification, reset, and alert emails
 */
export class EmailService {
    private transporter: nodemailer.Transporter | null = null;

    constructor() {
        if (config.email.host) {
            this.transporter = nodemailer.createTransport({
                host: config.email.host,
                port: config.email.port,
                secure: config.email.port === 465,
                auth: {
                    user: config.email.user,
                    pass: config.email.password,
                },
            });
        } else {
            logger.warn('Email service not configured - emails will be logged only');
        }
    }

    /**
     * Send email (or log in development)
     */
    private async send(to: string, template: EmailTemplate): Promise<boolean> {
        const mailOptions = {
            from: config.email.from,
            to,
            subject: template.subject,
            html: template.html,
            text: template.text,
        };

        if (!this.transporter) {
            // Log email in development
            logger.info('Email would be sent', {
                to: to.replace(/(.{2}).*(@.*)/, '$1***$2'),
                subject: template.subject,
            });
            return true;
        }

        try {
            await this.transporter.sendMail(mailOptions);
            logger.info('Email sent', {
                to: to.replace(/(.{2}).*(@.*)/, '$1***$2'),
                subject: template.subject,
            });
            return true;
        } catch (error) {
            logger.error('Failed to send email', { error, to: to.replace(/(.{2}).*(@.*)/, '$1***$2') });
            return false;
        }
    }

    /**
     * Send email verification link
     */
    async sendVerificationEmail(email: string, token: string, expiresInHours: number = 24): Promise<boolean> {
        const verificationUrl = `${process.env['APP_URL'] ?? 'https://app.example.com'}/verify-email?token=${token}`;

        const template: EmailTemplate = {
            subject: 'Verify Your Email - Banking App',
            html: `
        <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
          <h1 style="color: #333;">Verify Your Email</h1>
          <p>Please verify your email address by clicking the button below:</p>
          <a href="${verificationUrl}" style="display: inline-block; padding: 12px 24px; background-color: #007bff; color: white; text-decoration: none; border-radius: 4px; margin: 16px 0;">
            Verify Email
          </a>
          <p style="color: #666; font-size: 14px;">
            This link will expire in ${expiresInHours} hours.
          </p>
          <p style="color: #666; font-size: 14px;">
            If you didn't create an account, please ignore this email.
          </p>
          <hr style="border: none; border-top: 1px solid #eee; margin: 24px 0;">
          <p style="color: #999; font-size: 12px;">
            For security, this link can only be used once.
          </p>
        </div>
      `,
            text: `Verify your email by visiting: ${verificationUrl}\n\nThis link expires in ${expiresInHours} hours.`,
        };

        return this.send(email, template);
    }

    /**
     * Send password reset link
     */
    async sendPasswordResetEmail(email: string, token: string, expiresInMinutes: number = 60): Promise<boolean> {
        const resetUrl = `${process.env['APP_URL'] ?? 'https://app.example.com'}/reset-password?token=${token}`;

        const template: EmailTemplate = {
            subject: 'Password Reset Request - Banking App',
            html: `
        <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
          <h1 style="color: #333;">Password Reset Request</h1>
          <p>We received a request to reset your password. Click the button below to proceed:</p>
          <a href="${resetUrl}" style="display: inline-block; padding: 12px 24px; background-color: #dc3545; color: white; text-decoration: none; border-radius: 4px; margin: 16px 0;">
            Reset Password
          </a>
          <p style="color: #666; font-size: 14px;">
            This link will expire in ${expiresInMinutes} minutes.
          </p>
          <p style="color: #dc3545; font-size: 14px;">
            <strong>If you didn't request this, please ignore this email and your password will remain unchanged.</strong>
          </p>
          <hr style="border: none; border-top: 1px solid #eee; margin: 24px 0;">
          <p style="color: #999; font-size: 12px;">
            For security, this link can only be used once.
          </p>
        </div>
      `,
            text: `Reset your password by visiting: ${resetUrl}\n\nThis link expires in ${expiresInMinutes} minutes.\n\nIf you didn't request this, ignore this email.`,
        };

        return this.send(email, template);
    }

    /**
     * Send login alert for new device/location
     */
    async sendLoginAlert(
        email: string,
        device: string,
        ip: string,
        location: string,
        time: Date
    ): Promise<boolean> {
        const template: EmailTemplate = {
            subject: '⚠️ New Login Detected - Banking App',
            html: `
        <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
          <h1 style="color: #333;">New Login to Your Account</h1>
          <p>We detected a new login to your account:</p>
          <table style="margin: 16px 0; border-collapse: collapse;">
            <tr>
              <td style="padding: 8px; color: #666;">Device:</td>
              <td style="padding: 8px;"><strong>${device}</strong></td>
            </tr>
            <tr>
              <td style="padding: 8px; color: #666;">Location:</td>
              <td style="padding: 8px;"><strong>${location}</strong></td>
            </tr>
            <tr>
              <td style="padding: 8px; color: #666;">IP Address:</td>
              <td style="padding: 8px;"><strong>${ip}</strong></td>
            </tr>
            <tr>
              <td style="padding: 8px; color: #666;">Time:</td>
              <td style="padding: 8px;"><strong>${time.toISOString()}</strong></td>
            </tr>
          </table>
          <p style="color: #dc3545;">
            <strong>If this wasn't you, please secure your account immediately by changing your password.</strong>
          </p>
        </div>
      `,
            text: `New login detected:\nDevice: ${device}\nLocation: ${location}\nIP: ${ip}\nTime: ${time.toISOString()}\n\nIf this wasn't you, change your password immediately.`,
        };

        return this.send(email, template);
    }

    /**
     * Send MFA enabled notification
     */
    async sendMFAEnabledNotification(email: string): Promise<boolean> {
        const template: EmailTemplate = {
            subject: '✓ Two-Factor Authentication Enabled - Banking App',
            html: `
        <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
          <h1 style="color: #28a745;">Two-Factor Authentication Enabled</h1>
          <p>Two-factor authentication has been successfully enabled on your account.</p>
          <p>From now on, you'll need to enter a verification code from your authenticator app when logging in.</p>
          <p style="color: #666; font-size: 14px;">
            If you didn't make this change, please contact support immediately.
          </p>
        </div>
      `,
            text: `Two-factor authentication has been enabled on your account. If you didn't make this change, contact support immediately.`,
        };

        return this.send(email, template);
    }

    /**
     * Send password changed notification
     */
    async sendPasswordChangedNotification(email: string, ip: string): Promise<boolean> {
        const template: EmailTemplate = {
            subject: '⚠️ Password Changed - Banking App',
            html: `
        <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
          <h1 style="color: #333;">Your Password Has Been Changed</h1>
          <p>Your account password was changed from IP address: <strong>${ip}</strong></p>
          <p>Time: <strong>${new Date().toISOString()}</strong></p>
          <p style="color: #dc3545;">
            <strong>If you didn't make this change, contact support immediately.</strong>
          </p>
        </div>
      `,
            text: `Your password has been changed from IP: ${ip}. If you didn't make this change, contact support immediately.`,
        };

        return this.send(email, template);
    }
}

// Export singleton
export const emailService = new EmailService();
