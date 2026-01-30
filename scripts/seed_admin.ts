import { sequelize, User } from '../src/models';
import { UserStatus, KycStatus } from '../src/models/User';
import { passwordHasher } from '../src/utils/PasswordHasher';
import { logger } from '../src/middleware/requestLogger';
import { config } from '../src/config/config';

async function seedAdmin() {
    try {
        await sequelize.authenticate();
        console.log('Database connection established successfully.');

        // Initial sync to ensure tables exist (only safe in dev/test)
        if (config.isDevelopment()) {
            await sequelize.sync();
        }

        const adminEmail = 'admin@example.com';
        const adminPassword = 'AdminPassword123!';

        const existingUser = await User.findOne({
            where: { email: adminEmail }
        });

        if (existingUser) {
            console.log('Admin user already exists.');
            return;
        }

        console.log('Creating admin user...');

        const passwordHash = await passwordHasher.hash(adminPassword);

        // Create admin user with all verifications passed
        const admin = await User.create({
            email: adminEmail,
            passwordHash,
            status: UserStatus.ACTIVE,
            emailVerified: true,
            kycStatus: KycStatus.VERIFIED,
            mfaEnabled: false, // Start without MFA for easier testing
            failedLoginAttempts: 0
        });

        console.log('===================================================');
        console.log('ADMIN USER CREATED SUCCESSFULLY');
        console.log('===================================================');
        console.log(`Email:    ${adminEmail}`);
        console.log(`Password: ${adminPassword}`);
        console.log('===================================================');

    } catch (error) {
        console.error('Error seeding admin user:', error);
        process.exit(1);
    } finally {
        await sequelize.close();
    }
}

seedAdmin();
