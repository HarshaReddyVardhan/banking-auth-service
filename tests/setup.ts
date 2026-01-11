// Test setup file

// Set test environment variables
process.env['NODE_ENV'] = 'test';
process.env['DB_HOST'] = 'localhost';
process.env['DB_PORT'] = '5432';
process.env['DB_NAME'] = 'banking_auth_test';
process.env['DB_USER'] = 'test_user';
process.env['DB_PASSWORD'] = 'test_password';
process.env['DB_SSL'] = 'false';
process.env['REDIS_HOST'] = 'localhost';
process.env['REDIS_PORT'] = '6379';
process.env['REDIS_TLS'] = 'false';
process.env['FIELD_ENCRYPTION_KEY'] = '0123456789abcdef0123456789abcdef';
process.env['BCRYPT_ROUNDS'] = '4'; // Lower for faster tests
process.env['JWT_PRIVATE_KEY'] = `-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEA0Z3VS5JJcds3xfn/ygWyF8PbnGy0AXwYDGR+FBhB0kHdJz9m
-----END RSA PRIVATE KEY-----`;
process.env['JWT_PUBLIC_KEY'] = `-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0Z3VS5JJcds3xfn/ygWy
-----END PUBLIC KEY-----`;

// Increase timeout for async operations
jest.setTimeout(10000);
