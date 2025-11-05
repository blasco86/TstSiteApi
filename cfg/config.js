import path from 'path';
import { fileURLToPath } from 'url';
import dotenv from 'dotenv';
import { Cryptor } from '../utils/cryptor.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
dotenv.config({ path: path.join(__dirname, '.env.tstsite') });

const cryptor = new Cryptor(path.join(__dirname, '../utils/.env.key'));
const envData = cryptor.decryptEnvFile(path.join(__dirname, '.env.tstsite'));

const SECRET_KEY = envData.SECRET_KEY;
if (!SECRET_KEY || SECRET_KEY.length < 32) {
    console.error('❌ SECRET_KEY no configurada o insuficiente (min 32 bytes).');
    process.exit(1);
}

export const Config = {
    SECRET_KEY,
    API_KEY: envData.API_KEY,
    ALGORITHM: envData.ALGORITHM || 'HS256',
    JWT_EXPIRATION_DELTA: parseInt(envData.JWT_MINUTES || '30', 10) * 60,
    JWT_ISSUER: envData.JWT_ISSUER || 'tstsite',
    JWT_AUDIENCE: envData.JWT_AUDIENCE || 'tstsite-api',
    DB_CONFIG: {
        host: envData.DB_HOST,
        port: parseInt(envData.DB_PORT || '5432', 10),
        user: envData.DB_USER,
        password: envData.DB_PASSWORD,
        database: envData.DB_NAME
    }
};