import dotenv from 'dotenv';
import path from 'path';
import { fileURLToPath } from 'url';
import { Cryptor } from '../utils/cryptor.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
dotenv.config({ path: path.join(__dirname, '.env.tstsite') });

const cryptor = new Cryptor(path.join(__dirname, '../utils/.env.key'));
const envData = cryptor.decryptEnvFile(path.join(__dirname, '.env.tstsite'));

export const Config = {
    SECRET_KEY: envData.SECRET_KEY || 'fallback-secret',
    API_KEY: envData.API_KEY,
    ALGORITHM: envData.ALGORITHM || 'HS256',
    // 🔄 Ahora en minutos (30 min por defecto)
    JWT_EXPIRATION_DELTA: parseInt(envData.JWT_MINUTES || '30', 10) * 60,
    DB_CONFIG: {
        host: envData.DB_HOST,
        port: parseInt(envData.DB_PORT || '5432', 10),
        user: envData.DB_USER,
        password: envData.DB_PASSWORD,
        database: envData.DB_NAME
    }
};