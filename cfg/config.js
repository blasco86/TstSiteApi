import path from 'path';
import { fileURLToPath } from 'url';
import dotenv from 'dotenv';
import { Cryptor } from '../utils/cryptor.js';

/**
 * 📂 Obtiene el directorio actual del archivo.
 */
const __dirname = path.dirname(fileURLToPath(import.meta.url));

/**
 * 🤫 Carga las variables de entorno desde el archivo .env.tstsite.
 */
dotenv.config({ path: path.join(__dirname, '../.env/.env.tstsite') });

/**
 * 🔑 Inicializa el encriptador con la clave del archivo .env.key.
 */
const cryptor = new Cryptor(path.join(__dirname, '../.env/.env.key'));

/**
 *  decryptEnvFile
 * 📄 Desencripta el archivo de entorno y obtiene los datos.
 * @param {string} path - Ruta al archivo de entorno encriptado.
 * @returns {object} - Objeto con las variables de entorno desencriptadas.
 */
const envData = cryptor.decryptEnvFile(path.join(__dirname, '../.env/.env.tstsite'));

/**
 * SECRET_KEY
 * 🗝️ Clave secreta para la firma de tokens JWT.
 * @type {string}
 */
const SECRET_KEY = envData.SECRET_KEY;
if (!SECRET_KEY || SECRET_KEY.length < 32) {
    console.error('❌ SECRET_KEY no configurada o insuficiente (min 32 bytes).');
    process.exit(1);
}

/**
 * Config
 * ⚙️ Objeto de configuración para la aplicación.
 * @property {string} SECRET_KEY - Clave secreta para JWT.
 * @property {string} API_KEY - Clave de API para el acceso a la aplicación.
 * @property {string} ALGORITHM - Algoritmo de firma para JWT.
 * @property {number} JWT_EXPIRATION_DELTA - Tiempo de expiración de JWT en segundos.
 * @property {string} JWT_ISSUER - Emisor del token JWT.
 * @property {string} JWT_AUDIENCE - Audiencia del token JWT.
 * @property {boolean} ENCRYPTION_ENABLED - Flag para habilitar/deshabilitar encriptación de payloads.
 * @property {boolean} ALLOW_UNENCRYPTED - Flag para permitir requests sin encriptar.
 * @property {object} DB_CONFIG - Configuración de la base de datos.
 */
export const Config = {
    SECRET_KEY,
    API_KEY: envData.API_KEY,
    ALGORITHM: envData.ALGORITHM || 'HS256',
    JWT_EXPIRATION_DELTA: parseInt(envData.JWT_MINUTES || '30', 10) * 60,
    JWT_ISSUER: envData.JWT_ISSUER || 'tstsite',
    JWT_AUDIENCE: envData.JWT_AUDIENCE || 'tstsite-api',

    // 🔐 Flag para habilitar/deshabilitar encriptación de payloads
    ENCRYPTION_ENABLED: envData.ENCRYPTION_ENABLED === 'true' || false,
    // 🔓 Flag para permitir requests sin encriptar cuando la encriptación está habilitada
    ALLOW_UNENCRYPTED: envData.ALLOW_UNENCRYPTED === 'true' || true,

    DB_CONFIG: {
        host: envData.DB_HOST,
        port: parseInt(envData.DB_PORT || '5432', 10),
        user: envData.DB_USER,
        password: envData.DB_PASSWORD,
        database: envData.DB_NAME
    }
};