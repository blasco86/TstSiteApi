import crypto from 'crypto';
import { Config } from '../cfg/config.js';

/**
 * 🔐 Sistema de encriptación para payloads de la API
 * Usa AES-256-GCM con claves derivadas de PBKDF2
 */

// Constantes de encriptación
const ALGORITHM = 'aes-256-gcm';
const IV_LENGTH = 12; // GCM recomienda 12 bytes
const AUTH_TAG_LENGTH = 16;
const SALT_LENGTH = 32;
const KEY_LENGTH = 32; // 256 bits
const PBKDF2_ITERATIONS = 100000;

/**
 * Deriva una clave de encriptación desde la SECRET_KEY usando PBKDF2
 * @param {Buffer} salt - Salt único para derivación
 * @returns {Buffer} Clave derivada
 */
function deriveKey(salt) {
    return crypto.pbkdf2Sync(
        Config.SECRET_KEY,
        salt,
        PBKDF2_ITERATIONS,
        KEY_LENGTH,
        'sha256'
    );
}

/**
 * 🔓 Desencripta un payload encriptado por el cliente
 * @param {string} encryptedData - Datos encriptados en formato base64
 * @returns {Object} Objeto JSON desencriptado
 * @throws {Error} Si falla la desencriptación o validación
 */
export function decryptPayload(encryptedData) {
    try {
        // Decodificar de base64
        const buffer = Buffer.from(encryptedData, 'base64');

        // Estructura: [salt:32][iv:12][authTag:16][ciphertext:*]
        if (buffer.length < SALT_LENGTH + IV_LENGTH + AUTH_TAG_LENGTH) {
            throw new Error('Payload encriptado demasiado corto');
        }

        // Extraer componentes
        const salt = buffer.subarray(0, SALT_LENGTH);
        const iv = buffer.subarray(SALT_LENGTH, SALT_LENGTH + IV_LENGTH);
        const authTag = buffer.subarray(
            SALT_LENGTH + IV_LENGTH,
            SALT_LENGTH + IV_LENGTH + AUTH_TAG_LENGTH
        );
        const ciphertext = buffer.subarray(SALT_LENGTH + IV_LENGTH + AUTH_TAG_LENGTH);

        // Derivar clave
        const key = deriveKey(salt);

        // Desencriptar
        const decipher = crypto.createDecipheriv(ALGORITHM, key, iv);
        decipher.setAuthTag(authTag);

        let decrypted = decipher.update(ciphertext);
        decrypted = Buffer.concat([decrypted, decipher.final()]);

        // Parsear JSON
        return JSON.parse(decrypted.toString('utf8'));
    } catch (err) {
        console.error('[Decrypt Error]', err.message);
        throw new Error('Fallo al desencriptar payload: ' + err.message);
    }
}

/**
 * 🔐 Encripta un payload para enviar al cliente
 * @param {Object} data - Objeto a encriptar
 * @returns {string} Datos encriptados en base64
 */
export function encryptPayload(data) {
    try {
        // Generar componentes aleatorios
        const salt = crypto.randomBytes(SALT_LENGTH);
        const iv = crypto.randomBytes(IV_LENGTH);

        // Derivar clave
        const key = deriveKey(salt);

        // Serializar datos
        const plaintext = JSON.stringify(data);

        // Encriptar
        const cipher = crypto.createCipheriv(ALGORITHM, key, iv);
        let encrypted = cipher.update(plaintext, 'utf8');
        encrypted = Buffer.concat([encrypted, cipher.final()]);

        // Obtener auth tag
        const authTag = cipher.getAuthTag();

        // Combinar: salt + iv + authTag + ciphertext
        const result = Buffer.concat([salt, iv, authTag, encrypted]);

        // Retornar en base64
        return result.toString('base64');
    } catch (err) {
        console.error('[Encrypt Error]', err.message);
        throw new Error('Fallo al encriptar payload: ' + err.message);
    }
}

/**
 * Valida timestamp para prevenir ataques replay
 * @param {number} timestamp - Timestamp del cliente (ms)
 * @param {number} maxAge - Edad máxima permitida en ms (default: 5min)
 * @returns {boolean} true si el timestamp es válido
 */
export function validateTimestamp(timestamp, maxAge = 5 * 60 * 1000) {
    const now = Date.now();
    const age = Math.abs(now - timestamp);
    return age <= maxAge;
}

/**
 * Middleware Express para desencriptar body automáticamente
 */
export function decryptBodyMiddleware(req, res, next) {
    // Solo procesar si hay encryptedPayload en el body
    if (!req.body?.encryptedPayload) {
        return next();
    }

    try {
        const decrypted = decryptPayload(req.body.encryptedPayload);

        // Validar timestamp si existe
        if (decrypted.timestamp && !validateTimestamp(decrypted.timestamp)) {
            return res.status(401).json({
                resultado: 'error',
                mensaje: 'Solicitud expirada o timestamp inválido'
            });
        }

        // Reemplazar body con datos desencriptados
        req.body = decrypted.data || decrypted;
        req.decryptedAt = Date.now();

        next();
    } catch (err) {
        return res.status(400).json({
            resultado: 'error',
            mensaje: 'Error al desencriptar payload',
            detalle: err.message
        });
    }
}