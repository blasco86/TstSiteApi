import crypto from 'crypto';
import { Config } from '../cfg/config.js';

/**
 * 🔐 Sistema de encriptación compatible con Kotlin Multiplatform
 * AES-256-GCM con authTag incluido automáticamente en el ciphertext
 *
 * FORMATO COMPATIBLE:
 * Base64( salt(32) + iv(12) + ciphertext_con_authTag )
 */

const ALGORITHM = 'aes-256-gcm';
const IV_LENGTH = 12;
const AUTH_TAG_LENGTH = 16;
const SALT_LENGTH = 32;

/**
 * deriveKey
 * 🔑 Deriva una clave de cifrado usando HMAC-SHA256.
 * @param {Buffer} salt - El salt, que se usará como dato para el HMAC.
 * @returns {Buffer} La clave derivada de 32 bytes.
 */
function deriveKey(salt) {
    return crypto.createHmac('sha256', Config.SECRET_KEY)
        .update(salt)
        .digest();
}

/**
 * decryptPayload
 * 🔓 Desencripta un payload encriptado.
 * @param {string} encryptedData - El payload encriptado en base64.
 * @returns {object} - El payload desencriptado.
 */
export function decryptPayload(encryptedData) {
    try {
        const buffer = Buffer.from(encryptedData, 'base64');

        const minLength = SALT_LENGTH + IV_LENGTH + AUTH_TAG_LENGTH;
        if (buffer.length < minLength) {
            throw new Error(`El contenido cifrado es demasiado corto: ${buffer.length} bytes`);
        }

        const salt = buffer.subarray(0, SALT_LENGTH);
        const iv = buffer.subarray(SALT_LENGTH, SALT_LENGTH + IV_LENGTH);
        const ciphertextWithTag = buffer.subarray(SALT_LENGTH + IV_LENGTH);

        const key = deriveKey(salt);

        const ciphertext = ciphertextWithTag.subarray(0, ciphertextWithTag.length - AUTH_TAG_LENGTH);
        const authTag = ciphertextWithTag.subarray(ciphertextWithTag.length - AUTH_TAG_LENGTH);

        const decipher = crypto.createDecipheriv(ALGORITHM, key, iv);
        decipher.setAuthTag(authTag);

        let decrypted = decipher.update(ciphertext);
        decrypted = Buffer.concat([decrypted, decipher.final()]);

        return JSON.parse(decrypted.toString('utf8'));
    } catch (err) {
        console.error('[Decrypt Error]', err.message);
        throw new Error('Fallo al desencriptar el contenido: ' + err.message);
    }
}

/**
 * encryptPayload
 * 🔐 Encripta un payload.
 * @param {object} data - El payload a encriptar.
 * @returns {string} - El payload encriptado en base64.
 */
export function encryptPayload(data) {
    try {
        const salt = crypto.randomBytes(SALT_LENGTH);
        const iv = crypto.randomBytes(IV_LENGTH);
        const key = deriveKey(salt);

        const plaintext = JSON.stringify(data);
        const cipher = crypto.createCipheriv(ALGORITHM, key, iv);

        let encrypted = cipher.update(plaintext, 'utf8');
        encrypted = Buffer.concat([encrypted, cipher.final()]);

        const authTag = cipher.getAuthTag();
        const result = Buffer.concat([salt, iv, encrypted, authTag]);

        return result.toString('base64');
    } catch (err) {
        console.error('[Encrypt Error]', err.message);
        throw new Error('Fallo al encriptar el contenido: ' + err.message);
    }
}

/**
 * validateTimestamp
 * 🕰️ Valida la marca de tiempo de una solicitud.
 * @param {number} timestamp - La marca de tiempo a validar.
 * @param {number} maxAge - La edad máxima permitida en milisegundos.
 * @returns {boolean} - `true` si la marca de tiempo es válida, `false` en caso contrario.
 */
export function validateTimestamp(timestamp, maxAge = 5 * 60 * 1000) {
    const now = Date.now();
    const age = Math.abs(now - timestamp);
    return age <= maxAge;
}

/**
 * decryptBodyMiddleware
 * 🛡️ Middleware para desencriptar el cuerpo de la solicitud.
 * @param {object} req - El objeto de solicitud de Express.
 * @param {object} res - El objeto de respuesta de Express.
 * @param {function} next - La función para pasar al siguiente middleware.
 */
export function decryptBodyMiddleware(req, res, next) {
    if (!Config.ENCRYPTION_ENABLED) {
        return next();
    }

    if (!req.body?.encryptedPayload) {
        if (Config.ALLOW_UNENCRYPTED) {
            return next();
        }
        return res.status(400).json({
            resultado: 'error',
            mensaje: 'Se requiere un contenido cifrado (encryptedPayload)'
        });
    }

    try {
        const decrypted = decryptPayload(req.body.encryptedPayload);

        if (decrypted.timestamp && !validateTimestamp(decrypted.timestamp)) {
            return res.status(401).json({
                resultado: 'error',
                mensaje: 'La solicitud ha caducado por tiempo'
            });
        }

        req.body = decrypted.data || decrypted;
        req.wasEncrypted = true;

        next();
    } catch (err) {
        console.error('❌ Error al desencriptar:', err.message);
        return res.status(400).json({
            resultado: 'error',
            mensaje: 'Error al desencriptar el contenido',
            detalle: err.message
        });
    }
}

/**
 * encryptResponseMiddleware
 * 🛡️ Middleware para encriptar la respuesta.
 * @param {object} req - El objeto de solicitud de Express.
 * @param {object} res - El objeto de respuesta de Express.
 * @param {function} next - La función para pasar al siguiente middleware.
 */
export function encryptResponseMiddleware(req, res, next) {
    if (!Config.ENCRYPTION_ENABLED) {
        return next();
    }

    const originalJson = res.json.bind(res);

    res.json = function(data) {
        const shouldEncrypt = req.wasEncrypted &&
            req.method !== 'GET' &&
            data &&
            Object.keys(data).length > 0;

        if (!shouldEncrypt) {
            return originalJson(data);
        }

        try {
            const encrypted = encryptPayload(data);
            return originalJson({ encryptedPayload: encrypted });
        } catch (err) {
            console.error('[Response Encryption Error]', err.message);
            return originalJson(data);
        }
    };

    next();
}

/**
 * encryptResponse
 * 🔐 Encripta una respuesta.
 * @param {object} data - La respuesta a encriptar.
 * @returns {object} - La respuesta encriptada.
 */
export function encryptResponse(data) {
    if (!Config.ENCRYPTION_ENABLED) {
        return data;
    }
    try {
        const encrypted = encryptPayload(data);
        return { encryptedPayload: encrypted };
    } catch (err) {
        console.error('[Manual Encryption Error]', err.message);
        return data;
    }
}