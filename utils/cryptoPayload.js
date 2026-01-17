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
    const buffer = Buffer.from(encryptedData, 'base64');
    const minLength = SALT_LENGTH + IV_LENGTH + AUTH_TAG_LENGTH;

    if (buffer.length < minLength) {
        const msg = `El contenido cifrado es demasiado corto: ${buffer.length} bytes`;
        console.error('[Decrypt Error]', msg);
        throw new Error('Fallo al desencriptar el contenido: ' + msg);
    }

    try {
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
 * @param {import('express').Request & { wasEncrypted?: boolean }} req - El objeto de solicitud de Express.
 * @param {import('express').Response} res - El objeto de respuesta de Express.
 * @param {import('express').NextFunction} next - La función para pasar al siguiente middleware.
 */
export function decryptBodyMiddleware(req, res, next) {
    if (!Config.ENCRYPTION_ENABLED) {
        return next();
    }

    // Si es una petición GET, no suele tener body, así que pasamos.
    // (A menos que tu API use GET con body, lo cual es raro pero posible).
    /*
    if (req.method === 'GET') {
        return next();
    }
    */

    if (!req.body?.encryptedPayload) {
        if (Config.ALLOW_UNENCRYPTED) {
            return next();
        }

        // Si el cliente acepta HTML (es un navegador), devolvemos una página de error bonita con título.
        if (req.accepts('html')) {
            const errorResponse = {
                resultado: 'error',
                mensaje: 'Se requiere un contenido cifrado (encryptedPayload)'
            };
            return res.status(400).send(`
                <!DOCTYPE html>
                <html lang="es">
                <head>
                    <meta charset="UTF-8">
                    <title>TstSite API</title>
                    <style>
                        body { font-family: monospace; background: #1e1e1e; color: #d4d4d4; padding: 20px; }
                        pre { background: #252526; padding: 15px; border-radius: 5px; border: 1px solid #3e3e42; overflow-x: auto; }
                    </style>
                </head>
                <body>
                    <h1>TstSite API - Error</h1>
                    <pre>${JSON.stringify(errorResponse, null, 4)}</pre>
                </body>
                </html>
            `);
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
 * @param {import('express').Request & { wasEncrypted?: boolean }} req - El objeto de solicitud de Express.
 * @param {import('express').Response} res - El objeto de respuesta de Express.
 * @param {import('express').NextFunction} next - La función para pasar al siguiente middleware.
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