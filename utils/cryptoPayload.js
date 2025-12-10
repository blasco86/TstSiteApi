import crypto from 'crypto';
import { Config } from '../cfg/config.js';

/**
 * 🔐 Sistema de encriptación bidireccional para payloads de la API
 * Usa AES-256-GCM con claves derivadas de PBKDF2
 *
 * FORMATO COMPATIBLE CON KOTLIN MULTIPLATFORM:
 * Base64( salt(32 bytes) + iv(12 bytes) + ciphertext+authTag )
 *
 * El authTag (16 bytes) está incluido automáticamente al final del ciphertext
 * por cipher.final() en ambas implementaciones (Node.js y Kotlin)
 */

// Constantes de encriptación
const ALGORITHM = 'aes-256-gcm';
const IV_LENGTH = 12;
const AUTH_TAG_LENGTH = 16;
const SALT_LENGTH = 32;
const KEY_LENGTH = 32;
const PBKDF2_ITERATIONS = 100000;

/**
 * Deriva una clave de encriptación desde la SECRET_KEY usando PBKDF2
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
 */
export function decryptPayload(encryptedData) {
    try {
        const buffer = Buffer.from(encryptedData, 'base64');

        // Estructura: salt(32) + iv(12) + ciphertext+authTag
        const minLength = SALT_LENGTH + IV_LENGTH + AUTH_TAG_LENGTH;

        if (buffer.length < minLength) {
            throw new Error(`Payload demasiado corto: ${buffer.length} bytes (mínimo ${minLength})`);
        }

        // Extraer componentes
        const salt = buffer.subarray(0, SALT_LENGTH);
        const iv = buffer.subarray(SALT_LENGTH, SALT_LENGTH + IV_LENGTH);
        // El resto es ciphertext + authTag (el authTag está al final automáticamente)
        const ciphertextAndTag = buffer.subarray(SALT_LENGTH + IV_LENGTH);

        // Derivar clave
        const key = deriveKey(salt);

        // Desencriptar
        const decipher = crypto.createDecipheriv(ALGORITHM, key, iv);

        let decrypted = decipher.update(ciphertextAndTag);
        decrypted = Buffer.concat([decrypted, decipher.final()]);

        return JSON.parse(decrypted.toString('utf8'));
    } catch (err) {
        console.error('[Decrypt Error]', err.message);
        throw new Error('Fallo al desencriptar payload: ' + err.message);
    }
}

/**
 * 🔐 Encripta un payload para enviar al cliente
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

        const result = Buffer.concat([salt, iv, encrypted]);

        return result.toString('base64');
    } catch (err) {
        console.error('[Encrypt Error]', err.message);
        throw new Error('Fallo al encriptar payload: ' + err.message);
    }
}

/**
 * Valida timestamp para prevenir ataques replay
 */
export function validateTimestamp(timestamp, maxAge = 5 * 60 * 1000) {
    const now = Date.now();
    const age = Math.abs(now - timestamp);
    return age <= maxAge;
}

/**
 * 🔓 Middleware para desencriptar body de requests entrantes
 */
export function decryptBodyMiddleware(req, res, next) {
    // Si la encriptación está deshabilitada, pasar directo
    if (!Config.ENCRYPTION_ENABLED) {
        return next();
    }

    // Si no hay encryptedPayload, verificar si se permite sin encriptar
    if (!req.body?.encryptedPayload) {
        if (Config.ALLOW_UNENCRYPTED) {
            console.log('ℹ️ Request sin encriptar (permitido)');
            return next();
        } else {
            return res.status(400).json({
                resultado: 'error',
                mensaje: 'Se requiere payload encriptado'
            });
        }
    }

    // Desencriptar payload
    try {
        console.log('🔓 Desencriptando payload entrante...');
        console.log('🔍 Longitud del payload Base64:', req.body.encryptedPayload.length);

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
        req.wasEncrypted = true;

        console.log('✅ Payload desencriptado correctamente');
        next();
    } catch (err) {
        console.error('❌ Error al desencriptar:', err.message);
        return res.status(400).json({
            resultado: 'error',
            mensaje: 'Error al desencriptar payload',
            detalle: err.message
        });
    }
}

/**
 * 🔐 Middleware para encriptar respuestas salientes
 */
export function encryptResponseMiddleware(req, res, next) {
    if (!Config.ENCRYPTION_ENABLED) {
        return next();
    }

    // Guardar la función json original
    const originalJson = res.json.bind(res);

    // Sobrescribir res.json para encriptar
    res.json = function(data) {
        const shouldEncrypt = req.wasEncrypted &&
            req.method !== 'GET' &&
            data &&
            Object.keys(data).length > 0;

        if (!shouldEncrypt) {
            return originalJson(data);
        }

        try {
            console.log('🔐 Encriptando respuesta...');
            const encrypted = encryptPayload(data);

            return originalJson({
                encryptedPayload: encrypted
            });
        } catch (err) {
            console.error('[Response Encryption Error]', err.message);
            return originalJson(data);
        }
    };

    next();
}

/**
 * 🔐 Helper para encriptar respuestas manualmente
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