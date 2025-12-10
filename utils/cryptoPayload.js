import crypto from 'crypto';
import { Config } from '../cfg/config.js';

/**
 * 🔐 Sistema de encriptación bidireccional para payloads de la API
 * Formato compatible con Kotlin Multiplatform:
 *
 * Base64( salt(32) + iv(12) + ciphertext + authTag(16) )
 */

const ALGORITHM = "aes-256-gcm";
const SALT_LENGTH = 32;
const IV_LENGTH = 12;
const AUTH_TAG_LENGTH = 16;
const KEY_LENGTH = 32;
const PBKDF2_ITERATIONS = 100000; // CORREGIDO: nombre consistente

/**
 * Deriva la clave usando PBKDF2-SHA256 (igual que Kotlin)
 */
function deriveKey(secret, salt) {
    return crypto.pbkdf2Sync(
        secret,
        salt,
        PBKDF2_ITERATIONS,
        KEY_LENGTH,
        "sha256"
    );
}

/**
 * DESCIFRAR con DEBUG
 */
export function decryptPayload(encryptedBase64) {
    console.log("═══════════════ 🔓 DEBUG decryptPayload (Node.js) ─═══════════════");

    try {
        console.log("[DEBUG] encryptedPayload(base64) =", encryptedBase64);

        const buffer = Buffer.from(encryptedBase64, "base64");
        console.log("[DEBUG] total buffer length =", buffer.length);

        if (buffer.length < SALT_LENGTH + IV_LENGTH + AUTH_TAG_LENGTH) {
            throw new Error("Buffer demasiado corto para salt+iv+ciphertext+tag");
        }

        const salt = buffer.subarray(0, SALT_LENGTH);
        const iv = buffer.subarray(SALT_LENGTH, SALT_LENGTH + IV_LENGTH);

        // ciphertext + authTag
        const ctAndTag = buffer.subarray(SALT_LENGTH + IV_LENGTH);
        if (ctAndTag.length < AUTH_TAG_LENGTH) {
            throw new Error("ciphertext demasiado corto para contener authTag");
        }

        const authTag = ctAndTag.subarray(ctAndTag.length - AUTH_TAG_LENGTH);
        const ciphertext = ctAndTag.subarray(0, ctAndTag.length - AUTH_TAG_LENGTH);

        // PRINT DEBUG
        console.log("[DEBUG] salt.len =", salt.length, "hex =", salt.toString("hex"));
        console.log("[DEBUG] iv.len =", iv.length, "hex =", iv.toString("hex"));
        console.log("[DEBUG] ciphertext.len =", ciphertext.length);
        console.log("[DEBUG] authTag.len =", authTag.length, "hex =", authTag.toString("hex"));

        // derive key
        const key = deriveKey(Config.SECRET_KEY, salt);
        console.log("[DEBUG] derivedKey(hex) =", key.toString("hex"));
        console.log("[DEBUG] SECRET_KEY(first 16 chars) =", (Config.SECRET_KEY || "").slice(0, 16));

        // decrypt
        const decipher = crypto.createDecipheriv(ALGORITHM, key, iv);
        decipher.setAuthTag(authTag);

        let decrypted = decipher.update(ciphertext);
        decrypted = Buffer.concat([decrypted, decipher.final()]);

        const jsonString = decrypted.toString("utf8");
        console.log("[DEBUG] decrypted UTF-8 =", jsonString);

        console.log("═══════════════════════════════════════════════");
        return JSON.parse(jsonString);

    } catch (err) {
        console.error("[Decrypt ERROR]", err && err.stack ? err.stack : err);
        console.log("═══════════════════════════════════════════════");
        throw new Error("Error en desencriptación: " + (err && err.message ? err.message : String(err)));
    }
}

/**
 * 🔐 ENCRIPTAR PAYLOAD (Node → Kotlin)
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

        // AuthTag de GCM debe incluirse explícitamente
        const authTag = cipher.getAuthTag();

        // Formato final: salt + iv + ciphertext + authTag
        const result = Buffer.concat([salt, iv, encrypted, authTag]);

        return result.toString('base64');

    } catch (err) {
        console.error('[Encrypt Error]', err);
        throw new Error('Fallo al encriptar payload: ' + err.message);
    }
}

/**
 * 🕒 Validación del timestamp
 */
export function validateTimestamp(timestamp, maxAge = 5 * 60 * 1000) {
    const now = Date.now();
    const age = Math.abs(now - timestamp);
    return age <= maxAge;
}

/**
 * 🔓 Middleware: desencriptar requests
 */
export function decryptBodyMiddleware(req, res, next) {

    if (!Config.ENCRYPTION_ENABLED) return next();

    if (!req.body?.encryptedPayload) {
        if (Config.ALLOW_UNENCRYPTED) {
            console.log('ℹ️ Request sin encriptar (permitido)');
            return next();
        }
        return res.status(400).json({
            resultado: 'error',
            mensaje: 'Se requiere payload encriptado'
        });
    }

    try {
        console.log('🔓 Desencriptando payload entrante...');

        const decrypted = decryptPayload(req.body.encryptedPayload);

        if (decrypted.timestamp && !validateTimestamp(decrypted.timestamp)) {
            return res.status(401).json({
                resultado: 'error',
                mensaje: 'Solicitud expirada o timestamp inválido'
            });
        }

        req.body = decrypted.data || decrypted;
        req.decryptedAt = Date.now();
        req.wasEncrypted = true;

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
 * 🔐 Middleware: encriptar respuestas
 */
export function encryptResponseMiddleware(req, res, next) {

    if (!Config.ENCRYPTION_ENABLED) return next();

    const originalJson = res.json.bind(res);

    res.json = function (data) {
        const shouldEncrypt = req.wasEncrypted &&
            req.method !== 'GET' &&
            data &&
            Object.keys(data).length > 0;

        if (!shouldEncrypt) return originalJson(data);

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
 * Helper para encriptar manualmente
 */
export function encryptResponse(data) {
    if (!Config.ENCRYPTION_ENABLED) return data;

    try {
        const encrypted = encryptPayload(data);
        return { encryptedPayload: encrypted };

    } catch (err) {
        console.error('[Manual Encryption Error]', err.message);
        return data;
    }
}