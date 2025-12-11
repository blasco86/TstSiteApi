import crypto from 'crypto';
import { Config } from '../cfg/config.js';

/**
 * timingSafeCompare
 * 🕰️ Compara dos cadenas de forma segura contra ataques de temporización.
 * @param {string} a - La primera cadena.
 * @param {string} b - La segunda cadena.
 * @returns {boolean} - `true` si las cadenas son iguales, `false` en caso contrario.
 */
function timingSafeCompare(a, b) {
    const bufA = Buffer.from(a || '');
    const bufB = Buffer.from(b || '');
    if (bufA.length !== bufB.length) return false;
    return crypto.timingSafeEqual(bufA, bufB);
}

/**
 * apiKeyRequired
 * 🔑 Middleware para verificar la API Key.
 * @param {object} req - El objeto de solicitud de Express.
 * @param {object} res - El objeto de respuesta de Express.
 * @param {function} next - La función para pasar al siguiente middleware.
 */
export function apiKeyRequired(req, res, next) {
    const apiKey = req.headers['x-api-key'];
    if (!apiKey) {
        return res.status(401).json({ resultado: 'error', mensaje: 'Se requiere una clave de API (API Key)' });
    }
    if (!timingSafeCompare(String(apiKey), String(Config.API_KEY || ''))) {
        return res.status(403).json({ resultado: 'error', mensaje: 'La clave de API (API Key) no es válida' });
    }
    next();
}