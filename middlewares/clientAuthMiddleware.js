import crypto from 'crypto';
import jwt from 'jsonwebtoken';
import { Config } from '../cfg/config.js';

/**
 * timingSafeCompare
 * 🕰️ Compara dos cadenas de forma segura contra ataques de temporización.
 * @param {string} a - La primera cadena a comparar.
 * @param {string} b - La segunda cadena a comparar.
 */
function timingSafeCompare(a, b) {
    const bufA = Buffer.from(a || '');
    const bufB = Buffer.from(b || '');
    if (bufA.length !== bufB.length) return false;
    return crypto.timingSafeEqual(bufA, bufB);
}

/**
 * clientAuthMiddleware
 * 🔐 Middleware unificado: acepta JWT (clientes) o API Key (uso interno/admin).
 *
 * Estrategia:
 *  1. Si viene header `Authorization: Bearer <token>` → valida JWT.
 *  2. Si viene header `x-api-key` → valida API Key (uso interno/scripts).
 *  3. Si ninguno → 401.
 *
 * Esto permite eliminar la API Key de todos los clientes (JS, WasmJS, Android,
 * iOS, JVM) sin romper herramientas internas que usen la key directamente.
 * @param {object} req - El objeto de solicitud de Express.
 * @param {object} res - El objeto de respuesta de Express.
 * @param {function} next - La función next de Express.
 */
export function clientAuthMiddleware(req, res, next) {
    const authHeader = req.headers['authorization'] || '';
    const apiKey = req.headers['x-api-key'];

    // --- Opción 1: JWT ---
    if (authHeader.startsWith('Bearer ')) {
        const token = authHeader.split(' ')[1];
        try {
            const decoded = jwt.verify(token, Config.SECRET_KEY, {
                algorithms: [Config.ALGORITHM],
                issuer: Config.JWT_ISSUER,
                audience: Config.JWT_AUDIENCE,
            });
            req.user = decoded;
            return next();
        } catch {
            return res.status(401).json({ resultado: 'error', mensaje: 'El token no es válido o ha expirado' });
        }
    }

    // --- Opción 2: API Key (uso interno) ---
    if (apiKey) {
        if (timingSafeCompare(String(apiKey), String(Config.API_KEY || ''))) {
            req.user = { role: 'internal' };
            return next();
        }
        return res.status(403).json({ resultado: 'error', mensaje: 'La clave de API no es válida' });
    }

    // --- Sin credenciales ---
    return res.status(401).json({ resultado: 'error', mensaje: 'Se requiere autenticación (token o API Key)' });
}