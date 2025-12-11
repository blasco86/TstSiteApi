import jwt from 'jsonwebtoken';
import { Config } from '../cfg/config.js';

/**
 * 🚫 Almacena los tokens JWT revocados.
 * @type {Set<string>}
 */
export const revokedTokens = new Set();

/**
 * tokenRequired
 * 🛡️ Middleware para verificar el token JWT.
 * @param {object} req - El objeto de solicitud de Express.
 * @param {object} res - El objeto de respuesta de Express.
 * @param {function} next - La función para pasar al siguiente middleware.
 */
export function tokenRequired(req, res, next) {
    const authHeader = req.headers['authorization'] || '';
    if (!authHeader.startsWith('Bearer ')) {
        return res.status(401).json({ resultado: 'error', mensaje: 'Se requiere un token de autenticación' });
    }
    const token = authHeader.split(' ')[1];
    try {
        const decoded = jwt.verify(token, Config.SECRET_KEY, {
            algorithms: [Config.ALGORITHM],
            issuer: Config.JWT_ISSUER,
            audience: Config.JWT_AUDIENCE
        });
        if (revokedTokens.has(decoded.jti)) {
            return res.status(401).json({ resultado: 'error', mensaje: 'El token ha sido revocado. Debe iniciar sesión de nuevo.' });
        }
        req.user = decoded;
        next();
    } catch (err) {
        return res.status(401).json({ resultado: 'error', mensaje: 'El token no es válido o ha expirado' });
    }
}