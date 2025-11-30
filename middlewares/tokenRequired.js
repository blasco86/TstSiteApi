import jwt from 'jsonwebtoken';
import { Config } from '../cfg/config.js';

export const revokedTokens = new Set();

export function tokenRequired(req, res, next) {
    const authHeader = req.headers['authorization'] || '';
    if (!authHeader.startsWith('Bearer ')) {
        return res.status(401).json({ resultado: 'error', mensaje: 'Token requerido' });
    }
    const token = authHeader.split(' ')[1];
    try {
        const decoded = jwt.verify(token, Config.SECRET_KEY, {
            algorithms: [Config.ALGORITHM],
            issuer: Config.JWT_ISSUER,
            audience: Config.JWT_AUDIENCE
        });
        if (revokedTokens.has(decoded.jti)) {
            return res.status(401).json({ resultado: 'error', mensaje: 'Token revocado. Debe iniciar sesión nuevamente.' });
        }
        req.user = decoded;
        next();
    } catch (err) {
        return res.status(401).json({ resultado: 'error', mensaje: 'Token no valido o expirado' });
    }
}