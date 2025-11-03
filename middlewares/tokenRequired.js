import jwt from 'jsonwebtoken';
import { Config } from '../cfg/config.js';

export function tokenRequired(req, res, next) {
    const authHeader = req.headers['authorization'] || '';
    if (!authHeader.startsWith('Bearer ')) {
        return res.status(401).json({ error: 'Token requerido o mal formado' });
    }

    const token = authHeader.split(' ')[1];
    try {
        const payload = jwt.verify(token, Config.SECRET_KEY, {
            algorithms: [Config.ALGORITHM]
        });
        req.user = payload;
        next();
    } catch (err) {
        if (err.name === 'TokenExpiredError') {
            return res.status(401).json({ error: 'Token expirado' });
        }
        return res.status(401).json({ error: 'Token inválido' });
    }
}
