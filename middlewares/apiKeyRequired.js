import crypto from 'crypto';
import { Config } from '../cfg/config.js';

function timingSafeCompare(a, b) {
    const bufA = Buffer.from(a || '');
    const bufB = Buffer.from(b || '');
    if (bufA.length !== bufB.length) return false;
    return crypto.timingSafeEqual(bufA, bufB);
}

export function apiKeyRequired(req, res, next) {
    const apiKey = req.headers['x-api-key'];
    if (!apiKey) {
        return res.status(401).json({ resultado: 'error', mensaje: 'API Key requerida' });
    }
    if (!timingSafeCompare(String(apiKey), String(Config.API_KEY || ''))) {
        return res.status(403).json({ resultado: 'error', mensaje: 'API Key no valida' });
    }
    next();
}