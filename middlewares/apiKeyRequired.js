import { Config } from '../cfg/config.js';

export function apiKeyRequired(req, res, next) {
    const apiKey = req.headers['x-api-key'];
    if (!apiKey) {
        return res.status(401).json({ error: 'API Key requerida' });
    }
    if (apiKey !== Config.API_KEY) {
        return res.status(403).json({ error: 'API Key inválida' });
    }
    next();
}
