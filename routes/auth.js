import express from 'express';
import jwt from 'jsonwebtoken';
import crypto from 'crypto';
import rateLimit from 'express-rate-limit';
import { Config } from '../cfg/config.js';
import { apiKeyRequired } from '../middlewares/apiKeyRequired.js';
import { tokenRequired, revokedTokens } from '../middlewares/tokenRequired.js';
import { getDbConnection } from '../cfg/db.js';

const router = express.Router();

// 🧱 Limitador de intentos de login
const loginLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutos
    max: 10,
    standardHeaders: true,
    legacyHeaders: false,
    message: { resultado: 'error', mensaje: 'Demasiados intentos. Prueba más tarde.' },
});

// 🔐 Generar JWT a partir de la info devuelta por fn_login
const generateToken = ({ p_id_usuario, p_usuario, p_perfil }) => {
    const now = Math.floor(Date.now() / 1000);
    return jwt.sign(
        {
            sub: p_id_usuario,
            username: p_usuario,
            role: p_perfil,
            iat: now,
            exp: now + Config.JWT_EXPIRATION_DELTA,
            jti: crypto.randomUUID(),
            iss: Config.JWT_ISSUER,
            aud: Config.JWT_AUDIENCE,
        },
        Config.SECRET_KEY,
        { algorithm: Config.ALGORITHM }
    );
};

// 🧩 LOGIN
router.post('/login', apiKeyRequired, loginLimiter, async (req, res, next) => {
    const { username, password } = req.body;
    if (!username || !password) return res.status(400).json({ resultado: 'error', mensaje: 'Usuario y contraseña necesarios' });

    let client;
    try {
        client = await getDbConnection();
        const { rows } = await client.query('SELECT fn_login($1, $2) AS result', [username, password]);
        const result = rows?.[0]?.result;

        if (!result) return res.status(500).json({ resultado: 'error', mensaje: 'Respuesta inesperada de la base de datos' });

        const parsed = typeof result === 'string' ? JSON.parse(result) : result;

        if (parsed.resultado !== 'ok') {
            await new Promise(r => setTimeout(r, 500));
            return res.status(401).json(parsed);
        }

        const token = generateToken(parsed);
        const response = { ...parsed, token, expiresIn: Config.JWT_EXPIRATION_DELTA };

        res.json(response);
    } catch (err) {
        console.error('[Auth Error]', err.message);
        next(err);
    } finally {
        client?.release?.();
    }
});

// 🔍 VALIDAR TOKEN
router.post('/validate', apiKeyRequired, (req, res) => {
    const authHeader = req.headers['authorization'] || '';
    if (!authHeader.startsWith('Bearer ')) return res.status(400).json({ resultado: 'error', mensaje: 'Token requerido' });

    const token = authHeader.split(' ')[1];
    try {
        const payload = jwt.verify(token, Config.SECRET_KEY);
        if (revokedTokens.has(payload.jti)) return res.status(401).json({ resultado: 'error', mensaje: 'Token revocado' });
        res.json({ valid: true, user: payload });
    } catch {
        res.status(401).json({ resultado: 'error', mensaje: 'Token no valido o expirado' });
    }
});

// 👤 PERFIL
router.get('/profile', apiKeyRequired, tokenRequired, (req, res) => {
    res.json({
        resultado: 'ok',
        message: 'Perfil del usuario autenticado',
        user: req.user,
    });
});

// 🚪 LOGOUT
router.post('/logout', apiKeyRequired, tokenRequired, (req, res) => {
    revokedTokens.add(req.user.jti);
    res.json({ resultado: 'ok', message: 'Sesión cerrada correctamente' });
});

export default router;