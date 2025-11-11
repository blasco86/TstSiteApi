import express from 'express';
import jwt from 'jsonwebtoken';
import crypto from 'crypto';
import rateLimit from 'express-rate-limit';
import { Config } from '../cfg/config.js';
import { apiKeyRequired } from '../middlewares/apiKeyRequired.js';
import { tokenRequired, revokedTokens } from '../middlewares/tokenRequired.js';
import { getDbConnection } from '../cfg/db.js';

const router = express.Router();

/* 🧱 LIMITADOR DE INTENTOS DE LOGIN (previene fuerza bruta) */
const loginLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutos
    max: 10, // máximo 10 intentos
    standardHeaders: true,
    legacyHeaders: false,
    message: { error: 'Demasiados intentos. Prueba más tarde.' },
});

/* 🔐 GENERAR TOKEN JWT (con buena práctica de claims) */
const generateToken = ({ id_usuario, usuario, perfil }) => {
    const now = Math.floor(Date.now() / 1000);
    return jwt.sign(
        {
            sub: id_usuario, // subject (id del usuario)
            username: usuario,
            role: perfil,
            iat: now, // issued at
            exp: now + Config.JWT_EXPIRATION_DELTA, // expiración
            jti: crypto.randomUUID(), // identificador único
            iss: Config.JWT_ISSUER, // emisor
            aud: Config.JWT_AUDIENCE, // audiencia
        },
        Config.SECRET_KEY,
        { algorithm: Config.ALGORITHM }
    );
};

/* 🧩 LOGIN */
router.post('/login', apiKeyRequired, loginLimiter, async (req, res, next) => {
    const { username, password } = req.body;
    if (!username || !password) {
        return res.status(400).json({ error: 'Usuario y contraseña necesarios' });
    }

    let client;
    try {
        client = await getDbConnection();

        // Llamar la función de login
        const { rows } = await client.query('SELECT fn_login($1, $2) AS result', [username, password]);
        const result = rows?.[0]?.result;

        if (!result) {
            return res.status(500).json({ error: 'Respuesta inesperada de la base de datos' });
        }

        // 🚫 No uses JSON.parse() — el campo ya es objeto JSONB
        const parsed = typeof result === 'string' ? JSON.parse(result) : result;

        if (parsed.resultado !== 'ok') {
            // retraso intencionado (protege contra brute force timing)
            await new Promise(r => setTimeout(r, 500));
            return res.status(401).json(parsed);
        }

        const token = generateToken(parsed);

        res.json({
            message: 'Acceso correcto',
            token,
            user: {
                id: parsed.id_usuario,
                username: parsed.usuario,
                role: parsed.perfil,
                estado: parsed.estado,
                permisos: parsed.permisos,
            },
            expires_in: Config.JWT_EXPIRATION_DELTA,
        });
    } catch (err) {
        console.error('[Auth Error]', err.message);
        next(err);
    } finally {
        // 🔒 asegura liberar conexión siempre
        if (client) client.release?.();
    }
});

/* 🔍 VALIDAR TOKEN */
router.post('/validate', apiKeyRequired, (req, res) => {
    const authHeader = req.headers['authorization'] || '';
    if (!authHeader.startsWith('Bearer ')) {
        return res.status(400).json({ error: 'Token requerido' });
    }

    const token = authHeader.split(' ')[1];
    try {
        const payload = jwt.verify(token, Config.SECRET_KEY);
        if (revokedTokens.has(payload.jti)) {
            return res.status(401).json({ error: 'Token revocado. Inicia sesión nuevamente.' });
        }
        res.json({ valid: true, user: payload });
    } catch (err) {
        res.status(401).json({ error: 'Token inválido o expirado' });
    }
});

/* 👤 PERFIL */
router.get('/profile', apiKeyRequired, tokenRequired, async (req, res) => {
    res.json({
        message: 'Perfil del usuario autenticado',
        user: req.user,
    });
});

/* 🚪 LOGOUT */
router.post('/logout', apiKeyRequired, tokenRequired, (req, res) => {
    revokedTokens.add(req.user.jti);
    res.json({ message: 'Sesión cerrada correctamente' });
});

export default router;