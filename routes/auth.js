import express from 'express';
import jwt from 'jsonwebtoken';
import crypto from 'crypto';
import rateLimit from 'express-rate-limit';
import { Config } from '../cfg/config.js';
import { clientAuthMiddleware } from '../middlewares/clientAuthMiddleware.js';
import { revokedTokens } from '../middlewares/tokenRequired.js';
import { query } from '../cfg/db.js';

const router = express.Router();

/**
 * 🧱 Limitador de intentos de login para prevenir ataques de fuerza bruta.
 * El login es público (sin API Key), así que el rate limit es la primera defensa.
 */
const loginLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutos
    max: 10,
    standardHeaders: true,
    legacyHeaders: false,
    message: { resultado: 'error', mensaje: 'Demasiados intentos de acceso. Inténtelo de nuevo más tarde.' },
});

/**
 * generateToken
 * 🔐 Genera un token JWT a partir de la información del usuario.
 * @param {object} user - Objeto con datos del usuario.
 * @param {number} user.p_id_usuario - ID del usuario.
 * @param {string} user.p_usuario - Nombre de usuario.
 * @param {string} user.p_perfil - Perfil del usuario.
 */
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

/**
 * @swagger
 * /auth/login:
 *   post:
 *     summary: 🔑 Inicia sesión en la aplicación.
 *     description: >
 *       Endpoint público. Protegido por CORS estricto + rate limiting.
 *       No requiere API Key. Devuelve un JWT para usar en el resto de endpoints.
 * @param {object} req - El objeto de solicitud de Express.
 * @param {object} res - El objeto de respuesta de Express.
 * @param {function} next - La función next de Express.
 */
router.post('/login', loginLimiter, async (req, res, next) => {
    const { username, password } = req.body;
    if (!username || !password) {
        return res.status(400).json({ resultado: 'error', mensaje: 'El nombre de usuario y la contraseña son obligatorios' });
    }

    try {
        const { rows } = await query('SELECT tstsite_exe.fn_login($1, $2) AS result', [username, password]);
        const result = rows?.[0]?.result;

        if (!result) {
            return res.status(500).json({ resultado: 'error', mensaje: 'Respuesta inesperada del servidor de datos' });
        }

        const parsed = typeof result === 'string' ? JSON.parse(result) : result;

        if (parsed.resultado !== 'ok') {
            await new Promise(r => setTimeout(r, 500)); // anti-timing attack
            return res.status(401).json(parsed);
        }

        const token = generateToken(parsed);
        const response = { ...parsed, token, expiresIn: Config.JWT_EXPIRATION_DELTA };

        res.json(response);
    } catch (err) {
        console.error('[Auth Error]', err.message);
        next(err);
    }
});

/**
 * @swagger
 * /auth/validate:
 *   post:
 *     summary: 🔍 Valida un token JWT.
 * @param {object} req - El objeto de solicitud de Express.
 * @param {object} res - El objeto de respuesta de Express.
 */
router.post('/validate', clientAuthMiddleware, (req, res) => {
    res.json({ valid: true, user: req.user });
});

/**
 * @swagger
 * /auth/profile:
 *   post:
 *     summary: 👤 Obtiene el perfil del usuario autenticado.
 * @param {object} req - El objeto de solicitud de Express.
 * @param {object} res - El objeto de respuesta de Express.
 */
router.post('/profile', clientAuthMiddleware, (req, res) => {
    res.json({
        resultado: 'ok',
        message: 'Perfil del usuario autenticado',
        user: req.user,
    });
});

/**
 * @swagger
 * /auth/logout:
 *   post:
 *     summary: 🚪 Cierra la sesión del usuario.
 * @param {object} req - El objeto de solicitud de Express.
 * @param {object} res - El objeto de respuesta de Express.
 */
router.post('/logout', clientAuthMiddleware, (req, res) => {
    if (req.user?.jti) {
        revokedTokens.add(req.user.jti);
    }
    res.json({ resultado: 'ok', message: 'La sesión se ha cerrado correctamente' });
});

export default router;