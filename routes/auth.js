import express from 'express';
import jwt from 'jsonwebtoken';
import crypto from 'crypto';
import rateLimit from 'express-rate-limit';
import { Config } from '../cfg/config.js';
import { apiKeyRequired } from '../middlewares/apiKeyRequired.js';
import { tokenRequired, revokedTokens } from '../middlewares/tokenRequired.js';
import { query } from '../cfg/db.js';

const router = express.Router();

/**
 * 🧱 Limitador de intentos de login para prevenir ataques de fuerza bruta.
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
 * @param {object} userInfo - La información del usuario.
 * @returns {string} - El token JWT generado.
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
 *     summary: 🧩 Inicia sesión en la aplicación.
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               username:
 *                 type: string
 *               password:
 *                 type: string
 *     responses:
 *       200:
 *         description: Inicio de sesión exitoso.
 *       400:
 *         description: Usuario y contraseña necesarios.
 *       401:
 *         description: Credenciales incorrectas.
 */
router.post('/login', apiKeyRequired, loginLimiter, async (req, res, next) => {
    const { username, password } = req.body;
    if (!username || !password) return res.status(400).json({ resultado: 'error', mensaje: 'El nombre de usuario y la contraseña son obligatorios' });

    try {
        const { rows } = await query('SELECT tstsite_exe.fn_login($1, $2) AS result', [username, password]);
        const result = rows?.[0]?.result;

        if (!result) return res.status(500).json({ resultado: 'error', mensaje: 'Respuesta inesperada del servidor de datos' });

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
    }
});

/**
 * @swagger
 * /auth/validate:
 *   post:
 *     summary: 🔍 Valida un token JWT.
 *     responses:
 *       200:
 *         description: Token válido.
 *       401:
 *         description: Token no válido o expirado.
 */
router.post('/validate', apiKeyRequired, (req, res) => {
    const authHeader = req.headers['authorization'] || '';
    if (!authHeader.startsWith('Bearer ')) return res.status(400).json({ resultado: 'error', mensaje: 'Se requiere un token de autenticación' });

    const token = authHeader.split(' ')[1];
    try {
        const payload = jwt.verify(token, Config.SECRET_KEY);
        if (revokedTokens.has(payload.jti)) return res.status(401).json({ resultado: 'error', mensaje: 'El token ha sido revocado' });
        res.json({ valid: true, user: payload });
    } catch {
        res.status(401).json({ resultado: 'error', mensaje: 'El token no es válido o ha expirado' });
    }
});

/**
 * @swagger
 * /auth/profile:
 *   get:
 *     summary: 👤 Obtiene el perfil del usuario autenticado.
 *     responses:
 *       200:
 *         description: Perfil del usuario.
 *       401:
 *         description: No autorizado.
 */
router.get('/profile', apiKeyRequired, tokenRequired, (req, res) => {
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
 *     responses:
 *       200:
 *         description: Sesión cerrada correctamente.
 *       401:
 *         description: No autorizado.
 */
router.post('/logout', apiKeyRequired, tokenRequired, (req, res) => {
    revokedTokens.add(req.user.jti);
    res.json({ resultado: 'ok', message: 'La sesión se ha cerrado correctamente' });
});

export default router;