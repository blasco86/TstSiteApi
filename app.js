import express from 'express';
import helmet from 'helmet';
import jwt from 'jsonwebtoken';
import fetch from 'node-fetch';
import rateLimit from 'express-rate-limit';
import crypto from 'crypto';
import { Config } from './cfg/config.js';
import { apiKeyRequired } from './middlewares/apiKeyRequired.js';
import { tokenRequired, revokedTokens } from './middlewares/tokenRequired.js';
import { getDbConnection } from './services/db.js';

const app = express();
app.use(express.json({ limit: '50kb' }));

// Helmet + HSTS (solo si estamos detrás de HTTPS)
app.use(helmet());
app.use((req, res, next) => {
    if (req.secure || req.headers['x-forwarded-proto'] === 'https') {
        res.setHeader('Strict-Transport-Security', 'max-age=63072000; includeSubDomains; preload');
    }
    next();
});

// ---------------- Utils ----------------
const DEFAULT_TZ = 'Europe/Madrid';
const tzRegex = /^[A-Za-z]+\/[A-Za-z_]+$/;
const allowedDatestyles = new Set(['ISO, DMY', 'ISO, MDY', 'ISO, YMD']);

async function getTimezoneFromIp(req) {
    const regionHeader = req.headers['x-region'];
    if (typeof regionHeader === 'string' && regionHeader.trim() !== '') {
        const candidate = regionHeader.trim();
        if (tzRegex.test(candidate)) return candidate;
    }

    const ip = req.headers['x-forwarded-for']?.split(',')[0]?.trim() || req.socket.remoteAddress;
    if (!ip || ['127.0.0.1', '::1'].includes(ip)) return DEFAULT_TZ;

    try {
        const res = await fetch(`https://ipapi.co/${ip}/timezone/`, { timeout: 2000 });
        const tz = res.ok ? (await res.text()).trim() : null;
        if (typeof tz === 'string' && tzRegex.test(tz)) return tz;
        return DEFAULT_TZ;
    } catch {
        return DEFAULT_TZ;
    }
}

const getDatestyleFromRegion = (region = '') => {
    const r = region.toLowerCase();
    if (r.startsWith('america/')) {
        return ['new_york', 'chicago', 'los_angeles', 'toronto'].some(c => r.includes(c))
            ? 'ISO, MDY'
            : 'ISO, DMY';
    }
    if (r.startsWith('asia/')) return 'ISO, YMD';
    return 'ISO, DMY';
};

// ---------------- JWT ----------------
const generateToken = ({ id_usuario, usuario, perfil }) => {
    const now = Math.floor(Date.now() / 1000);
    const exp = now + Config.JWT_EXPIRATION_DELTA;
    const payload = {
        sub: id_usuario,
        username: usuario,
        role: perfil,
        iat: now,
        exp,
        jti: crypto.randomUUID(),
        iss: Config.JWT_ISSUER,
        aud: Config.JWT_AUDIENCE
    };
    return jwt.sign(payload, Config.SECRET_KEY, { algorithm: Config.ALGORITHM });
};

const verifyToken = (token) => {
    try {
        return jwt.verify(token, Config.SECRET_KEY, {
            algorithms: [Config.ALGORITHM],
            issuer: Config.JWT_ISSUER,
            audience: Config.JWT_AUDIENCE
        });
    } catch (err) {
        return { error: err.name === 'TokenExpiredError' ? 'Token expirado' : 'Token inválido' };
    }
};

// ---------------- Rate limiter ----------------
const loginLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 10,
    message: { error: 'Demasiados intentos. Prueba más tarde.' }
});

// ---------------- Routes ----------------
app.post('/', apiKeyRequired, (_, res) => {
    res.json({
        message: 'Microservicio TstSite funcionando',
        version: '1.0.5',
        endpoints: ['/login', '/validate', '/profile', '/logout']
    });
});

// ---------------- Login ----------------
app.post('/login', apiKeyRequired, loginLimiter, async (req, res, next) => {
    const { username, password } = req.body;

    if (typeof username !== 'string' || typeof password !== 'string') {
        return res.status(400).json({ error: 'Username y password requeridos' });
    }

    let client;
    try {
        const region = await getTimezoneFromIp(req);
        const datestyle = getDatestyleFromRegion(region);
        client = await getDbConnection(region, datestyle);

        const { rows } = await client.query('SELECT fn_login($1, $2) AS result', [username, password]);
        const result = rows?.[0]?.result;
        if (!result) return res.status(500).json({ error: 'Respuesta inesperada de la base de datos' });

        const parsed = typeof result === 'string' ? JSON.parse(result) : result;
        if (parsed.resultado !== 'ok') {
            await new Promise((r) => setTimeout(r, 500));
            return res.status(401).json(parsed);
        }

        res.json({
            message: 'Login correcto',
            token: generateToken(parsed),
            user: {
                id: parsed.id_usuario,
                username: parsed.usuario,
                role: parsed.perfil,
                estado: parsed.estado
            },
            expires_in: Config.JWT_EXPIRATION_DELTA
        });
    } catch (e) {
        next(e);
    } finally {
        if (client) {
            try {
                await client.query('RESET ALL').catch(()=>{});
            } catch {}
            client.release();
        }
    }
});

// ---------------- Validate ----------------
app.post('/validate', apiKeyRequired, (req, res) => {
    const authHeader = req.headers['authorization'] || '';
    if (!authHeader.startsWith('Bearer ')) return res.status(400).json({ error: 'Token requerido en Authorization header' });
    const token = authHeader.split(' ')[1];
    const payload = verifyToken(token);
    if (payload.error) return res.status(401).json(payload);
    res.json({ valid: true, user: payload });
});

// ---------------- Profile ----------------
app.post('/profile', apiKeyRequired, tokenRequired, (req, res) => {
    res.json({ message: 'Perfil del usuario', user: req.user });
});

// ---------------- Logout ----------------
app.post('/logout', apiKeyRequired, tokenRequired, (req, res) => {
    const authHeader = req.headers['authorization'] || '';
    if (!authHeader.startsWith('Bearer ')) {
        return res.status(400).json({ error: 'Token requerido en Authorization header' });
    }

    const token = authHeader.split(' ')[1];
    try {
        const decoded = jwt.verify(token, Config.SECRET_KEY, {
            algorithms: [Config.ALGORITHM],
            issuer: Config.JWT_ISSUER,
            audience: Config.JWT_AUDIENCE
        });
        revokedTokens.add(decoded.jti);
        res.json({ message: 'Logout correcto. Token invalidado.' });
    } catch (err) {
        res.status(401).json({ error: 'Token inválido o expirado' });
    }
});

app.get('/favicon.ico', (_, res) => res.status(204));

// ---------------- Error handling ----------------
app.use((err, req, res, next) => {
    console.error('[Server Error]', err?.message || err);
    res.status(500).json({ error: 'Error interno del servidor' });
});

export default app;