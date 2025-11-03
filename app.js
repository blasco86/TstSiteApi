import express from 'express';
import helmet from 'helmet';
import jwt from 'jsonwebtoken';
import fetch from 'node-fetch';
import { Config } from './cfg/config.js';
import { apiKeyRequired } from './middlewares/apiKeyRequired.js';
import { tokenRequired } from './middlewares/tokenRequired.js';
import { getDbConnection } from './services/db.js';

const app = express();
app.use(express.json({ limit: '50kb' }));
app.use(helmet());

// ---------------- Utils ----------------
const DEFAULT_TZ = 'Europe/Madrid';

async function getTimezoneFromIp(req) {
    const regionHeader = req.headers['x-region'];
    if (regionHeader && regionHeader.toLowerCase() !== 'undefined') {
        return regionHeader.trim();
    }

    const ip = req.headers['x-forwarded-for']?.split(',')[0]?.trim() || req.socket.remoteAddress;
    if (!ip || ['127.0.0.1', '::1'].includes(ip)) return DEFAULT_TZ;

    try {
        const res = await fetch(`https://ipapi.co/${ip}/timezone/`, { timeout: 2000 });
        const tz = res.ok ? (await res.text()).trim() : null;
        return tz && tz.toLowerCase() !== 'undefined' ? tz : DEFAULT_TZ;
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
    return jwt.sign({ sub: id_usuario, username: usuario, role: perfil, iat: now, exp }, Config.SECRET_KEY, {
        algorithm: Config.ALGORITHM
    });
};

const verifyToken = (token) => {
    try {
        return jwt.verify(token, Config.SECRET_KEY, { algorithms: [Config.ALGORITHM] });
    } catch (err) {
        return { error: err.name === 'TokenExpiredError' ? 'Token expirado' : 'Token inválido' };
    }
};

// ---------------- Routes ----------------
app.post('/', apiKeyRequired, (_, res) => {
    res.json({
        message: 'Microservicio TstSite funcionando',
        version: '1.0.4',
        endpoints: ['/login', '/validate', '/profile']
    });
});

app.post('/login', apiKeyRequired, async (req, res, next) => {
    const { username, password } = req.body;

    if (typeof username !== 'string' || typeof password !== 'string') {
        return res.status(400).json({ error: 'Username y password requeridos' });
    }

    let client;
    try {
        const region = await getTimezoneFromIp(req);
        client = await getDbConnection(region, getDatestyleFromRegion(region));

        const { rows } = await client.query('SELECT fn_login($1, $2) AS result', [username.trim(), password]);
        const result = rows?.[0]?.result;
        if (!result) return res.status(500).json({ error: 'Respuesta inesperada de la base de datos' });

        const parsed = typeof result === 'string' ? JSON.parse(result) : result;
        if (parsed.resultado !== 'ok') {
            // ⚡ Breve retardo para mitigar ataques de fuerza bruta
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
        if (client) client.release();
    }
});

app.post('/validate', apiKeyRequired, (req, res) => {
    const { token } = req.body || {};
    if (!token) return res.status(400).json({ error: 'Token requerido' });
    const payload = verifyToken(token);
    if (payload.error) return res.status(401).json(payload);
    res.json({ valid: true, user: payload });
});

app.post('/profile', apiKeyRequired, tokenRequired, (req, res) => {
    res.json({ message: 'Perfil del usuario', user: req.user });
});

app.get('/favicon.ico', (_, res) => res.status(204));

// ---------------- Error handling ----------------
app.use((err, req, res, next) => {
    console.error('[Server Error]', err);
    res.status(500).json({ error: 'Error interno del servidor' });
});

export default app;