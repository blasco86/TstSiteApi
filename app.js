import express from 'express';
import helmet from 'helmet';
import rateLimit from 'express-rate-limit';
import cors from 'cors';

import { Config } from './cfg/config.js';
import { decryptBodyMiddleware, encryptResponseMiddleware } from './utils/cryptoPayload.js';
import authRoutes from './routes/auth.js';
import userRoutes from './routes/users.js';
import catalogRoutes from './routes/catalog.js';

const app = express();

// 🔗 CORS
const allowedOrigins = [
    'http://localhost:8080',
    'http://localhost:8081',
    'http://localhost:3001',
    'http://localhost',
    'http://127.0.0.1',
    'http://127.0.0.1:8080',
    'http://127.0.0.1:8081',
    'https://tstsite.alwaysdata.net',
];
app.use(cors({
    origin: (origin, callback) => {
        // Permitir peticiones sin origin (como Postman, curl, apps nativas)
        if (!origin) {
            // console.log('[CORS] ✅ Petición sin origin permitida');
            return callback(null, true);
        }
        if (allowedOrigins.includes(origin)) {
            // console.log('[CORS] ✅ Origen permitido:', origin);
            return callback(null, true);
        }
        // console.warn('[CORS] ❌ Origen bloqueado:', origin);
        return callback(new Error('Origen no permitido por CORS: ' + origin));
    },
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'x-api-key', 'Authorization'],
    credentials: true
}));

// ⚙️ Middlewares generales
app.use(express.json({ limit: '50kb' }));
// 🔐 Middleware de desencriptación de requests (ANTES de las rutas)
app.use(decryptBodyMiddleware);
// 🔐 Middleware de encriptación de responses (ANTES de las rutas)
app.use(encryptResponseMiddleware);
app.use(helmet());

// 🚦 Límite de tasa global
const globalLimiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 200 });
app.use(globalLimiter);

// 🗺️ Rutas
app.get('/', (_, res) => res.json({
    resultado: 'ok',
    mensaje: 'API TstSite operativo',
    version: '2.3',
    encryption_enabled: Config.ENCRYPTION_ENABLED,
    allow_unencrypted: Config.ALLOW_UNENCRYPTED
}));
app.use('/auth', authRoutes);
app.use('/users', userRoutes);
app.use('/catalog', catalogRoutes);

// ⭐ Favicon
app.get('/favicon.ico', (_, res) => res.status(204));

// ⚠️ Manejo de errores
app.use((err, req, res, next) => {
    console.error('[Server Error]', err?.message || err);
    res.status(500).json({ resultado: 'error', mensaje: 'Error interno del servidor' });
});

export default app;