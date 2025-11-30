import express from 'express';
import helmet from 'helmet';
import rateLimit from 'express-rate-limit';
import cors from 'cors';

import authRoutes from './routes/auth.js';
import userRoutes from './routes/users.js';
import catalogRoutes from './routes/catalog.js';

const app = express();

// --- CORS ---
const allowedOrigins = [
    'http://localhost:8081',
    'http://localhost',
    'http://127.0.0.1',
    'https://tstsite.alwaysdata.net',
];

app.use(cors({
    origin: (origin, callback) => {
        // origin puede ser undefined (Postman, curl, etc.)
        if (!origin || allowedOrigins.includes(origin)) {
            return callback(null, true);
        }
        console.warn('[CORS] Origen bloqueado:', origin);
        return callback(new Error('Origen no permitido por CORS: ' + origin));
    },
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'x-api-key'],
}));

// Soporte a cookies o auth basada en sesión:
app.use(cors({
    origin: allowedOrigins,
    credentials: true,
//   ...
}));

// --- Middlewares generales ---
app.use(express.json({ limit: '50kb' }));
app.use(helmet());

// Rate limit global opcional
const globalLimiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 200 });
app.use(globalLimiter);

// --- Rutas ---
app.get('/', (_, res) => res.json({ resultado: 'ok', mensaje: 'API TstSite funcionando', version: '2.0' }));
app.use('/auth', authRoutes);
app.use('/users', userRoutes);
app.use('/catalog', catalogRoutes);

// Favicon
app.get('/favicon.ico', (_, res) => res.status(204));

// Manejo de errores
app.use((err, req, res) => {
    console.error('[Server Error]', err?.message || err);
    res.status(500).json({ resultado: 'error', mensaje: 'Error interno del servidor' });
});

export default app;