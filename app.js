import express from 'express';
import helmet from 'helmet';
import rateLimit from 'express-rate-limit';
import cors from 'cors';
import { decryptBodyMiddleware, encryptResponseMiddleware } from './utils/cryptoPayload.js';
import authRoutes from './routes/auth.js';
import userRoutes from './routes/users.js';
import catalogRoutes from './routes/catalog.js';

/**
 * 🚀 Inicialización de la aplicación Express.
 */
const app = express();

/**
 * 🔗 Configuración de CORS.
 * @type {string[]}
 */
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
        if (!origin || allowedOrigins.includes(origin)) {
            return callback(null, true);
        }
        return callback(new Error('Origen no permitido por el CORS: ' + origin));
    },
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'x-api-key', 'Authorization'],
    credentials: true
}));

/**
 * ⚙️ Middlewares generales de la aplicación.
 */
app.use(express.json({ limit: '50kb' }));
app.use(decryptBodyMiddleware);
app.use(encryptResponseMiddleware);

/**
 * 🛡️ Configuración de seguridad de cabeceras HTTP con Helmet.
 * Esto ayuda a proteger la aplicación de vulnerabilidades web conocidas.
 */
app.use(helmet({
    contentSecurityPolicy: {
        directives: {
            defaultSrc: ["'self'"], // Solo permite contenido del mismo origen.
            scriptSrc: ["'self'"], // Solo scripts del mismo origen.
            styleSrc: ["'self'"],
            imgSrc: ["'self'"],
            fontSrc: ["'self'"],
            objectSrc: ["'none'"], // No permite plugins como Flash.
            upgradeInsecureRequests: [], // Pide a los navegadores que usen HTTPS.
        },
    },
    frameguard: { action: 'deny' }, // Evita que la página se muestre en un <iframe>.
    hsts: { maxAge: 31536000, includeSubDomains: true, preload: true }, // Fuerza HTTPS por un año.
    noSniff: true, // Evita que el navegador "adivine" el tipo de contenido.
    xssFilter: true, // Activa el filtro de XSS de los navegadores.
}));


/**
 * 🚦 Límite de tasa global para prevenir ataques de fuerza bruta.
 */
const globalLimiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 200 });
app.use(globalLimiter);

/**
 * 🗺️ Definición de las rutas de la API.
 */
app.get('/', (_, res) => res.json({
    resultado: 'ok',
    mensaje: 'API TstSite operativa',
    version: '2.5'
}));
app.use('/auth', authRoutes);
app.use('/users', userRoutes);
app.use('/catalog', catalogRoutes);

/**
 * ⭐ Ruta para el favicon.
 */
app.get('/favicon.ico', (_, res) => res.status(204));

/**
 * ⚠️ Middleware para el manejo de errores.
 */
app.use((err, req, res, next) => {
    console.error('[Server Error]', err?.message || err);
    res.status(500).json({ resultado: 'error', mensaje: 'Error interno en el servidor' });
});

export default app;