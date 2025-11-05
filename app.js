import express from 'express';
import helmet from 'helmet';
import rateLimit from 'express-rate-limit';
import authRoutes from './routes/auth.js';
import userRoutes from './routes/users.js';

const app = express();
app.use(express.json({ limit: '50kb' }));
app.use(helmet());

// Rate limit global opcional
const globalLimiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 200 });
app.use(globalLimiter);

// Rutas
app.get('/', (_, res) => res.json({ message: 'API TstSite funcionando', version: '2.0' }));
app.use('/auth', authRoutes);
app.use('/users', userRoutes);

// Favicon
app.get('/favicon.ico', (_, res) => res.status(204));

// Manejo de errores
app.use((err, req, res, next) => {
    console.error('[Server Error]', err?.message || err);
    res.status(500).json({ error: 'Error interno del servidor' });
});

export default app;