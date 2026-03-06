import express from 'express';
import { clientAuthMiddleware } from '../middlewares/clientAuthMiddleware.js';
import { query } from '../cfg/db.js';

const router = express.Router();

/**
 * @swagger
 * /users/{accion}:
 *   post:
 *     summary: 👥 Gestión de usuarios.
 *     description: Requiere JWT válido. No requiere API Key.
 * @param {object} req - El objeto de solicitud de Express.
 * @param {object} res - El objeto de respuesta de Express.
 * @param {function} next - La función next de Express.
 */
router.post('/:accion', clientAuthMiddleware, async (req, res, next) => {
    const { accion } = req.params;
    const datos = req.body;

    try {
        const { rows } = await query(
            'SELECT tstsite_exe.fn_gestion_usuario($1, $2) AS result',
            [accion, JSON.stringify(datos)]
        );

        const result = typeof rows[0].result === 'string' ? JSON.parse(rows[0].result) : rows[0].result;
        res.json(result);
    } catch (err) {
        console.error('[DB Error]', err.message);
        next(err);
    }
});

export default router;