import express from 'express';
import { tokenRequired } from '../middlewares/tokenRequired.js';
import { apiKeyRequired } from '../middlewares/apiKeyRequired.js';
import { query } from '../cfg/db.js';

const router = express.Router();

/**
 * @swagger
 * /users/{accion}:
 *   post:
 *     summary: 🚀 Gestión de usuarios.
 *     parameters:
 *       - in: path
 *         name: accion
 *         required: true
 *         schema:
 *           type: string
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *     responses:
 *       200:
 *         description: Operación realizada con éxito.
 *       400:
 *         description: Error en la solicitud.
 *       500:
 *         description: Error en el servidor.
 */
router.post('/:accion', apiKeyRequired, tokenRequired, async (req, res, next) => {
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