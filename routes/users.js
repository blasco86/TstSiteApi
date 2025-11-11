import express from 'express';
import { tokenRequired } from '../middlewares/tokenRequired.js';
import { apiKeyRequired } from '../middlewares/apiKeyRequired.js';
import { getDbConnection } from '../cfg/db.js';

const router = express.Router();

// 🚀 Gestión de usuarios
router.post('/:accion', apiKeyRequired, tokenRequired, async (req, res, next) => {
    const { accion } = req.params;
    const datos = req.body;

    let client;
    try {
        client = await getDbConnection();
        const { rows } = await client.query(
            'SELECT tstsite_exe.fn_gestion_usuario($1, $2) AS result',
            [accion, JSON.stringify(datos)]
        );

        const result = typeof rows[0].result === 'string' ? JSON.parse(rows[0].result) : rows[0].result;
        res.json(result);
    } catch (err) {
        console.error('[DB Error]', err.message);
        next(err);
    } finally {
        client?.release();
    }
});

export default router;