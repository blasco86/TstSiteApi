import express from 'express';
import { clientAuthMiddleware } from '../middlewares/clientAuthMiddleware.js';
import { query } from '../cfg/db.js';

const router = express.Router();

/**
 * @swagger
 * /catalog:
 *   post:
 *     summary: 📚 Obtiene el catálogo de productos.
 *     description: Requiere JWT válido. No requiere API Key.
 * @param {object} req - El objeto de solicitud de Express.
 * @param {object} res - El objeto de respuesta de Express.
 * @param {function} next - La función next de Express.
 */
router.post('/', clientAuthMiddleware, async (req, res, next) => {
    try {
        const { rows } = await query(
            'SELECT tstsite_exe.fn_menu_catalogo_json() AS result'
        );

        if (!rows || rows.length === 0) {
            return res.status(500).json({ resultado: 'error', mensaje: 'Respuesta vacía del servidor de datos' });
        }

        const rawResult = rows[0].result;
        let catalogo;

        try {
            if (typeof rawResult === 'string') {
                catalogo = JSON.parse(rawResult);
            } else {
                catalogo = rawResult;
            }
            if (catalogo === null) catalogo = [];
        } catch (e) {
            console.error('[Catalog JSON Error]', e.message);
            return res.status(500).json({ resultado: 'error', mensaje: 'El formato del catálogo no es válido' });
        }

        if (!Array.isArray(catalogo)) {
            return res.status(500).json({ resultado: 'error', mensaje: 'El catálogo no tiene el formato de array esperado' });
        }

        return res.json({ resultado: 'ok', total_categorias: catalogo.length, catalogo });
    } catch (err) {
        console.error('[DB Catalog Error]', err.message || err);
        next(err);
    }
});

export default router;