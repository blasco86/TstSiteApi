import express from 'express';
import { tokenRequired } from '../middlewares/tokenRequired.js';
import { apiKeyRequired } from '../middlewares/apiKeyRequired.js';
import { getDbConnection } from '../cfg/db.js'; // o '../cfg/db.js' según tu proyecto

const router = express.Router();

/**
 * 🚀 Catálogo de productos
 * GET /catalog
 * Devuelve la estructura completa del catálogo: tipos, subtipos y productos
 */
router.post('/', apiKeyRequired, tokenRequired, async (req, res, next) => {
    let client;
    try {
        client = await getDbConnection();

        const { rows } = await client.query(
            'SELECT tstsite_exe.fn_menu_catalogo_json() AS result'
        );

        if (!rows || rows.length === 0) {
            return res
                .status(500)
                .json({ resultado: 'error', mensaje: 'Respuesta vacía de la base de datos' });
        }

        const rawResult = rows[0].result;

        // Si la función está declarada como RETURNS jsonb, pg normalmente ya te da un objeto/array JS
        let catalogo;

        if (rawResult && typeof rawResult === 'object') {
            catalogo = rawResult;
        } else {
            // Fallback defensivo por si algún día cambias a text/JSON
            try {
                catalogo = JSON.parse(rawResult);
            } catch (e) {
                console.error('[Catalog JSON Error]', e.message);
                return res
                    .status(500)
                    .json({ resultado: 'error', mensaje: 'Formato de catálogo inválido' });
            }
        }

        // Por si por algún motivo no es array
        if (!Array.isArray(catalogo)) {
            return res
                .status(500)
                .json({ resultado: 'error', mensaje: 'El catálogo no es un array' });
        }

        return res.json({
            resultado: 'ok',
            total_categorias: catalogo.length,
            catalogo,
        });
    } catch (err) {
        console.error('[DB Catalog Error]', err.message || err);
        next(err);
    } finally {
        if (client) {
            try {
                client.release();
            } catch {
                // ignoramos errores al liberar
            }
        }
    }
});

export default router;