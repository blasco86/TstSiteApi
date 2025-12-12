import express from 'express';
import { tokenRequired } from '../middlewares/tokenRequired.js';
import { apiKeyRequired } from '../middlewares/apiKeyRequired.js';
import { query } from '../cfg/db.js';

const router = express.Router();

/**
 * @swagger
 * /catalog:
 *   post:
 *     summary: 🚀 Obtiene el catálogo de productos.
 *     responses:
 *       200:
 *         description: Catálogo de productos.
 *       500:
 *         description: Error en el servidor.
 */
router.post('/', apiKeyRequired, tokenRequired, async (req, res, next) => {
    try {
        const { rows } = await query(
            'SELECT tstsite_exe.fn_menu_catalogo_json() AS result'
        );

        if (!rows || rows.length === 0) {
            return res
                .status(500)
                .json({ resultado: 'error', mensaje: 'Respuesta vacía del servidor de datos' });
        }

        const rawResult = rows[0].result;
        let catalogo;

        try {
            // El resultado de la base de datos (rawResult) puede ser:
            // 1. Un objeto/array ya parseado por `pg` (si la columna es de tipo json/jsonb).
            // 2. Un string en formato JSON (si la columna es de tipo text).
            // 3. `null` (si la función de base de datos devuelve NULL).
            if (typeof rawResult === 'string') {
                catalogo = JSON.parse(rawResult);
            } else {
                catalogo = rawResult;
            }

            // Si el resultado es `null` (directamente de la BD o de JSON.parse('null')),
            // lo normalizamos a un array vacío para mantener la consistencia.
            if (catalogo === null) {
                catalogo = [];
            }
        } catch (e) {
            console.error('[Catalog JSON Error]', e.message);
            return res
                .status(500)
                .json({ resultado: 'error', mensaje: 'El formato del catálogo no es válido' });
        }

        // Verificamos que el catálogo sea un array.
        // Si la función de la BD devolviera un objeto JSON `{...}` en lugar de un array `[...]`,
        // esta validación fallaría, lo cual es el comportamiento esperado.
        if (!Array.isArray(catalogo)) {
            return res
                .status(500)
                .json({ resultado: 'error', mensaje: 'El catálogo no tiene el formato de array esperado' });
        }

        return res.json({
            resultado: 'ok',
            total_categorias: catalogo.length,
            catalogo,
        });
    } catch (err) {
        console.error('[DB Catalog Error]', err.message || err);
        next(err);
    }
});

export default router;