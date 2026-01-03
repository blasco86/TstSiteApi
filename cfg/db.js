import pkg from 'pg';
import { Config } from './config.js';
const { Pool } = pkg;

/**
 * 🏊‍♂️ Pool de conexiones a la base de datos.
 * @type {import('pg').Pool}
 */
const pool = new Pool(Config.DB_CONFIG);

/**
 * 🌍 Expresión regular para validar la zona horaria.
 * @type {RegExp}
 */
const tzRegex = /^[A-Za-z]+\/[A-Za-z_]+$/;

/**
 * 📅 Estilos de fecha permitidos.
 * @type {Set<string>}
 */
const allowedDatestyles = new Set(['ISO, DMY', 'ISO, MDY', 'ISO, YMD']);

/**
 * query
 * 🚀 Ejecuta una consulta en la base de datos de forma segura, gestionando la conexión automáticamente.
 * @param {string} text - La consulta SQL a ejecutar.
 * @param {Array} [params] - Los parámetros para la consulta.
 * @param {object} [options] - Opciones adicionales como la región o el estilo de fecha.
 * @param {string} [options.region='Europe/Madrid'] - La zona horaria para la conexión.
 * @param {string} [options.datestyle='ISO, DMY'] - El estilo de fecha para la conexión.
 * @returns {Promise<import('pg').QueryResult>} - Una promesa que se resuelve con el resultado de la consulta.
 */
export async function query(text, params, options = {}) {
    let { region = 'Europe/Madrid', datestyle = 'ISO, DMY' } = options;

    if (!tzRegex.test(region)) {
        region = 'Europe/Madrid';
    }
    if (!allowedDatestyles.has(datestyle)) {
        datestyle = 'ISO, DMY';
    }

    const client = await pool.connect();
    try {
        await client.query(`SET TimeZone = '${region}'`);
        await client.query(`SET DateStyle = '${datestyle}'`);
        return await client.query(text, params);
    } finally {
        // 🤫 Nos aseguramos de que la conexión SIEMPRE se libere.
        client.release();
    }
}