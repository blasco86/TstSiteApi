import pkg from 'pg';
import { Config } from './config.js';
const { Pool } = pkg;

/**
 * 🏊‍♂️ Pool de conexiones a la base de datos.
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
 * getDbConnection
 * 🤝 Obtiene una conexión a la base de datos.
 * @param {string} region - La zona horaria para la conexión.
 * @param {string} datestyle - El estilo de fecha para la conexión.
 * @returns {Promise<import('pg').PoolClient>} - Una promesa que se resuelve con un cliente de la base de datos.
 */
export async function getDbConnection(region = 'Europe/Madrid', datestyle = 'ISO, DMY') {
    if (!tzRegex.test(region)) {
        region = 'Europe/Madrid';
    }
    if (!allowedDatestyles.has(datestyle)) datestyle = 'ISO, DMY';
    const client = await pool.connect();
    try {
        await client.query(`SET TimeZone = '${region}'`);
        await client.query(`SET DateStyle = '${datestyle}'`);
        return client;
    } catch (err) {
        client.release();
        throw err;
    }
}