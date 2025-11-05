import pkg from 'pg';
import { Config } from '../cfg/config.js';
const { Pool } = pkg;

const pool = new Pool(Config.DB_CONFIG);

const tzRegex = /^[A-Za-z]+\/[A-Za-z_]+$/;
const allowedDatestyles = new Set(['ISO, DMY', 'ISO, MDY', 'ISO, YMD']);

export async function getDbConnection(region = 'Europe/Madrid', datestyle = 'ISO, DMY') {
    if (!tzRegex.test(region)) {
        console.warn('[DB] Region inválida, forzando DEFAULT_TZ');
        region = 'Europe/Madrid';
    }
    if (!allowedDatestyles.has(datestyle)) datestyle = 'ISO, DMY';

    const client = await pool.connect();
    try {
        // Ya no iniciamos una transacción, aplicamos ajustes directos
        await client.query(`SET TimeZone = '${region}'`);
        await client.query(`SET DateStyle = '${datestyle}'`);

        // Cada query que hagas con este cliente será autocommit
        return client;
    } catch (err) {
        client.release();
        throw err;
    }
}
