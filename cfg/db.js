import pkg from 'pg';
import { Config } from './config.js';
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
        await client.query(`SET TimeZone = '${region}'`);
        await client.query(`SET DateStyle = '${datestyle}'`);

        return client;
    } catch (err) {
        client.release();
        throw err;
    }
}
