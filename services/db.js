import pkg from 'pg';
import { Config } from '../cfg/config.js';
const { Pool } = pkg;

const pool = new Pool(Config.DB_CONFIG);

/**
 * Retorna una conexión PostgreSQL configurada según región y formato de fecha.
 */
export async function getDbConnection(region = 'Europe/Madrid', datestyle = 'ISO, DMY') {
    const client = await pool.connect();
    try {
        await client.query(`SET TimeZone = '${region}'`);
        await client.query(`SET DateStyle = '${datestyle}'`);
        return client;
    } catch (err) {
        console.error('[DB CONFIG ERROR]', err.message);
        client.release();
        throw err;
    }
}