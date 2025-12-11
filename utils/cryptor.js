import fs from 'fs';
import path from 'path';
import dotenv from 'dotenv';
import fernet from 'fernet';
import { fileURLToPath } from 'url';

/**
 * 🔐 Clase para encriptar y desencriptar valores.
 */
export class Cryptor {
    /**
     * @param {string} keyFilePath - La ruta al archivo que contiene la clave de encriptación.
     */
    constructor(keyFilePath = path.join(path.dirname(fileURLToPath(import.meta.url)), '../.env/.env.key')) {
        if (!fs.existsSync(keyFilePath)) throw new Error(`❌ No se ha encontrado el archivo de clave: ${keyFilePath}`);
        const key = fs.readFileSync(keyFilePath, 'utf8').trim();
        if (!key) throw new Error('❌ El archivo de clave está vacío');
        this.secret = new fernet.Secret(key);
    }

    /**
     * isEncrypted
     * 🤔 Verifica si un valor está encriptado.
     * @param {string} val - El valor a verificar.
     * @returns {boolean} - `true` si el valor está encriptado, `false` en caso contrario.
     */
    isEncrypted = (val) => typeof val === 'string' && val.startsWith('ENC(') && val.endsWith(')');

    /**
     * decryptValue
     * 🔓 Desencripta un valor.
     * @param {string} value - El valor a desencriptar.
     * @returns {string} - El valor desencriptado.
     */
    decryptValue(value) {
        if (!this.isEncrypted(value)) return value;
        try {
            const token = value.slice(4, -1);
            return new fernet.Token({ secret: this.secret, token, ttl: 0 }).decode();
        } catch (err) {
            console.error(`❌ Fallo al descifrar el valor: ${value}`);
            throw new Error(`No se pudo descifrar un valor de configuración. Verifique que la clave en .env.key sea la correcta. Error original: ${err.message}`);
        }
    }

    /**
     * decryptEnvFile
     * 📄 Desencripta un archivo de entorno.
     * @param {string} envPath - La ruta al archivo de entorno.
     * @returns {object} - Un objeto con los valores desencriptados.
     */
    decryptEnvFile(envPath) {
        const parsed = dotenv.config({ path: envPath }).parsed || {};
        return Object.fromEntries(Object.entries(parsed).map(([k, v]) => [k, this.decryptValue(v)]));
    }

    /**
     * encryptValue
     * 🔒 Encripta un valor usando la clave de Fernet.
     * @param {string} value - El valor a encriptar.
     * @returns {string} El valor encriptado con el formato ENC(...).
     */
    encryptValue(value) {
        if (this.isEncrypted(value)) {
            console.warn('⚠️ El valor ya parece estar cifrado. No se volverá a cifrar.');
            return value;
        }
        const token = new fernet.Token({ secret: this.secret });
        const encryptedToken = token.encode(value);
        return `ENC(${encryptedToken})`;
    }
}