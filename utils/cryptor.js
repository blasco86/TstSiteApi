import fs from 'fs';
import path from 'path';
import dotenv from 'dotenv';
import fernet from 'fernet';
import { fileURLToPath } from 'url';

export class Cryptor {
    constructor(keyFilePath = path.join(path.dirname(fileURLToPath(import.meta.url)), '../.env/.env.key')) {
        if (!fs.existsSync(keyFilePath)) throw new Error(`❌ Clave no encontrada: ${keyFilePath}`);
        const key = fs.readFileSync(keyFilePath, 'utf8').trim();
        if (!key) throw new Error('❌ Clave vacía');
        this.secret = new fernet.Secret(key);
    }

    isEncrypted = (val) => typeof val === 'string' && val.startsWith('ENC(') && val.endsWith(')');

    decryptValue(value) {
        if (!this.isEncrypted(value)) return value;
        try {
            const token = value.slice(4, -1);
            return new fernet.Token({ secret: this.secret, token, ttl: 0 }).decode();
        } catch {
            console.warn(`⚠️ Valor cifrado inválido: ${value}`);
            return value;
        }
    }

    decryptEnvFile(envPath) {
        const parsed = dotenv.config({ path: envPath }).parsed || {};
        return Object.fromEntries(Object.entries(parsed).map(([k, v]) => [k, this.decryptValue(v)]));
    }
}