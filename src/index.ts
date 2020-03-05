import { closeContext, Context, createContext, storageExist } from "./context";
import { initialize as dbInitialize } from "./model/initialize";
import * as Keys from "./model/keys";

import { Key, PrivateKey, PublicKey, SecretStorage } from "./types";

export { SecretStorage };

export interface KeyStore {
    getKeys(): Promise<Key[]>;
    importRaw(params: {
        privateKey: PrivateKey;
        passphrase?: string;
        meta?: string;
    }): Promise<Key>;
    exportKey(params: { key: Key; passphrase: string }): Promise<SecretStorage>;
    importKey(params: {
        secret: SecretStorage;
        passphrase: string;
    }): Promise<Key>;
    exportRawKey(params: { key: Key; passphrase: string }): Promise<PrivateKey>;
    getPublicKey(params: {
        key: Key;
        passphrase: string;
    }): Promise<PublicKey | null>;
    createKey(params: { passphrase?: string; meta?: string }): Promise<Key>;
    deleteKey(params: { key: Key }): Promise<boolean>;
    sign(params: {
        key: Key;
        message: string;
        passphrase: string;
    }): Promise<string>;

    getMeta(params: { key: Key }): Promise<string>;

    save(): Promise<SecretStorage[]>;
    load(value: SecretStorage[]): Promise<void>;

    clear(): Promise<void>;
}

class CCKey {
    public static CCKey = CCKey;

    public static async create(
        params: {
            dbType?: string;
            dbPath?: string;
        } = {}
    ): Promise<CCKey> {
        const dbType = params.dbType || "persistent";
        const dbPath = params.dbPath || "keystore.db";
        const context = await createContext({
            dbType,
            dbPath
        });
        return new CCKey(context);
    }
    public static async exist(
        params: {
            dbType?: string;
            dbPath?: string;
        } = {}
    ): Promise<boolean> {
        const dbType = params.dbType || "persistent";
        const dbPath = params.dbPath || "keystore.db";
        return storageExist({ dbType, dbPath });
    }

    public keystore: KeyStore = createKeyStore(this.context);

    private constructor(private context: Context) {}

    public getMeta(): Promise<string> {
        return this.context.db.get("meta").value();
    }

    public setMeta(meta: string): Promise<string> {
        return this.context.db.set("meta", meta).write();
    }

    public close(): Promise<void> {
        return closeContext(this.context);
    }

    public async save(): Promise<string> {
        const meta = await this.getMeta();
        const keystore = await this.keystore.save();

        return JSON.stringify({
            meta,
            keystore
        });
    }

    public async load(value: string): Promise<void> {
        const data = JSON.parse(value);
        await this.setMeta(data.meta);

        await this.keystore.load(data.keystore);
    }

    public async clear(): Promise<void> {
        await this.context.db.unset("meta").write();
        await this.keystore.clear();
        await dbInitialize(this.context.db);
    }
}

function createKeyStore(context: Context): KeyStore {
    return {
        getKeys: () => {
            return Keys.getKeys(context);
        },

        importRaw: (params: {
            privateKey: PrivateKey;
            passphrase?: string;
            meta?: string;
        }) => {
            return Keys.importRaw(context, params);
        },

        exportKey: (params: { key: Key; passphrase: string }) => {
            return Keys.exportKey(context, params);
        },

        importKey: (params: { secret: SecretStorage; passphrase: string }) => {
            return Keys.importKey(context, params);
        },

        exportRawKey: (params: { key: Key; passphrase: string }) => {
            return Keys.exportRawKey(context, params);
        },

        getPublicKey: (params: { key: Key; passphrase: string }) => {
            return Keys.getPublicKey(context, params);
        },

        createKey: (params: { passphrase?: string; meta?: string }) => {
            return Keys.createKey(context, params);
        },

        deleteKey: (params: { key: Key }) => {
            return Keys.deleteKey(context, params);
        },

        sign: (params: { key: Key; message: string; passphrase: string }) => {
            return Keys.sign(context, params);
        },

        getMeta: (params: { key: Key }) => {
            return Keys.getMeta(context, params);
        },

        save: () => {
            return Keys.save(context);
        },

        load: (value: SecretStorage[]) => {
            return Keys.load(context, value);
        },

        clear: () => {
            return Keys.clear(context);
        }
    };
}

export { CCKey };

module.exports = CCKey;
