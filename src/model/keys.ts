import {
    generatePrivateKey,
    getAccountIdFromPublic,
    getPublicFromPrivate,
    signEd25519
} from "foundry-primitives";
import * as _ from "lodash";
import { Context } from "../context";
import { ErrorCode, KeystoreError } from "../logic/error";
import { decode, encode } from "../logic/storage";
import { Key, PrivateKey, PublicKey, SecretStorage } from "../types";

export async function getKeys(context: Context): Promise<Key[]> {
    const rows: any = await context.db.get("key").value();
    return _.map(rows, (secret: SecretStorage) => secret.address) as Key[];
}

export async function getPublicKey(
    context: Context,
    params: { key: Key; passphrase: string }
): Promise<PublicKey | null> {
    const secret = await getSecretStorage(context, params);
    if (secret == null) {
        return null;
    }
    const privateKey = await decode(secret, params.passphrase);
    return getPublicFromPrivate(privateKey);
}

export function importRaw(
    context: Context,
    params: {
        privateKey: PrivateKey;
        passphrase?: string;
        meta?: string;
    }
): Promise<Key> {
    return createKeyFromPrivateKey(context, params);
}

export async function exportKey(
    context: Context,
    params: { key: Key; passphrase: string }
): Promise<SecretStorage> {
    const secret = await getSecretStorage(context, params);
    if (secret == null) {
        throw new KeystoreError(ErrorCode.NoSuchKey);
    }
    await decode(secret, params.passphrase); // Throws an error if the passphrase is incorrect.
    return secret;
}

export async function importKey(
    context: Context,
    params: { secret: SecretStorage; passphrase: string }
): Promise<Key> {
    const privateKey = await decode(params.secret, params.passphrase);
    return importRaw(context, {
        privateKey,
        passphrase: params.passphrase,
        meta: params.secret.meta
    });
}

export function createKey(
    context: Context,
    params: { passphrase?: string; meta?: string }
): Promise<Key> {
    const privateKey = generatePrivateKey();
    return createKeyFromPrivateKey(context, {
        ...params,
        privateKey
    });
}

async function createKeyFromPrivateKey(
    context: Context,
    params: {
        privateKey: PrivateKey;
        passphrase?: string;
        meta?: string;
    }
): Promise<Key> {
    const publicKey = getPublicFromPrivate(params.privateKey);
    const passphrase = params.passphrase || "";
    const meta = params.meta || "{}";

    const secret = await encode(params.privateKey, passphrase, meta);
    const rows: any = context.db.get("key");
    await rows.push(secret).write();
    return keyFromPublicKey(publicKey);
}

export function keyFromPublicKey(publicKey: PublicKey): Key {
    return getAccountIdFromPublic(publicKey);
}

export async function deleteKey(
    context: Context,
    params: { key: Key }
): Promise<boolean> {
    const secret = await getSecretStorage(context, params);
    if (secret == null) {
        return false;
    }

    await removeKey(context, params);
    return true;
}

async function getSecretStorage(
    context: Context,
    params: { key: Key }
): Promise<SecretStorage | null> {
    const collection: any = context.db.get("key");
    const secret = await collection
        .find(
            (secretStorage: SecretStorage) =>
                secretStorage.address === params.key
        )
        .value();

    if (secret == null) {
        return null;
    }
    return secret as SecretStorage;
}

async function removeKey(
    context: Context,
    params: { key: Key }
): Promise<void> {
    const collection: any = context.db.get("key");
    await collection
        .remove((secret: SecretStorage) => secret.address === params.key)
        .write();
}

export async function exportRawKey(
    context: Context,
    params: { key: Key; passphrase: string }
) {
    const secret = await getSecretStorage(context, params);
    if (secret == null) {
        throw new KeystoreError(ErrorCode.NoSuchKey);
    }

    return decode(secret, params.passphrase);
}

export async function sign(
    context: Context,
    params: {
        key: Key;
        message: string;
        passphrase: string;
    }
): Promise<string> {
    const secret = await getSecretStorage(context, params);
    if (secret == null) {
        throw new KeystoreError(ErrorCode.NoSuchKey);
    }

    const privateKey = await decode(secret, params.passphrase);
    return signEd25519(params.message, privateKey);
}

export async function getMeta(
    context: Context,
    params: { key: Key }
): Promise<string> {
    const secret = await getSecretStorage(context, params);
    if (secret == null) {
        throw new KeystoreError(ErrorCode.NoSuchKey);
    }
    return secret.meta;
}

export function save(context: Context): Promise<SecretStorage[]> {
    return context.db.get("key").value();
}

export function load(context: Context, value: SecretStorage[]): Promise<void> {
    return context.db.set("key", value).write();
}

export async function clear(context: Context): Promise<void> {
    await context.db.unset("key").write();
}
