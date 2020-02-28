import { CCKey } from "../index";
import { keyFromPublicKey } from "../model/keys";

describe("keystore", () => {
    let cckey: CCKey;
    beforeEach(async () => {
        cckey = await CCKey.create({ dbType: "in-memory" });
    });

    afterEach(async () => {
        cckey.close();
    });

    test("importRaw", async () => {
        const privateKey =
            "2c459a04538af99de4b5150ccd213392ea683cc33e6e28a4dfbf8d2c5706032a40200442f046f5012df6d6acf8105be68278a6d3bd631603ab86fed89cdf9901";
        const key = await cckey.keystore.importRaw({
            privateKey,
            passphrase: "satoshi"
        });
        const publicKey =
            "40200442f046f5012df6d6acf8105be68278a6d3bd631603ab86fed89cdf9901";
        expect(key).toBe(keyFromPublicKey(publicKey));
    });

    test("importKey", async () => {
        const secret = {
            crypto: {
                ciphertext:
                    "b3dc8f6d26b0d1da16f96c74a7f069392a9ac2cdbfaa0a16842928fc224225e0c158308becefa06feb4513327ba2712cb52180928d8001bee2465389a5537a42",
                cipherparams: { iv: "02ce853ed0b18fb8b59b814462182183" },
                cipher: "aes-128-ctr",
                kdf: "pbkdf2",
                kdfparams: {
                    dklen: 32,
                    salt:
                        "4d1f44a96bff17f13652daae92de36ffca5462b2175e13dae2912130e7186b91",
                    c: 10240,
                    prf: "hmac-sha256"
                },
                mac:
                    "b662cf0be237b7515156f0ff5bf1d4b2cfdf148e261c0c43201e116923ecde3f"
            },
            id: "14650255-9cc3-6ef2-fd75-12a08127c6e7",
            version: 3,
            meta: "some meta info"
        };
        const key = await cckey.keystore.importKey({
            secret,
            passphrase: "satoshi"
        });
        const publicKey =
            "40200442f046f5012df6d6acf8105be68278a6d3bd631603ab86fed89cdf9901";
        expect(key).toBe(keyFromPublicKey(publicKey));
    });

    test("exportKey", async () => {
        const privateKey =
            "2c459a04538af99de4b5150ccd213392ea683cc33e6e28a4dfbf8d2c5706032a40200442f046f5012df6d6acf8105be68278a6d3bd631603ab86fed89cdf9901";
        const key = await cckey.keystore.importRaw({
            privateKey,
            passphrase: "satoshi"
        });
        const storage = await cckey.keystore.exportKey({
            key,
            passphrase: "satoshi"
        });
        expect(storage).toHaveProperty("crypto");
        expect(storage.crypto).toHaveProperty("cipher");
        expect(storage.crypto).toHaveProperty("cipherparams");
        expect(storage.crypto).toHaveProperty("ciphertext");
        expect(storage.crypto).toHaveProperty("kdf");
        expect(storage.crypto).toHaveProperty("kdfparams");
        expect(storage.crypto).toHaveProperty("mac");
        expect(storage).toHaveProperty("meta");
    });

    test("importKeyWithMeta", async () => {
        const secret = {
            crypto: {
                ciphertext:
                    "b3dc8f6d26b0d1da16f96c74a7f069392a9ac2cdbfaa0a16842928fc224225e0c158308becefa06feb4513327ba2712cb52180928d8001bee2465389a5537a42",
                cipherparams: { iv: "02ce853ed0b18fb8b59b814462182183" },
                cipher: "aes-128-ctr",
                kdf: "pbkdf2",
                kdfparams: {
                    dklen: 32,
                    salt:
                        "4d1f44a96bff17f13652daae92de36ffca5462b2175e13dae2912130e7186b91",
                    c: 10240,
                    prf: "hmac-sha256"
                },
                mac:
                    "b662cf0be237b7515156f0ff5bf1d4b2cfdf148e261c0c43201e116923ecde3f"
            },
            id: "14650255-9cc3-6ef2-fd75-12a08127c6e7",
            version: 3,
            meta: "some meta info"
        };
        const key = await cckey.keystore.importKey({
            secret,
            passphrase: "satoshi"
        });
        const storage = await cckey.keystore.exportKey({
            key,
            passphrase: "satoshi"
        });
        expect(storage.meta).toBe("some meta info");
    });

    test("exportRawKey", async () => {
        const privateKey =
            "2c459a04538af99de4b5150ccd213392ea683cc33e6e28a4dfbf8d2c5706032a40200442f046f5012df6d6acf8105be68278a6d3bd631603ab86fed89cdf9901";
        const key = await cckey.keystore.importRaw({
            privateKey,
            passphrase: "satoshi"
        });
        const exportedPrivateKey = await cckey.keystore.exportRawKey({
            key,
            passphrase: "satoshi"
        });
        expect(exportedPrivateKey).toBe(privateKey);
    });

    test("createKey", async () => {
        const key = await cckey.keystore.createKey({ passphrase: "satoshi" });
        expect(key).toBeTruthy();
        expect(key.length).toBe(40);
    });

    test("createKey with an empty passphrase", async () => {
        const key = await cckey.keystore.createKey({ passphrase: "" });
        expect(key).toBeTruthy();
        expect(key.length).toBe(40);
    });

    test("getKeys", async () => {
        let keys = await cckey.keystore.getKeys();
        expect(keys.length).toBe(0);

        const key1 = await cckey.keystore.createKey({ passphrase: "satoshi" });
        const key2 = await cckey.keystore.createKey({ passphrase: "satoshi" });
        keys = await cckey.keystore.getKeys();
        expect(keys).toEqual([key1, key2]);
    });

    test("deleteKey", async () => {
        const passphrase = "satoshi";
        const key1 = await cckey.keystore.createKey({ passphrase });
        const key2 = await cckey.keystore.createKey({ passphrase });
        const originPublicKey2 = await cckey.keystore.getPublicKey({
            key: key2,
            passphrase
        });
        await cckey.keystore.deleteKey({ key: key1 });

        const keys = await cckey.keystore.getKeys();
        expect(keys).toEqual([key2]);

        const publicKey1 = await cckey.keystore.getPublicKey({
            key: key1,
            passphrase
        });
        const publicKey2 = await cckey.keystore.getPublicKey({
            key: key2,
            passphrase
        });
        expect(publicKey1).toEqual(null);
        expect(publicKey2).toEqual(originPublicKey2);
    });

    test("exportAndImport", async () => {
        const createdKey = await cckey.keystore.createKey({
            passphrase: "satoshi"
        });
        expect(createdKey).toBeTruthy();
        expect(createdKey.length).toBe(40);

        const secret = await cckey.keystore.exportKey({
            key: createdKey,
            passphrase: "satoshi"
        });
        expect(secret).toHaveProperty("crypto");
        expect(secret.crypto).toHaveProperty("cipher");
        expect(secret.crypto).toHaveProperty("cipherparams");
        expect(secret.crypto).toHaveProperty("ciphertext");
        expect(secret.crypto).toHaveProperty("kdf");
        expect(secret.crypto).toHaveProperty("kdfparams");
        expect(secret.crypto).toHaveProperty("mac");

        const importedKey = await cckey.keystore.importKey({
            secret,
            passphrase: "satoshi"
        });
        expect(createdKey).toBe(importedKey);
    });

    test("createWithoutMeta", async () => {
        const createdKey = await cckey.keystore.createKey({
            passphrase: "satoshi"
        });
        const meta = await cckey.keystore.getMeta({ key: createdKey });
        expect(meta).toBe("{}");
    });

    test("createWithMeta", async () => {
        const createdKey = await cckey.keystore.createKey({
            passphrase: "satoshi",
            meta: '{"name": "test"}'
        });
        const meta = await cckey.keystore.getMeta({ key: createdKey });
        expect(meta).toBe('{"name": "test"}');
    });

    test("clear removes key", async () => {
        const createdKey = await cckey.keystore.createKey({
            passphrase: "satoshi"
        });
        expect(await cckey.keystore.getKeys()).toEqual([createdKey]);
        await cckey.keystore.clear();
        expect(await cckey.keystore.getKeys()).toEqual([]);
    });

    test("getPublicKey", async () => {
        const privateKey =
            "2c459a04538af99de4b5150ccd213392ea683cc33e6e28a4dfbf8d2c5706032a40200442f046f5012df6d6acf8105be68278a6d3bd631603ab86fed89cdf9901";
        const expectedPublicKey =
            "40200442f046f5012df6d6acf8105be68278a6d3bd631603ab86fed89cdf9901";
        const passphrase = "satoshi";
        const key = await cckey.keystore.importRaw({
            privateKey,
            passphrase
        });
        const publicKey = await cckey.keystore.getPublicKey({
            key,
            passphrase
        });
        if (publicKey == null) {
            throw Error("Cannot get a public key");
        }
        expect(publicKey).toBe(expectedPublicKey);
        expect(publicKey.length).toBe(64);
    });
});
