import { CCKey } from "../index";

describe("cckey", () => {
    let cckey: CCKey;

    beforeEach(async () => {
        cckey = await CCKey.create({ dbType: "in-memory" });
    });

    afterEach(async () => {
        cckey.close();
    });

    test("saveLoad", async () => {
        const passphrase = "satoshi";
        const Key1 = await cckey.keystore.createKey({ passphrase });
        const Key2 = await cckey.keystore.createKey({ passphrase });
        await cckey.setMeta("new meta data");
        const saveData = await cckey.save();
        const newCckey = await CCKey.create({ dbType: "in-memory" });
        await newCckey.load(saveData);

        expect(await newCckey.keystore.getKeys()).toEqual([Key1, Key2]);
        expect(await newCckey.getMeta()).toBe("new meta data");
    });

    test("clear removes key", async () => {
        const createdKey = await cckey.keystore.createKey({
            passphrase: "satoshi"
        });
        expect(await cckey.keystore.getKeys()).toEqual([createdKey]);
        await cckey.clear();
        expect(await cckey.keystore.getKeys()).toEqual([]);
    });
});
