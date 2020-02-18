Foundry keystore [![Build Status](https://travis-ci.org/CodeChain-io/foundry-keystore-js.svg?branch=master)](https://travis-ci.org/CodeChain-io/foundry-keystore-js)
===================

Foundry keystore is a private key management library. It saves Foundry's account address safely in a disk. If you want to manage Foundry keys using nodejs, you should use this.

Example
-----------

```js
var CCKey = require('foundry-keystore');

async function example() {
  const cckey = await CCKey.create();
  const savedKeys = await cckey.platform.getKeys();
  console.dir(savedKeys);
  await cckey.platform.createKey({ passphrase: "my password" });
  const savedKeys_ = await cckey.platform.getKeys();
  console.dir(savedKeys_);

  await cckey.close();
};
example();

```

How your private key is saved
-------------------

We use a JSON file to save an encrypted private key. You can find the file in `./keystore.db`
