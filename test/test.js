const argon2 = require("argon2");
const { assert } = require("chai");
const { instantiate } = require("js-nacl");

async function getNaCl() {
  return new Promise(resolve =>
    instantiate(naclInstance => resolve(naclInstance))
  );
}

describe("NaCl", async function testNaCl() {
  const password = "Correct Horse Battery Staple";
  const keyParams = {
    salt: Buffer.from(
      "045295c54ac968c5340a7da1334d0cc5c388d4fba010d5b35156603379344b2d",
      "hex"
    ),
    time: 3,
    mem: 32 * 1024,
    hashLen: 32
  };
  const expectedHashHex =
    "bb180e164564b225be71b1335fea063589ef51dbb3bf2fc54d28e69a965e1a44";

  it("should derive buffer using node-argon2", async function testNodeArgon2() {
  	// As a test case, let's verify that we get a specific value using an existing
		// library first.
    const hashBuf = await argon2.hash(password, {
      timeCost: keyParams.time,
      memoryCost: keyParams.mem,
      parallelism: 1,
      type: argon2.argon2id,
      hashLength: keyParams.hashLen,
      salt: keyParams.salt,
      raw: true
    });
    assert.equal(hashBuf.toString("hex"), expectedHashHex);
  });

  it("should define necessary constants", async function checkNaClConstants() {
  	// If appropriate? The C library seems to expose these, at any rate.
		// What their type should be, or whether the JS API should just take
		// strings or whatever, I do not know.
    const naCl = await getNaCl();
    assert.isDefined(
      naCl.crypto_pwhash_argon2i,
      "constant for Argon2i should be defined"
    );
    assert.isDefined(
      naCl.crypto_pwhash_argon2d,
      "constant for Argon2d should be defined"
    );
    assert.isDefined(
      naCl.crypto_pwhash_argon2id,
      "constant for Argon2id should be defined"
    );
  });

  it("should derive buffer using js-nacl", async function testNaClArgon2() {
  	// I would expect NaCl to yield the same result as node-argon2
    const naCl = await getNaCl();
    const hashBuf = naCl.crypto_pwhash(
      password,
      keyParams.salt,
      keyParams.time,
      keyParams.mem,
      naCl.crypto_pwhash_argon2id
    );
    assert.equal(hashBuf.toString("hex"), expectedHashHex);
  });

  it("should generate secret key", async function testNaClSecretKeyGen() {
  	// For secretbox encryption, the upstream lib exposes a generator function.
		// I'm not really sure what it does...
    const naCl = await getNaCl();
    assert.isFunction(
      naCl.crypto_secretbox_keygen,
      "crypto_secretbox_keygen should be defined"
    );
    assert(
      naCl.crypto_secretbox_keygen() instanceof Uint8Array,
      "crypto_secretbox_keygen() should return a Uint8Array"
    );
  });
});
