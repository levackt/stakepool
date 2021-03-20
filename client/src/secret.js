const { Encoding, fromUtf8 } = require("@iov/encoding");
const { coin } = require("@cosmjs/sdk38");
const { getValidators, getDelegationShares } = require('../src/staking');

const { EnigmaUtils, Secp256k1Pen, CosmWasmClient, SigningCosmWasmClient,
    pubkeyToAddress, encodeSecp256k1Pubkey } = require("secretjs");
const fs = require("fs");
require("dotenv").config();
const httpUrl = process.env.SECRET_REST_URL;

const customFees = {
  upload: {
    amount: [{ amount: "2000000", denom: "uscrt" }],
    gas: "3000000",
  },
  init: {
    amount: [{ amount: "500000", denom: "uscrt" }],
    gas: "500000",
  },
  exec: {
    amount: [{ amount: "300000", denom: "uscrt" }],
    gas: "300000",
  },
  send: {
    amount: [{ amount: "80000", denom: "uscrt" }],
    gas: "80000",
  },
}


module.exports = {
    getClient: function () {
        return new CosmWasmClient(httpUrl);
    },
    getSigningClient: async function (mnemonic) {
        const signingPen = await Secp256k1Pen.fromMnemonic(mnemonic);
        const myWalletAddress = pubkeyToAddress(
            encodeSecp256k1Pubkey(signingPen.pubkey),
            "secret"
        );

        const txEncryptionSeed = EnigmaUtils.GenerateNewSeed();
        const client = new SigningCosmWasmClient(
            httpUrl,
            myWalletAddress,
            (signBytes) => signingPen.sign(signBytes),
            txEncryptionSeed, customFees
        );
        return client;
    }
}
