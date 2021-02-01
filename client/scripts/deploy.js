#!/usr/bin/env node

const { Encoding, fromUtf8 } = require("@iov/encoding");
const { coin } = require("@cosmjs/sdk38");
const http = require('http');

/* eslint-disable @typescript-eslint/camelcase */
const { EnigmaUtils, Secp256k1Pen, SigningCosmWasmClient, pubkeyToAddress, encodeSecp256k1Pubkey } = require("secretjs");
const fs = require("fs");
const { Console } = require("console");
require("dotenv").config();

const httpUrl = process.env.SECRET_REST_URL;

const account = {
  mnemonic:
  process.env.MNEMONIC,
  address: process.env.ADDRESS,
};

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
    amount: [{ amount: "500000", denom: "uscrt" }],
    gas: "500000",
  },
  send: {
    amount: [{ amount: "80000", denom: "uscrt" }],
    gas: "80000",
  },
}


async function main() {

  let validator;

  // query the validators
  http.get(httpUrl + '/staking/validators', (resp) => {
    let data = '';

    resp.on('data', (chunk) => {
      data += chunk;
    });

    resp.on('end', () => {
      // use the first validator
      validator = JSON.parse(data).result[0].operator_address;
      console.log("Validator: ", validator);
    });

  }).on("error", (err) => {
    console.log("Error querying validators: " + err.message);
    process.exit(0)
  });

  const signingPen = await Secp256k1Pen.fromMnemonic(account.mnemonic);
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

  const acc = await client.getAccount()
  console.log(`wallet=${myWalletAddress}`);
  account.balance = acc.balance[0].amount;

  console.log(`balance=${myWalletAddress}, ${account.balance}`);

  //upload staking contract
  console.log("Dir: ", __dirname);
  wasm = fs.readFileSync(__dirname + "/../../contract.wasm");
  uploadReceipt = await client.upload(wasm, {})
  console.info(`Staking upload succeeded. Receipt: ${JSON.stringify(uploadReceipt)}`);
  codeId = uploadReceipt.codeId;

  // init staking
  const codes = await client.getCodes();
  label = "steaksauce" + (codes.length + 2);

  const initMsg = {
    "name": "STEAKSAUCE",
    "symbol":"SSS",
    "decimals":6,
    "prng_seed": Buffer.from("hello world").toString('base64'),
    "validator": validator,
    "config": {
      "public_total_supply":true,
      "enable_deposit":true,
      "enable_redeem":true,
      "enable_mint":true,
      "enable_burn":true,
      "validator": validator
    }
  }
  console.log(`initMsg=${JSON.stringify(initMsg)}`)

  const stakingInit = await client.instantiate(codeId, initMsg, label);
  console.info(`Staking contract instantiated at ${stakingInit.contractAddress}`);

  console.log('querying minters')
  let result = await client.queryContractSmart(stakingInit.contractAddress, { minters: {  } });
  console.log(result)

  result = await client.queryContractSmart(stakingInit.contractAddress, { token_info: {  } });
  console.log("token_info: ", result)
//  deposit stake
  const amount = 1000000
  const denom = "uscrt";
  const stake = [coin(amount, denom)];
  console.log(`stake`)
  console.log(stake)
  result = await client.execute(stakingInit.contractAddress, {
    deposit: {}
  }, "", stake);
  console.log("Deposit result: ", JSON.parse(fromUtf8(result.data)))

  // result = await client.execute(stakingInit.contractAddress, { query_balances: {  } });
  // console.log("Balances:", result)

  result = await client.queryContractSmart(stakingInit.contractAddress, { token_info: {  } });
  console.log("token_info: ", result)
}

main().then(
  () => {
    console.info("contract deployed.");
    process.exit(0);
  },
  error => {
    console.error(error);
    process.exit(1);
  },
);

