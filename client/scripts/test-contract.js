#!/usr/bin/env node

const { Encoding, fromUtf8 } = require("@iov/encoding");
const { coin } = require("@cosmjs/sdk38");
const { getValidators, getDelegationShares } = require('../src/staking');
const { getSigningClient } = require('../src/secret');

/* eslint-disable @typescript-eslint/camelcase */
const fs = require("fs");
require("dotenv").config();
const { promisify } = require('util')
const sleep = promisify(setTimeout)

async function main() {

  let validator;

  const user1 = {
    mnemonic: process.env.MNEMONIC,
    address: process.env.ADDRESS,
  };

  const user2 = {
    mnemonic: process.env.MNEMONIC2,
    address: process.env.ADDRESS2,
  };



  const client = await getSigningClient(user1.mnemonic);
  const client2 = await getSigningClient(user2.mnemonic);
  const account = await client.getAccount();
  const account2 = await client2.getAccount();
  console.log("Deployer account: ", account);

  //upload staking contract
  wasm = fs.readFileSync(__dirname + "/../../contract.wasm");
  uploadReceipt = await client.upload(wasm, {})
  console.info(`Staking upload succeeded. Receipt: ${JSON.stringify(uploadReceipt)}`);
  codeId = uploadReceipt.codeId;

  // init staking
  const codes = await client.getCodes();
  label = "steaksauce" + (codes.length + 2);

  const initMsg = {
    "name": "SECRETSTEAKSAUCE",
    "symbol":"SSS",
    "decimals":6,
    "prng_seed": Buffer.from("hello world").toString('base64'),
    "validator": validator,
    "config": {
      "public_total_supply":false,
      "enable_deposit":true,
      "enable_redeem":true,
      "enable_mint":true,
      "enable_burn":false,
      "validator": validator
    }
  }
  console.log(`initMsg=${JSON.stringify(initMsg)}`)

  const stakingInit = await client.instantiate(codeId, initMsg, label);
  console.info(`Staking contract instantiated at ${stakingInit.contractAddress}`);

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

