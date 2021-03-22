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

  // query the validators and take the first
  const validators = await getValidators();
  validator = validators[0].operator_address;
  console.log("Validator: ", validator);

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
      "public_total_supply":true,
      "enable_deposit":true,
      "enable_redeem":false,
      "enable_mint":true,
      "enable_burn":false,
      "validator": validator
    }
  }
  console.log(`initMsg=${JSON.stringify(initMsg)}`)

  const stakingInit = await client.instantiate(codeId, initMsg, label);
  console.info(`Staking contract instantiated at ${stakingInit.contractAddress}`);

  let result = await client.queryContractSmart(stakingInit.contractAddress, { minters: {  } });
  console.log("Minters: ", result)

  result = await client.queryContractSmart(stakingInit.contractAddress, { token_info: {  } });
  console.log("token_info: ", result)

  result = await client.queryContractSmart(stakingInit.contractAddress, { lottery_info: {  } });
  console.log("lottery_info: ", result)

  // query delegations
  const startDelegations = await getDelegationShares(stakingInit.contractAddress)
  console.log("Delegation shares: ", startDelegations);

  //  create viewing key
  const entropy = "Something random";

  let handleMsg = { create_viewing_key: {entropy: entropy} };
  console.log('Creating viewing key');
  response = await client.execute(stakingInit.contractAddress, handleMsg);
  console.log('response: ', response);

  // Convert the UTF8 bytes to String, before parsing the JSON for the api key.
  const apiKey = JSON.parse(fromUtf8(response.data)).create_viewing_key.key;

  response = await client2.execute(stakingInit.contractAddress, handleMsg);
  console.log('response: ', response);

  // Convert the UTF8 bytes to String, before parsing the JSON for the api key.
  const apiKey2 = JSON.parse(fromUtf8(response.data)).create_viewing_key.key;

  // Query balance with the api key
  const balanceQuery = {
      balance: {
          key: apiKey,
          address: user1.address
      }
  };
  let balance = await client.queryContractSmart(stakingInit.contractAddress, balanceQuery);
  console.log('My token balance: ', balance);

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

  result = await client.queryContractSmart(stakingInit.contractAddress, { token_info: {  } });
  console.log("token_info: ", result);

  // query txs
  result = await client.queryContractSmart(stakingInit.contractAddress, { transaction_history: {
       address: user1.address,
       key: apiKey,
       page: 0,
       page_size: 10,
     }
   });
  console.log("txs: ", result.transaction_history.txs);

  // equal deposit from account2
  result = await client2.execute(stakingInit.contractAddress, {
      deposit: {}
  }, "", stake);

  result = await client.queryContractSmart(stakingInit.contractAddress, { token_info: {  } });
  console.log("token_info: ", result);

  const delegationShares = await getDelegationShares(stakingInit.contractAddress)
  console.log("Delegation shares: ", delegationShares);

  let blockHeight = await (await client.getBlock()).header.height

  const rewardBlock = blockHeight + 2;
  while (blockHeight < rewardBlock) {
    await sleep(6000)
    blockHeight = await (await client.getBlock()).header.height
  }

  result = await client.execute(stakingInit.contractAddress, {
    claim_rewards: { }
  });
  console.log("claim_rewards result: ", result)
  console.log("claim_rewards result: ", JSON.parse(fromUtf8(result.data)))

  // contract should have the reward balance now
  console.log("Contract Account: ", await client.getAccount(stakingInit.contractAddress));

  // check both accounts for a win tx
  result = await client.queryContractSmart(stakingInit.contractAddress, { transaction_history: {
       address: user1.address,
       key: apiKey,
       page: 0,
       page_size: 10,
     }
   });
  console.log("user1 txs: ", result.transaction_history.txs);

  result = await client.queryContractSmart(stakingInit.contractAddress, { transaction_history: {
       address: user2.address,
       key: apiKey2,
       page: 0,
       page_size: 10,
     }
   });
  console.log("user2 txs: ", result.transaction_history.txs);
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

