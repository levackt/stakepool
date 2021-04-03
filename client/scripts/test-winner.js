#!/usr/bin/env node

const { Encoding, fromUtf8 } = require("@iov/encoding");
const { getDelegationShares } = require('../src/staking');
const { getSigningClient } = require('../src/secret');

/* eslint-disable @typescript-eslint/camelcase */
const fs = require("fs");
require("dotenv").config();
const { promisify } = require('util')
const sleep = promisify(setTimeout)

async function main() {

  const contractAddress = "secret10a68eweaycm0smn0gj8qjsaut07c4ucrk3smw8";

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

  let result = await client.queryContractSmart(contractAddress, { token_info: {  } });
  console.log("token_info: ", result)

  result = await client.queryContractSmart(contractAddress, { lottery_info: {  } });
  console.log("lottery_info: ", result)

  // query delegations
  const startDelegations = await getDelegationShares(contractAddress)
  console.log("Delegation shares: ", startDelegations);

  //  create viewing key
  const entropy = "Something random";

  let handleMsg = { create_viewing_key: {entropy: entropy} };
  console.log('Creating viewing key');
  response = await client.execute(contractAddress, handleMsg);
  console.log('response: ', response);

  // Convert the UTF8 bytes to String, before parsing the JSON for the api key.
  const apiKey = JSON.parse(fromUtf8(response.data)).create_viewing_key.key;

  response = await client2.execute(contractAddress, handleMsg);
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
  const balanceQuery2 = {
      balance: {
          key: apiKey2,
          address: user2.address
      }
  };
  let balance = await client.queryContractSmart(contractAddress, balanceQuery);
  console.log('user1 token balance: ', balance);
  balance = await client2.queryContractSmart(contractAddress, balanceQuery2);
  console.log('user2 token balance: ', balance);

  result = await client.queryContractSmart(contractAddress, { token_info: {  } });
  console.log("token_info: ", result);

  const delegationShares = await getDelegationShares(contractAddress)
  console.log("Delegation shares: ", delegationShares);

  result = await client2.execute(contractAddress, {
    claim_rewards: { }
  });
  console.log("claim_rewards result: ", result)
  console.log("claim_rewards result: ", JSON.parse(fromUtf8(result.data)))

  // contract should have the reward balance now
  console.log("Contract Account: ", await client.getAccount(contractAddress));

  // check both accounts for a win tx
  result = await client.queryContractSmart(contractAddress, { transaction_history: {
       address: user1.address,
       key: apiKey,
       page: 0,
       page_size: 10,
     }
   });
  console.log("user1 txs: ", result.transaction_history.txs);

  result = await client.queryContractSmart(contractAddress, { transaction_history: {
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
    console.info("done");
    process.exit(0);
  },
  error => {
    console.error(error);
    process.exit(1);
  },
);

