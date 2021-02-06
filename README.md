# Secret pool

Staking secret contract, where the rewards are allocated to a random winner based on the weight of their stake.

## Build
```sh
 cargo wasm
```

## Start server

```sh
  docker run -it --rm \
 -p 26657:26657 -p 26656:26656 -p 1337:1337 \
 -v $(pwd):/root/code \
 --name secretdev enigmampc/secret-network-sw-dev
```

## ENV Config
```sh
cp client/.env-defaults client/.env

Add your deployment account details to .env
```

## Fund deployer account
```sh
./client/scripts/fund_accounts.sh
```

## Test contract deploy, staking etc with SecretJS
```sh
cd client
yarn
node scripts/test-contract.js
```