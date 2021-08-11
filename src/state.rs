use cosmwasm_std::{
    Api, CanonicalAddr, Coin, HumanAddr, ReadonlyStorage, StdError, StdResult, Storage, Uint128,
};
use cosmwasm_storage::{singleton, singleton_read, PrefixedStorage,
    ReadonlyPrefixedStorage, ReadonlySingleton, Singleton,
};
// use rust_decimal::Decimal;
use std::any::type_name;
use std::convert::TryFrom;

use secret_toolkit::{
    serialization::Json,
    storage::{AppendStore, AppendStoreMut, TypedStore, TypedStoreMut},
};

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::msg::{status_level_to_u8, u8_to_status_level, ContractStatusLevel};
use crate::utils::{bytes_to_u128, bytes_to_u32};
use crate::viewing_key::ViewingKey;
use serde::de::DeserializeOwned;

pub static CONFIG_KEY: &[u8] = b"config";
pub static LOG_KEY: &[u8] = b"anodalog";
pub static LOTTERY_KEY: &[u8] = b"lottery";
pub static LAST_LOTTERY_KEY: &[u8] = b"lastlottery";
pub static ROUND_KEY: &[u8] = b"round";


pub const KEY_CONSTANTS: &[u8] = b"constants";
pub const KEY_TOTAL_SUPPLY: &[u8] = b"total_supply";
pub const KEY_CONTRACT_STATUS: &[u8] = b"contract_status";

pub const KEY_ENTROPY: &[u8] = b"entropy";
pub const KEY_ENTRIES: &[u8] = b"entries";

pub const PREFIX_CONFIG: &[u8] = b"config";
pub const PREFIX_LOTTERY: &[u8] = b"lottery";
pub const PREFIX_BALANCES: &[u8] = b"balances";
pub const PREFIX_ALLOWANCES: &[u8] = b"allowances";
pub const PREFIX_VIEW_KEY: &[u8] = b"viewingkey";
pub const PREFIX_RECEIVERS: &[u8] = b"receivers";
pub const VALIDATOR_SET_KEY: &[u8] = b"validator_set";


// Config

#[derive(Serialize, Debug, Deserialize, Clone, PartialEq, JsonSchema)]
pub struct Constants {
    pub admin: HumanAddr,
    pub denom: String,
    pub prng_seed: Vec<u8>,
    // privacy configuration
    pub total_supply_is_public: bool,
    pub deposit_is_enabled: bool,
    // is redeem enabled
    pub withdraw_is_enabled: bool,

}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
pub struct Lottery {
    pub entries: Vec<(CanonicalAddr, Uint128,u64)>,
    pub entropy: Vec<u8>,
    pub seed: Vec<u8>,
    pub duration: u64,
    pub start_height: u64,
    pub end_height: u64,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct RoundStruct {
    pub pending_staking_rewards: Uint128, // will get the rewards coming from the deposit | will be sent when next deposit comes
}

pub fn round<S: Storage>(storage: &mut S) -> Singleton<S, RoundStruct> {
    singleton(storage, ROUND_KEY)
}
pub fn round_read<S: Storage>(storage: &S) -> ReadonlySingleton<S, RoundStruct> {
    singleton_read(storage, ROUND_KEY)
}

pub fn lottery<S: Storage>(storage: &mut S) -> Singleton<S, Lottery> {
    singleton(storage, LOTTERY_KEY)
}

pub fn lottery_read<S: Storage>(storage: &S) -> ReadonlySingleton<S, Lottery> {
    singleton_read(storage, LOTTERY_KEY)
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
pub struct LastLotteryResults {
    pub winner : HumanAddr,
    pub winning_rewards: Uint128,
    pub number_of_entries: Uint128,
}
pub fn last_lottery_results<S: Storage>(storage: &mut S) -> Singleton<S, LastLotteryResults> {
    singleton(storage, LAST_LOTTERY_KEY)
}

pub fn last_lottery_results_read<S: Storage>(storage: &S) -> ReadonlySingleton<S, LastLotteryResults> {
    singleton_read(storage, LAST_LOTTERY_KEY)
}



pub struct ReadonlyConfig<'a, S: ReadonlyStorage> {
    storage: ReadonlyPrefixedStorage<'a, S>,
}

impl<'a, S: ReadonlyStorage> ReadonlyConfig<'a, S> {
    pub fn from_storage(storage: &'a S) -> Self {
        Self {
            storage: ReadonlyPrefixedStorage::new(PREFIX_CONFIG, storage),
        }
    }

    fn as_readonly(&self) -> ReadonlyConfigImpl<ReadonlyPrefixedStorage<S>> {
        ReadonlyConfigImpl(&self.storage)
    }

    pub fn constants(&self) -> StdResult<Constants> {
        self.as_readonly().constants()
    }

    pub fn total_supply(&self) -> u128 {
        self.as_readonly().total_supply()
    }


    pub fn contract_status(&self) -> ContractStatusLevel {
        self.as_readonly().contract_status()
    }



}

fn set_bin_data<T: Serialize, S: Storage>(storage: &mut S, key: &[u8], data: &T) -> StdResult<()> {
    let bin_data =
        bincode2::serialize(&data).map_err(|e| StdError::serialize_err(type_name::<T>(), e))?;

    storage.set(key, &bin_data);
    Ok(())
}

fn get_bin_data<T: DeserializeOwned, S: ReadonlyStorage>(storage: &S, key: &[u8]) -> StdResult<T> {
    let bin_data = storage.get(key);

    match bin_data {
        None => Err(StdError::not_found("Key not found in storage")),
        Some(bin_data) => Ok(bincode2::deserialize::<T>(&bin_data)
            .map_err(|e| StdError::serialize_err(type_name::<T>(), e))?),
    }
}



pub struct Config<'a, S: Storage> {
    storage: PrefixedStorage<'a, S>,
}

impl<'a, S: Storage> Config<'a, S> {
    pub fn from_storage(storage: &'a mut S) -> Self {
        Self {
            storage: PrefixedStorage::new(PREFIX_CONFIG, storage),
        }
    }

    fn as_readonly(&self) -> ReadonlyConfigImpl<PrefixedStorage<S>> {
        ReadonlyConfigImpl(&self.storage)
    }

    pub fn constants(&self) -> StdResult<Constants> {
        self.as_readonly().constants()
    }

    pub fn set_constants(&mut self, constants: &Constants) -> StdResult<()> {
        set_bin_data(&mut self.storage, KEY_CONSTANTS, constants)
    }


    pub fn total_deposit(&self) -> u128 {
        self.as_readonly().total_supply()
    }

    pub fn set_total_deposit(&mut self, supply: u128) {
        self.storage.set(KEY_TOTAL_SUPPLY, &supply.to_be_bytes());
    }

    pub fn contract_status(&self) -> ContractStatusLevel {
        self.as_readonly().contract_status()
    }

    pub fn set_contract_status(&mut self, status: ContractStatusLevel) {
        let status_u8 = status_level_to_u8(status);
        self.storage
            .set(KEY_CONTRACT_STATUS, &status_u8.to_be_bytes());
    }

    pub fn entropy(&self) -> Vec<u8> {
        self.as_readonly().entropy()
    }

    pub fn set_entropy(&mut self, entropy: Vec<u8>) {
        self.storage.set(KEY_ENTROPY, &entropy);
    }
}

/// This struct refactors out the readonly methods that we need for `Config` and `ReadonlyConfig`
/// in a way that is generic over their mutability.
///
/// This was the only way to prevent code duplication of these methods because of the way
/// that `ReadonlyPrefixedStorage` and `PrefixedStorage` are implemented in `cosmwasm-std`
struct ReadonlyConfigImpl<'a, S: ReadonlyStorage>(&'a S);

impl<'a, S: ReadonlyStorage> ReadonlyConfigImpl<'a, S> {
    fn constants(&self) -> StdResult<Constants> {
        let consts_bytes = self
            .0
            .get(KEY_CONSTANTS)
            .ok_or_else(|| StdError::generic_err("no constants stored in configuration"))?;
        bincode2::deserialize::<Constants>(&consts_bytes)
            .map_err(|e| StdError::serialize_err(type_name::<Constants>(), e))
    }

    fn total_supply(&self) -> u128 {
        let supply_bytes = self
            .0
            .get(KEY_TOTAL_SUPPLY)
            .expect("no total supply stored in config");
        // This unwrap is ok because we know we stored things correctly
        slice_to_u128(&supply_bytes).unwrap()
    }

    fn contract_status(&self) -> ContractStatusLevel {
        let supply_bytes = self
            .0
            .get(KEY_CONTRACT_STATUS)
            .expect("no contract status stored in config");

        // These unwraps are ok because we know we stored things correctly
        let status = slice_to_u8(&supply_bytes).unwrap();
        u8_to_status_level(status).unwrap()
    }


    fn entropy(&self) -> Vec<u8> {
        get_bin_data(self.0, KEY_ENTROPY).unwrap()
    }

    fn entries(&self) -> Vec<(CanonicalAddr, Uint128,u64)> {
        get_bin_data(self.0, KEY_ENTRIES).unwrap()
    }


}


// Viewing Keys

pub fn write_viewing_key<S: Storage>(store: &mut S, owner: &CanonicalAddr, key: &ViewingKey) {
    let mut balance_store = PrefixedStorage::new(PREFIX_VIEW_KEY, store);
    balance_store.set(owner.as_slice(), &key.to_hashed());
}

pub fn read_viewing_key<S: Storage>(store: &S, owner: &CanonicalAddr) -> Option<Vec<u8>> {
    let balance_store = ReadonlyPrefixedStorage::new(PREFIX_VIEW_KEY, store);
    balance_store.get(owner.as_slice())
}

// Receiver Interface

pub fn get_receiver_hash<S: ReadonlyStorage>(
    store: &S,
    account: &HumanAddr,
) -> Option<StdResult<String>> {
    let store = ReadonlyPrefixedStorage::new(PREFIX_RECEIVERS, store);
    store.get(account.as_str().as_bytes()).map(|data| {
        String::from_utf8(data)
            .map_err(|_err| StdError::invalid_utf8("stored code hash was not a valid String"))
    })
}

pub fn set_receiver_hash<S: Storage>(store: &mut S, account: &HumanAddr, code_hash: String) {
    let mut store = PrefixedStorage::new(PREFIX_RECEIVERS, store);
    store.set(account.as_str().as_bytes(), code_hash.as_bytes());
}

// Helpers

/// Converts 16 bytes value into u128
/// Errors if data found that is not 16 bytes
fn slice_to_u128(data: &[u8]) -> StdResult<u128> {
    match <[u8; 16]>::try_from(data) {
        Ok(bytes) => Ok(u128::from_be_bytes(bytes)),
        Err(_) => Err(StdError::generic_err(
            "Corrupted data found. 16 byte expected.",
        )),
    }
}

/// Converts 1 byte value into u8
/// Errors if data found that is not 1 byte
fn slice_to_u8(data: &[u8]) -> StdResult<u8> {
    if data.len() == 1 {
        Ok(data[0])
    } else {
        Err(StdError::generic_err(
            "Corrupted data found. 1 byte expected.",
        ))
    }
}

/// Reads 4 byte storage value into u32
/// Returns zero if key does not exist. Errors if data found that is not 4 bytes
pub fn read_u32<S: ReadonlyStorage>(store: &S, key: &[u8]) -> StdResult<u32> {
    let result = store.get(key);
    match result {
        Some(data) => bytes_to_u32(data.as_slice()),
        None => Ok(0u32),
    }
}

/// Reads 16 byte storage value into u128
/// Returns zero if key does not exist. Errors if data found that is not 16 bytes
pub fn read_u128<S: ReadonlyStorage>(store: &S, key: &[u8]) -> StdResult<u128> {
    let result = store.get(key);
    match result {
        Some(data) => bytes_to_u128(&data),
        None => Ok(0u128),
    }
}
