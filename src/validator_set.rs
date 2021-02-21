use bincode2;
use serde::{Deserialize, Serialize};

use crate::state::{CONFIG_KEY, VALIDATOR_SET_KEY};
use cosmwasm_std::{ReadonlyStorage, StdError, StdResult, Storage};
use cosmwasm_storage::{PrefixedStorage, ReadonlyPrefixedStorage};
use std::cmp::Ordering;
use std::collections::VecDeque;

#[derive(Eq, PartialEq, Serialize, Deserialize, Debug, Clone)]
pub struct Validator {
    address: String,
    staked: u128,
}

impl PartialOrd for Validator {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Validator {
    fn cmp(&self, other: &Self) -> Ordering {
        self.staked.cmp(&other.staked)
    }
}

#[derive(Serialize, Debug, Deserialize, Clone, PartialEq, Default)]
pub struct ValidatorSet {
    validators: VecDeque<Validator>,
}

impl ValidatorSet {
    pub fn remove(&mut self, address: &String, force: bool) -> StdResult<()> {
        let pos = self.exists(address);
        if pos.is_none() {
            return Err(StdError::generic_err(format!(
                "Failed to remove validator: {}, doesn't exist",
                address
            )));
        }

        let val = self.validators.get(pos.unwrap()).unwrap();

        if !force && val.staked != 0 {
            return Err(StdError::generic_err(format!(
                "Failed to remove validator: {}, you need to undelegate {}uscrt first or set the flag force=true",
                address, val.staked
            )));
        } else {
            self.validators.remove(pos.unwrap());
        }
        Ok(())
    }

    pub fn add(&mut self, address: String) {
        if self.exists(&address).is_none() {
            self.validators.push_back(Validator { address, staked: 0 })
        }
    }

    pub fn unbond(&mut self, to_stake: u128) -> StdResult<String> {
        if self.validators.is_empty() {
            return Err(StdError::generic_err(
                "Failed to get validator to unbond - validator set is empty",
            ));
        }

        let val = self.validators.front_mut().unwrap();
        val.staked -= to_stake;
        Ok(val.address.clone())
    }

    pub fn stake(&mut self, to_stake: u128) -> StdResult<String> {
        if self.validators.is_empty() {
            return Err(StdError::generic_err(
                "Failed to get validator to stake - validator set is empty",
            ));
        }

        let val = self.validators.back_mut().unwrap();
        val.staked += to_stake;
        Ok(val.address.clone())
    }

    pub fn exists(&self, address: &String) -> Option<usize> {
        self.validators.iter().position(|v| &v.address == address)
    }

    pub fn get_validator_address(&mut self) -> Option<&String> {
        if self.validators.is_empty() {
            return None
        }

        // testing 1 validator
        let val = self.validators.front_mut().unwrap();
        Some(&val.address)
    }
}

/// todo: validator address is a String till we test with HumanAddr and see that secretval addresses are working
pub fn get_validator_set<S: Storage>(store: &S) -> StdResult<ValidatorSet> {
    let config_store = ReadonlyPrefixedStorage::new(CONFIG_KEY, store);
    let x = config_store.get(VALIDATOR_SET_KEY).unwrap();
    let record: ValidatorSet = bincode2::deserialize(&x)
        .map_err(|_| StdError::generic_err("Error unpacking validator set"))?;
    Ok(record)
}

pub fn set_validator_set<S: Storage>(
    store: &mut S,
    validators: &ValidatorSet,
) -> StdResult<()> {
    let mut config_store = PrefixedStorage::new(CONFIG_KEY, store);
    let as_bytes = bincode2::serialize(validators)
        .map_err(|_| StdError::generic_err("Error packing validator set"))?;

    config_store.set(VALIDATOR_SET_KEY, &as_bytes);

    Ok(())
}
