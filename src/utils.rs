use crate::viewing_key::VIEWING_KEY_SIZE;
use cosmwasm_std::{StdError, StdResult};
use sha2::{Digest, Sha256};
use std::convert::TryInto;
use std::str::FromStr;
use subtle::ConstantTimeEq;

pub fn ct_slice_compare(s1: &[u8], s2: &[u8]) -> bool {
    bool::from(s1.ct_eq(s2))
}

pub fn create_hashed_password(s1: &str) -> [u8; VIEWING_KEY_SIZE] {
    Sha256::digest(s1.as_bytes())
        .as_slice()
        .try_into()
        .expect("Wrong password length")
}
// Converts 16 bytes value into u128
// Errors if data found that is not 16 bytes
pub fn bytes_to_u128(data: &[u8]) -> StdResult<u128> {
    match data[0..16].try_into() {
        Ok(bytes) => Ok(u128::from_be_bytes(bytes)),
        Err(_) => Err(StdError::generic_err(
            "Corrupted data found. 16 byte expected.",
        )),
    }
}

// Converts 4 bytes value into u32
// Errors if data found that is not 4 bytes
pub fn bytes_to_u32(data: &[u8]) -> StdResult<u32> {
    match data[0..4].try_into() {
        Ok(bytes) => Ok(u32::from_be_bytes(bytes)),
        Err(_) => Err(StdError::generic_err(
            "Corrupted data found. 4 byte expected.",
        )),
    }
}

/// Inflation rate, and other fun things are in the form 0.xxxxx. To use we remove the leading '0.'
/// and cut all but the the first 4 digits
#[allow(dead_code)]
pub fn dec_to_uint(dec: String) -> StdResult<u128> {
    let tokens: Vec<&str> = dec.split(".").collect();

    if tokens.len() < 2 {
        return Ok(
            u128::from_str(&dec).map_err(|_| StdError::generic_err("failed to parse number"))?
        );
    }

    Ok(u128::from_str(&tokens[1][0..4])
        .map_err(|_| StdError::generic_err("failed to parse number"))?)
}
