use cosmwasm_std::{Uint128};
use serde::{Deserialize, Serialize};
// use schemars::{JsonSchema};

#[derive(Serialize, Deserialize, Debug)]
pub struct UserInfo {
    pub amount_delegated: Uint128,
    pub start_height:u64,
    pub requested_withdraw:Uint128,
    pub available_tokens_for_withdrawl:Uint128,
}


