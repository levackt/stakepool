use cosmwasm_std::{Uint128};
use serde::{Deserialize, Serialize};
// use schemars::{JsonSchema};
#[derive(Serialize, Deserialize, Debug)]
pub struct RewardPool {
    pub total_tokens_staked: Uint128,
    pub total_rewards_restaked:Uint128,

}

#[derive(Serialize, Deserialize, Debug)]
pub struct UserInfo {
    pub amount_delegated: Uint128,
    pub start_time:u64,
    //amount vs time of request
    pub requested_withdraw:RequestedInfo,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct RequestedInfo {
    pub(crate) amount: Uint128,
    pub(crate) time: u64,
}








