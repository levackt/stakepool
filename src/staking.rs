use cosmwasm_std::{
     Coin, CosmosMsg, DistQuery, HumanAddr,
    Querier, RewardsResponse, StakingMsg,StdError, StdResult, Uint128,
};


pub fn get_rewards<Q: Querier>(querier: &Q, contract: &HumanAddr) -> StdResult<Uint128> {
    let query = DistQuery::Rewards {
        delegator: contract.clone(),
    };

    let query_rewards: RewardsResponse =
        querier
            .query(&query.into())
            .unwrap_or_else(|_| RewardsResponse {
                rewards: vec![],
                total: vec![],
            });

    if query_rewards.total.is_empty() {
        return Ok(Uint128(0));
    }
    let denom = query_rewards.total[0].denom.as_str();

    query_rewards.total.iter().fold(Ok(Uint128(0)), |racc, d| {
        let acc = racc?;
        if d.denom.as_str() != denom {
            Err(StdError::generic_err(format!(
                "different denoms in bonds: '{}' vs '{}'",
                denom, &d.denom
            )))
        } else {
            Ok(acc + d.amount)
        }
    })
}

pub fn withdraw_to_winner(validator: &String, winner: &HumanAddr) -> CosmosMsg {
    CosmosMsg::Staking(StakingMsg::Withdraw {
        validator: HumanAddr(validator.clone()),
        recipient: Some(winner.clone()),
    })
}


pub fn stake(validator: &String, amount: u128) -> CosmosMsg {
    CosmosMsg::Staking(StakingMsg::Delegate {
        validator: HumanAddr(validator.clone()),
        amount: Coin {
            denom: "uscrt".to_string(),
            amount: Uint128(amount),
        },
    })
}

pub fn undelegate(validator: &String, amount: Uint128) -> CosmosMsg {
    CosmosMsg::Staking(StakingMsg::Undelegate {
        validator: HumanAddr(validator.clone()),
        amount: Coin {
            denom: "uscrt".to_string(),
            amount: amount,
        },
    })
}
