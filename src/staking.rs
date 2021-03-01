use cosmwasm_std::{BondedRatioResponse, Coin, CosmosMsg, DistQuery, HumanAddr, InflationResponse, MintQuery, Querier, RewardsResponse, StakingMsg, StakingQuery, StdResult, Uint128, UnbondingDelegationsResponse, StdError};

pub fn get_locked_balance<Q: Querier>(
    querier: &Q,
    contract_address: &HumanAddr,
) -> StdResult<u128> {
    let staked_balance = get_bonded(querier, contract_address)?;
    let undelegation_balance = get_unbonding(querier, contract_address)?;

    Ok(staked_balance.u128() + undelegation_balance.u128())
}

pub fn get_total_onchain_balance<Q: Querier>(
    querier: &Q,
    contract_address: &HumanAddr,
) -> StdResult<u128> {
    let locked_balance = get_locked_balance(querier, contract_address)?;
    Ok(locked_balance)
}

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

// get_bonded returns the total amount of delegations from contract
// it ensures they are all the same denom
pub fn get_bonded<Q: Querier>(querier: &Q, contract: &HumanAddr) -> StdResult<Uint128> {
    let bonds = querier.query_all_delegations(contract)?;
    if bonds.is_empty() {
        return Ok(Uint128(0));
    }
    let denom = bonds[0].amount.denom.as_str();
    bonds.iter().fold(Ok(Uint128(0)), |racc, d| {
        let acc = racc?;
        if d.amount.denom.as_str() != denom {
            Err(StdError::generic_err(format!(
                "different denoms in bonds: '{}' vs '{}'",
                denom, &d.amount.denom
            )))
        } else {
            Ok(acc + d.amount.amount)
        }
    })
}

// get_bonded returns the total amount of delegations from contract
// it ensures they are all the same denom
pub fn get_unbonding<Q: Querier>(querier: &Q, contract: &HumanAddr) -> StdResult<Uint128> {
    let query = StakingQuery::UnbondingDelegations {
        delegator: contract.clone(),
    };

    let query_rewards: UnbondingDelegationsResponse = querier.query(&query.into())?;

    let bonds = query_rewards.delegations;
    if bonds.is_empty() {
        return Ok(Uint128(0));
    }
    let denom = bonds[0].amount.denom.as_str();
    bonds.iter().fold(Ok(Uint128(0)), |racc, d| {
        let acc = racc?;
        if d.amount.denom.as_str() != denom {
            Err(StdError::generic_err(format!(
                "different denoms in bonds: '{}' vs '{}'",
                denom, &d.amount.denom
            )))
        } else {
            Ok(acc + d.amount.amount)
        }
    })
}

pub fn withdraw_to_self(validator: &String) -> CosmosMsg {
    CosmosMsg::Staking(StakingMsg::Withdraw {
        validator: HumanAddr(validator.clone()),
        recipient: None,
    })
}

pub fn withdraw_to_winner(validator: &String, winner: &String) -> CosmosMsg {
    CosmosMsg::Staking(StakingMsg::Withdraw {
        validator: HumanAddr(validator.clone()),
        recipient: Some(HumanAddr(winner.clone())),
    })
}

pub fn restake(validator: &String, amount: u128) -> Vec<CosmosMsg> {
    vec![
        CosmosMsg::Staking(StakingMsg::Withdraw {
            validator: HumanAddr(validator.clone()),
            recipient: None,
        }),
        CosmosMsg::Staking(StakingMsg::Delegate {
            validator: HumanAddr(validator.clone()),
            amount: Coin {
                denom: "uscrt".to_string(),
                amount: Uint128(amount),
            },
        }),
    ]
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

pub fn undelegate(validator: &String, amount: u128) -> CosmosMsg {
    CosmosMsg::Staking(StakingMsg::Undelegate {
        validator: HumanAddr(validator.clone()),
        amount: Coin {
            denom: "uscrt".to_string(),
            amount: Uint128(amount),
        },
    })
}
