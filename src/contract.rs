use cosmwasm_std::{
    log, to_binary, Api, BankMsg, Binary, CanonicalAddr, Coin, CosmosMsg, Env, Extern,
    HandleResponse, HumanAddr, InitResponse, Querier, QueryResult, ReadonlyStorage,
    StdError, StdResult, Storage, Uint128,
};
use sha2::{Digest, Sha256};
use rand::distributions::WeightedIndex;
use rand::prelude::*;
use rand::{SeedableRng};
use rand_chacha::ChaChaRng;
use rust_decimal::prelude::ToPrimitive;
use crate::msg::{
    space_pad, ContractStatusLevel, HandleAnswer, HandleMsg, InitMsg, QueryAnswer, QueryMsg,
    ResponseStatus::Success,
};
use crate::rand::sha_256;
use crate::receiver::Snip20ReceiveMsg;
use crate::staking::{stake, withdraw_to_winner, get_rewards, undelegate};
use crate::state::{
    get_receiver_hash, log_string, lottery, lottery_read,
    read_viewing_key, store_deposit, store_redeem,write_viewing_key,Config, Constants,
    Lottery, ReadonlyBalances, ReadonlyConfig, store_win,
};
use crate::validator_set::{get_validator_set, set_validator_set, ValidatorSet};
use crate::viewing_key::{ViewingKey, VIEWING_KEY_SIZE};
use secret_toolkit::storage::{TypedStore, TypedStoreMut};
use crate::types::UserInfo;


/// We make sure that responses from `handle` are padded to a multiple of this size.
pub const RESPONSE_BLOCK_SIZE: usize = 256;

pub fn init<S: Storage, A: Api, Q: Querier>(
    deps: &mut Extern<S, A, Q>,
    env: Env,
    msg: InitMsg,
) -> StdResult<InitResponse> {
    let init_config = msg.config();
    let admin = msg.admin.unwrap_or_else(|| env.message.sender.clone());
    let prng_seed_hashed = sha_256(&msg.prng_seed.0);

    let mut config = Config::from_storage(&mut deps.storage);
    let mut total_supply: u128 = 0;
    config.set_total_deposit(total_supply);
    config.set_contract_status(ContractStatusLevel::NormalRun);
    config.set_constants(&Constants {
        admin: admin.clone(),
        prng_seed: prng_seed_hashed.to_vec(),
        total_supply_is_public: false,
        deposit_is_enabled: init_config.deposit_enabled(),
        withdraw_is_enabled: init_config.redeem_enabled(),
        denom:msg.denom
    })?;

    // ensure the validator is registered
    let vals = deps.querier.query_validators()?;
    let human_addr_wrap = HumanAddr(init_config.validator().clone());
    if !vals.iter().any(|v| v.address == human_addr_wrap) {
        return Err(StdError::generic_err(format!(
            "{} is not in the current validator set",
            init_config.validator()
        )));
    }

    let mut valset = ValidatorSet::default();
    valset.add(init_config.validator());
    set_validator_set(&mut deps.storage, &valset)?;

    let height = env.block.height;
    let duration = 10u64;


    //Create first lottery
    let a_lottery = Lottery {
        entries: Vec::default(),
        entropy: prng_seed_hashed.to_vec(),
        start_height: height + 1,
        end_height: height + duration + 1,
        seed: prng_seed_hashed.to_vec(),
        duration,
    };

    // Save to state
    lottery(&mut deps.storage).save(&a_lottery)?;


    Ok(InitResponse::default())
}


pub fn handle<S: Storage, A: Api, Q: Querier>(
    deps: &mut Extern<S, A, Q>,
    env: Env,
    msg: HandleMsg,
) -> StdResult<HandleResponse> {
    let contract_status = ReadonlyConfig::from_storage(&deps.storage).contract_status();

    match contract_status {
        ContractStatusLevel::StopAll | ContractStatusLevel::StopAllButRedeems => {
            let response = match msg {
                HandleMsg::SetContractStatus { level, .. } => set_contract_status(deps, env, level),
                HandleMsg::Withdraw { amount, memo, .. }
                if contract_status == ContractStatusLevel::StopAllButRedeems =>
                    {
                        try_withdraw(deps, env, None, amount, memo)
                    }
                HandleMsg::WithdrawTo {
                    recipient,
                    amount,
                    memo,
                    ..
                } if contract_status == ContractStatusLevel::StopAllButRedeems => {
                    try_withdraw(deps, env, Some(recipient), amount, memo)
                }
                _ => Err(StdError::generic_err(
                    "This contract is stopped and this action is not allowed",
                )),
            };
            return pad_response(response);
        }
        ContractStatusLevel::NormalRun => {} // If it's a normal run just continue
    }



    let response = match msg {
        // Stakepool's
        HandleMsg::Deposit { memo, .. } => try_deposit(deps, env, memo),
        HandleMsg::Withdraw { amount, memo, .. } => try_withdraw(deps, env, None, amount, memo),
        HandleMsg::WithdrawTo {
            recipient,
            amount,
            memo,
            ..
        } => try_withdraw(deps, env, Some(recipient), amount, memo),
        HandleMsg::ClaimRewards {} => claim_rewards(deps, env),

        // Base
        HandleMsg::CreateViewingKey { entropy, .. } => try_create_key(deps, env, entropy),
        HandleMsg::SetViewingKey { key, .. } => try_set_key(deps, env, key),

        // Other
        HandleMsg::ChangeAdmin { address, .. } => change_admin(deps, env, address),
        HandleMsg::SetContractStatus { level, .. } => set_contract_status(deps, env, level),
    };

    pad_response(response)
}

pub fn query<S: Storage, A: Api, Q: Querier>(deps: &Extern<S, A, Q>, msg: QueryMsg) -> QueryResult {
    match msg {
        QueryMsg::LotteryInfo {} => {
            // query_lottery_info(&deps.storage)
            let lottery = lottery_read(&deps.storage).load()?;
            to_binary(&QueryAnswer::LotteryInfo {
                start_height: lottery.start_height,
                end_height: lottery.end_height,
            })
        }
        _ => authenticated_queries(deps, msg),
    }
}

pub fn authenticated_queries<S: Storage, A: Api, Q: Querier>(
    deps: &Extern<S, A, Q>,
    msg: QueryMsg,
) -> QueryResult {
    let (addresses, key) = msg.get_validation_params();

    for address in addresses {
        let canonical_addr = deps.api.canonical_address(address)?;

        let expected_key = read_viewing_key(&deps.storage, &canonical_addr);

        if expected_key.is_none() {
            // Checking the key will take significant time. We don't want to exit immediately if it isn't set
            // in a way which will allow to time the command and determine if a viewing key doesn't exist
            key.check_viewing_key(&[0u8; VIEWING_KEY_SIZE]);
        } else if key.check_viewing_key(expected_key.unwrap().as_slice()) {
            return match msg {
                // Base
                QueryMsg::Balance { address, .. } => query_balance(&deps, &address),

                _ => panic!("This query type does not require authentication"),
            };
        }
    }

    Ok(to_binary(&QueryAnswer::ViewingKeyError {
        msg: "Wrong viewing key for this address or viewing key not set".to_string(),
    })?)
}

fn pad_response(response: StdResult<HandleResponse>) -> StdResult<HandleResponse> {
    response.map(|mut response| {
        response.data = response.data.map(|mut data| {
            space_pad(RESPONSE_BLOCK_SIZE, &mut data.0);
            data
        });
        response
    })
}

pub fn query_balance<S: Storage, A: Api, Q: Querier>(
    deps: &Extern<S, A, Q>,
    account: &HumanAddr,
) -> StdResult<Binary> {
    let address = deps.api.canonical_address(account)?;

    let amount = Uint128(ReadonlyBalances::from_storage(&deps.storage).account_amount(&address));
    let response = QueryAnswer::Balance { amount };
    to_binary(&response)
}



fn change_admin<S: Storage, A: Api, Q: Querier>(
    deps: &mut Extern<S, A, Q>,
    env: Env,
    address: HumanAddr,
) -> StdResult<HandleResponse> {
    let mut config = Config::from_storage(&mut deps.storage);

    check_if_admin(&config, &env.message.sender)?;

    let mut consts = config.constants()?;
    consts.admin = address;
    config.set_constants(&consts)?;

    Ok(HandleResponse {
        messages: vec![],
        log: vec![],
        data: Some(to_binary(&HandleAnswer::ChangeAdmin { status: Success })?),
    })
}

pub fn try_set_key<S: Storage, A: Api, Q: Querier>(
    deps: &mut Extern<S, A, Q>,
    env: Env,
    key: String,
) -> StdResult<HandleResponse> {
    let vk = ViewingKey(key);

    let message_sender = deps.api.canonical_address(&env.message.sender)?;
    write_viewing_key(&mut deps.storage, &message_sender, &vk);

    Ok(HandleResponse {
        messages: vec![],
        log: vec![],
        data: Some(to_binary(&HandleAnswer::SetViewingKey { status: Success })?),
    })
}

pub fn try_create_key<S: Storage, A: Api, Q: Querier>(
    deps: &mut Extern<S, A, Q>,
    env: Env,
    entropy: String,
) -> StdResult<HandleResponse> {
    let constants = ReadonlyConfig::from_storage(&deps.storage).constants()?;
    let prng_seed = constants.prng_seed;

    let key = ViewingKey::new(&env, &prng_seed, (&entropy).as_ref());

    let message_sender = deps.api.canonical_address(&env.message.sender)?;
    write_viewing_key(&mut deps.storage, &message_sender, &key);

    Ok(HandleResponse {
        messages: vec![],
        log: vec![],
        data: Some(to_binary(&HandleAnswer::CreateViewingKey { key })?),
    })
}

fn set_contract_status<S: Storage, A: Api, Q: Querier>(
    deps: &mut Extern<S, A, Q>,
    env: Env,
    status_level: ContractStatusLevel,
) -> StdResult<HandleResponse> {
    let mut config = Config::from_storage(&mut deps.storage);

    check_if_admin(&config, &env.message.sender)?;

    config.set_contract_status(status_level);

    Ok(HandleResponse {
        messages: vec![],
        log: vec![],
        data: Some(to_binary(&HandleAnswer::SetContractStatus {
            status: Success,
        })?),
    })
}

// claims the rewards to a random winner
fn claim_rewards<S: Storage, A: Api, Q: Querier>(
    deps: &mut Extern<S, A, Q>,
    env: Env,
) -> StdResult<HandleResponse> {

    // this way every time we call the claim_rewards function we will get a different result.
    // Plus it's going to be pretty hard to predict the exact time of the block, so less chance of cheating

    let mut validator_set = get_validator_set(&deps.storage)?;
    let validator = validator_set.get_validator_address().unwrap();

    let mut a_lottery = lottery(&mut deps.storage).load()?;
    validate_end_height(a_lottery.end_height, env.clone())?;
    validate_start_height(a_lottery.start_height, env.clone())?;

    a_lottery.entropy.extend(&env.block.height.to_be_bytes());
    a_lottery.entropy.extend(&env.block.time.to_be_bytes());

    // restart the lottery in the next block
    a_lottery.start_height = &env.block.height + 1;
    a_lottery.end_height = &env.block.height + a_lottery.duration + 1;
    lottery(&mut deps.storage).save(&a_lottery)?;

    let entries: Vec<_> = (&a_lottery.entries).into_iter().map(|(k, _, _)| k).collect();
    let weights: Vec<u128> = (&a_lottery.entries).into_iter().map(|(_, v, deposit_height)|
        if ((a_lottery.end_height - deposit_height) / a_lottery.duration) > 1 {
            v.u128()
        } else {
            v.u128() * ((a_lottery.end_height - deposit_height) / a_lottery.duration).to_u128().unwrap()
        }
    ).collect();


    // log_string(&mut deps.storage).save(&format!("Number of entries = {}", &weights.len()))?;

    let constants = ReadonlyConfig::from_storage(&deps.storage).constants()?;

    let prng_seed = constants.prng_seed;

    let mut hasher = Sha256::new();
    hasher.update(&prng_seed);
    hasher.update(&a_lottery.entropy);
    let hash = hasher.finalize();

    let mut result = [0u8; 32];
    result.copy_from_slice(hash.as_slice());

    let mut rng: ChaChaRng = ChaChaRng::from_seed(result);
    let dist = WeightedIndex::new(&weights).unwrap();

    let sample = dist.sample(&mut rng).clone();
    let winner = entries[sample];

    let mut messages: Vec<CosmosMsg> = vec![];

    let winner_human = deps.api.human_address(&winner.clone()).unwrap();
    // log_string(&mut deps.storage).save(&format!("And the winner is {}", winner_human.as_str()))?;

    messages.push(withdraw_to_winner(&validator, &winner_human.clone()));

    let rewards = get_rewards(&deps.querier, &env.contract.address).unwrap();
    let logs = vec![
        log("winner", winner_human.as_str()),
        log("amount", &rewards.to_string()),
    ];
    let rewards = Uint128(5000);

    let mut user = TypedStore::<UserInfo, S>::attach(&deps.storage)
        .load(winner_human.0.as_bytes())
        .unwrap_or(UserInfo { amount_delegated: Uint128(0), start_height: env.block.height, requested_withdraw: Uint128(0), available_tokens_for_withdrawl: Uint128(0) }); // NotFound is the only possible error
    user.available_tokens_for_withdrawl += rewards;
    TypedStoreMut::<UserInfo, S>::attach(&mut deps.storage).store(winner_human.0.as_bytes(), &user)?;

    store_win(
        &mut deps.storage,
        &winner,
        rewards,
        constants.denom,
        None,
    )?;

    let res = HandleResponse {
        messages,
        log: vec![],
        data: Some(to_binary(&HandleAnswer::ClaimRewards {
            status: Success,
            winner: winner_human.clone(),
        })?),
    };

    Ok(res)
}

fn valid_amount(amt: Uint128) -> bool {
    amt >= Uint128(1000000)
}



fn try_deposit<S: Storage, A: Api, Q: Querier>(
    deps: &mut Extern<S, A, Q>,
    env: Env,
    memo: Option<String>,
) -> StdResult<HandleResponse> {

    //Checking the if the request could proceed.
    let constants = Config::from_storage(&mut deps.storage).constants()?;
    if !constants.deposit_is_enabled {
        return Err(StdError::generic_err(
            "Deposit functionality is not enabled for this token.",
        ));
    }

    let mut deposit_amount = Uint128::zero();
    for coin in &env.message.sent_funds {
        if coin.denom == "uscrt" {
            deposit_amount = coin.amount
        }
        else{
             return Err(StdError::generic_err(
                "Coins send are not Scrt",
            ));
        }
    }

    if !valid_amount(deposit_amount) {
        return Err(StdError::generic_err(
            "Must deposit a minimum of 1000000 uscrt, or 1 scrt",
        ));
    }

    let mut user = TypedStore::<UserInfo, S>::attach(&deps.storage)
        .load(env.message.sender.0.as_bytes())
        .unwrap_or(UserInfo { amount_delegated: Uint128(0), start_height: env.block.height, requested_withdraw: Uint128(0), available_tokens_for_withdrawl: Uint128(0) }); // NotFound is the only possible error

    let mut config = Config::from_storage(&mut deps.storage);
    let total_supply = config.total_deposit();

    if let Some(total_deposit) = total_supply.checked_add(deposit_amount.0) {
        config.set_total_deposit(total_deposit);
    } else {
        return Err(StdError::generic_err(
            "This deposit would overflow the currency's total supply",
        ));
    }

    let sender_address = deps.api.canonical_address(&env.message.sender)?;
    let account_balance = user.amount_delegated.0;
    if let Some(account_balance) = account_balance.checked_add(deposit_amount.0) {
        user.start_height=env.block.height;
        user.amount_delegated = Uint128::from(account_balance);
        TypedStoreMut::<UserInfo, S>::attach(&mut deps.storage).store(env.message.sender.0.as_bytes(), &user)?;

    } else {
        return Err(StdError::generic_err(
            "This deposit would overflow your balance",
        ));
    }

    store_deposit(
        &mut deps.storage,
        &sender_address,
        deposit_amount,
        "uscrt".to_string(),
        memo,
    )?;

    // update lottery entries
    let mut a_lottery = lottery(&mut deps.storage).load()?;
    if a_lottery.entries.len() > 0 {
        &a_lottery.entries.retain(|(k, _, _)| k != &sender_address);
    }
    let start_height = env.block.height;
    &a_lottery.entries.push((
        sender_address.clone(),
        Uint128::from(account_balance + deposit_amount.0),
        start_height,
    ));

    &a_lottery.entropy.extend(&env.block.height.to_be_bytes());
    &a_lottery.entropy.extend(&env.block.time.to_be_bytes());
    lottery(&mut deps.storage).save(&a_lottery);

    let mut messages: Vec<CosmosMsg> = vec![];

    let mut validator_set = get_validator_set(&deps.storage)?;
    let validator = validator_set.stake(deposit_amount.u128())?;
    messages.push(stake(&validator, deposit_amount.u128()));


    Ok(HandleResponse {
        messages,
        log: vec![],
        data: Some(to_binary(&HandleAnswer::Deposit { status: Success })?),
    })
}

fn try_withdraw<S: Storage, A: Api, Q: Querier>(
    deps: &mut Extern<S, A, Q>,
    env: Env,
    redeem_to: Option<HumanAddr>,
    amount: Uint128,
    memo: Option<String>,
) -> StdResult<HandleResponse> {
    //loading configs from storage
    let amount_raw = amount.u128();
    let mut config = Config::from_storage(&mut deps.storage);
    let constants = config.constants()?;
    //Checking if the redeem functionality is enabled
    if !constants.withdraw_is_enabled {
        return Err(StdError::generic_err(
            "Redeem functionality is not enabled for this token.",
        ));
    }
    //Subtracting total supply of tokens given
    let total_supply = config.total_deposit();
    if let Some(total_supply) = total_supply.checked_sub(amount_raw) {
        config.set_total_deposit(total_supply);
    } else {
        return Err(StdError::generic_err(
            "You are trying to redeem more tokens than what is available in the total supply",
        ));
    }

    let mut user = TypedStore::<UserInfo, S>::attach(&deps.storage)
        .load(env.message.sender.0.as_bytes())
        .unwrap_or(UserInfo { amount_delegated: Uint128(0), start_height: env.block.height, requested_withdraw: Uint128(0), available_tokens_for_withdrawl: Uint128(0) }); // NotFound is the only possible error

    //Subtracting from user's balance
    let sender_address = deps.api.canonical_address(&env.message.sender)?;
    let account_balance = user.amount_delegated.0;
    if let Some(account_balance) = account_balance.checked_sub(amount_raw) {
        user.amount_delegated= Uint128::from(account_balance);
        TypedStoreMut::<UserInfo, S>::attach(&mut deps.storage).store(env.message.sender.0.as_bytes(), &user)?;

    } else {
        return Err(StdError::generic_err(format!(
            "insufficient funds to redeem: balance={}, required={}",
            account_balance, amount_raw
        )));
    }

    // update lottery entries
    let mut lottery = lottery(&mut deps.storage).load()?;
    &lottery.entries.retain(|(k, _, _)| k != &sender_address);
    if account_balance > 0 {
        &lottery
            .entries
            .push((sender_address.clone(), Uint128::from(account_balance), env.block.height));
    }
    lottery.entropy.extend(&env.block.height.to_be_bytes());
    lottery.entropy.extend(&env.block.time.to_be_bytes());

    //Asking the validator to undelegate the funds
    let mut validator_set = get_validator_set(&mut deps.storage)?;
    let validator = validator_set.get_validator_address().unwrap();
    let mut messages: Vec<CosmosMsg> = vec![];
    messages.push(undelegate(&validator, amount_raw));

    let withdrawl_coins: Vec<Coin> = vec![Coin {
        denom: "uscrt".to_string(),
        amount,
    }];
    let recipient_raw: Option<CanonicalAddr>;
    let recipient = if let Some(r) = redeem_to {
        recipient_raw = Some(deps.api.canonical_address(&r)?);
        r
    } else {
        recipient_raw = None;
        env.message.sender
    };

    messages.push(CosmosMsg::Bank(BankMsg::Send {
        from_address: env.contract.address,
        to_address: recipient,
        amount: withdrawl_coins,
    }));


    store_redeem(
        &mut deps.storage,
        &sender_address,
        recipient_raw,
        amount,
        constants.denom,
        memo,
    )?;

    let res = HandleResponse {
        messages,
        log: vec![],
        data: Some(to_binary(&HandleAnswer::Withdraw { status: Success })?),
    };

    Ok(res)
}




fn is_admin<S: Storage>(config: &Config<S>, account: &HumanAddr) -> StdResult<bool> {
    let consts = config.constants()?;
    if &consts.admin != account {
        return Ok(false);
    }

    Ok(true)
}

fn check_if_admin<S: Storage>(config: &Config<S>, account: &HumanAddr) -> StdResult<()> {
    if !is_admin(config, account)? {
        return Err(StdError::generic_err(
            "This is an admin command. Admin commands can only be run from admin address",
        ));
    }

    Ok(())
}


/// validate_end_height returns an error if the lottery ends in the future
fn validate_end_height(end_height: u64, env: Env) -> StdResult<()> {
    if env.block.height < end_height {
        Err(StdError::generic_err("Lottery end height is in the future"))
    } else {
        Ok(())
    }
}

/// validate_start_height returns an error if the lottery hasn't started
fn validate_start_height(start_height: u64, env: Env) -> StdResult<()> {
    if env.block.height < start_height {
        Err(StdError::generic_err("Lottery start height is in the future"))
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::msg::ResponseStatus;
    use crate::msg::{InitConfig, InitialBalance};
    use cosmwasm_std::testing::*;
    use cosmwasm_std::{from_binary, QueryResponse, WasmMsg, Decimal, FullDelegation, Validator, BlockInfo, MessageInfo, ContractInfo, QuerierResult};
    use std::any::Any;

    // Helper functions
    fn init_helper() -> (
        StdResult<InitResponse>,
        Extern<MockStorage, MockApi, MockQuerier>,
    ) {
        let mut deps = mock_dependencies(20, &[]);
        let env = mock_env("admin", &[], 1);
        let validator= "v".to_string();

        let init_config: InitConfig = from_binary(&Binary::from(
            format!(
                "{{\"public_total_supply\":false,
                    \"enable_deposit\":{},
                    \"enable_redeem\":{},
                    \"validator\":\"{}\"
                    }}",
                true, true, "v".to_string(),
            )
                .as_bytes(),
        ))
            .unwrap();

        deps.querier.update_staking(
            "SECSEC",
            &[Validator {
                address: HumanAddr(validator.clone()),
                commission: Decimal::percent(1),
                max_commission: Decimal::percent(2),
                /// TODO: what units are these (in terms of time)?
                max_change_rate: Decimal::percent(3),
            }],
            &[FullDelegation {
                delegator: Default::default(),
                validator: Default::default(),
                amount: Default::default(),
                can_redelegate: Default::default(),
                accumulated_rewards: Default::default(),
            }],
        );

        let init_msg = InitMsg {
            admin: Option::from(HumanAddr("haseeb".to_string())),
            denom: "uscrt".to_string(),
            prng_seed: Binary::from("I'm Batman".as_bytes()),
            config: Some(init_config),
        };

        (init(&mut deps, env, init_msg), deps)
    }


    pub fn mock_env<U: Into<HumanAddr>>(sender: U, sent: &[Coin], height: u64) -> Env {
        Env {
            block: BlockInfo {
                height,
                time: 1_571_797_419,
                chain_id: "secret-testnet".to_string(),
            },
            message: MessageInfo {
                sender: sender.into(),
                sent_funds: sent.to_vec(),
            },
            contract: ContractInfo {
                address: HumanAddr::from(MOCK_CONTRACT_ADDR),
            },
            contract_key: Some("".to_string()),
            contract_code_hash: "".to_string(),
        }
    }

    #[test]
    fn testing_deposit() {
        //1)Checking for errors
        let (_init_result, mut deps) = init_helper();
        let env = mock_env("Batman",  &[Coin {
            denom: "uscrt".to_string(),
            amount: Uint128(1000000),
        }], 10);

        let handlemsg= HandleMsg::Deposit { memo: Option::from("memo".to_string()), padding: None };
        let response = handle(&mut deps, env.clone(), handlemsg);
        let mut user = TypedStore::attach(&deps.storage)
            .load("Batman".as_bytes())
            .unwrap_or(UserInfo { amount_delegated: Uint128(0), start_height: env.block.height, requested_withdraw: Uint128(0), available_tokens_for_withdrawl: Uint128(0) }); // NotFound is the only possible error

        assert_eq!(user.amount_delegated,Uint128(1000000));

        let env = mock_env("Rick",  &[Coin {
            denom: "uscrt".to_string(),
            amount: Uint128(1000000),
        }], 10);

        let handlemsg= HandleMsg::Deposit { memo: Option::from("memo".to_string()), padding: None };
        let response = handle(&mut deps, env.clone(), handlemsg);
        let mut user = TypedStore::attach(&deps.storage)
            .load("Rick".as_bytes())
            .unwrap_or(UserInfo { amount_delegated: Uint128(0), start_height: env.block.height, requested_withdraw: Uint128(0), available_tokens_for_withdrawl: Uint128(0) }); // NotFound is the only possible error

        assert_eq!(user.amount_delegated,Uint128(1000000));

        let mut config = Config::from_storage(&mut deps.storage);
        let total_deposit = config.total_deposit();
        assert_eq!(total_deposit, 2000000);

    }

    #[test]
    fn testing_withdraw() {
        //1)Checking for errors
        let (_init_result, mut deps) = init_helper();
        let env = mock_env("Batman",  &[Coin {
            denom: "uscrt".to_string(),
            amount: Uint128(1000000),
        }], 10);

        let handlemsg= HandleMsg::Deposit { memo: Option::from("memo".to_string()), padding: None };
        let response = handle(&mut deps, env.clone(), handlemsg);
        let mut user = TypedStore::attach(&deps.storage)
            .load("Batman".as_bytes())
            .unwrap_or(UserInfo { amount_delegated: Uint128(0), start_height: env.block.height, requested_withdraw: Uint128(0), available_tokens_for_withdrawl: Uint128(0) }); // NotFound is the only possible error

        assert_eq!(user.amount_delegated,Uint128(1000000));

        let env = mock_env("Batman",  &[Coin {
            denom: "uscrt".to_string(),
            amount: Uint128(0),
        }], 10);

        let handlemsg= HandleMsg::Withdraw {
            amount: Uint128(1000000),
            memo: None,
            padding: None
        };
        let response = handle(&mut deps, env.clone(), handlemsg);
        let mut user = TypedStore::attach(&deps.storage)
            .load("Batman".as_bytes())
            .unwrap_or(UserInfo { amount_delegated: Uint128(0), start_height: env.block.height, requested_withdraw: Uint128(0), available_tokens_for_withdrawl: Uint128(0) }); // NotFound is the only possible error

        assert_eq!(user.amount_delegated,Uint128(0));

        let mut config = Config::from_storage(&mut deps.storage);
        let total_deposit = config.total_deposit();
        assert_eq!(total_deposit, 0);

    }

    #[test]
    fn testing_deposit_with_wrong_denom() {
        //1)Checking for errors
        let (_init_result, mut deps) = init_helper();
        let env = mock_env("Batman",  &[Coin {
            denom: "bitcoin".to_string(),
            amount: Uint128(1000000),
        }], 10);

        let handlemsg= HandleMsg::Deposit { memo: Option::from("memo".to_string()), padding: None };
        let response = handle(&mut deps, env.clone(), handlemsg);

        assert_eq!(response.unwrap_err(),StdError::generic_err(
            "Coins send are not Scrt",
        ));
    }
    #[test]
    fn testing_deposit_with_less_than_accepted_amount() {
        //1)Checking for errors
        let (_init_result, mut deps) = init_helper();
        let env = mock_env("Batman",  &[Coin {
            denom: "uscrt".to_string(),
            amount: Uint128(999999),
        }], 10);

        let handlemsg= HandleMsg::Deposit { memo: Option::from("memo".to_string()), padding: None };
        let response = handle(&mut deps, env.clone(), handlemsg);

        assert_eq!(response.unwrap_err(),StdError::generic_err(
            "Must deposit a minimum of 1000000 uscrt, or 1 scrt",
        ));
    }

    #[test]
    fn testing_deposit_total_supply_overload() {
        //1)Checking for errors
        let (_init_result, mut deps) = init_helper();
        let env = mock_env("Batman",  &[Coin {
            denom: "uscrt".to_string(),

            amount: Uint128(100000000000000000),
        }], 10);

        let handlemsg= HandleMsg::Deposit { memo: Option::from("memo".to_string()), padding: None };
        let response = handle(&mut deps, env.clone(), handlemsg);

    }


    #[test]
    fn testing_claim_rewards() {
        //1)Checking for errors
        let (_init_result, mut deps) = init_helper();
        let env = mock_env("Batman",  &[Coin {
            denom: "uscrt".to_string(),
            amount: Uint128(1000000),
        }], 10);

        let handlemsg= HandleMsg::Deposit { memo: Option::from("memo".to_string()), padding: None };
        let response = handle(&mut deps, env.clone(), handlemsg);
        let mut user = TypedStore::attach(&deps.storage)
            .load("Batman".as_bytes())
            .unwrap_or(UserInfo { amount_delegated: Uint128(0), start_height: env.block.height, requested_withdraw: Uint128(0), available_tokens_for_withdrawl: Uint128(0) }); // NotFound is the only possible error

        assert_eq!(user.amount_delegated,Uint128(1000000));

        let mut config = Config::from_storage(&mut deps.storage);
        let total_deposit = config.total_deposit();
        assert_eq!(total_deposit, 1000000);

        let env = mock_env("xyz",  &[Coin {
            denom: "uscrt".to_string(),
            amount: Uint128(0),
        }], 22);

        let handlemsg= HandleMsg::ClaimRewards {

        };
        let response = handle(&mut deps, env.clone(), handlemsg);
        let mut user = TypedStore::attach(&deps.storage)
            .load("Batman".as_bytes())
            .unwrap_or(UserInfo { amount_delegated: Uint128(0), start_height: env.block.height, requested_withdraw: Uint128(0), available_tokens_for_withdrawl: Uint128(0) }); // NotFound is the only possible error

        assert_eq!(user.available_tokens_for_withdrawl,Uint128(5000));

        let mut a_lottery = lottery(&mut deps.storage).load().unwrap();
        assert_eq!(a_lottery.start_height,23);


        let log_string = log_string(&mut deps.storage ).load();
        println!("{:?}",log_string);





    }



}
