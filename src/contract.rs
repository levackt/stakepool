/// This contract implements SNIP-20 standard:
/// https://github.com/SecretFoundation/SNIPs/blob/master/SNIP-20.md
use cosmwasm_std::{
    log, to_binary, Api, BankMsg, Binary, CanonicalAddr, Coin, CosmosMsg, Env, Extern,
    HandleResponse, HumanAddr, InitResponse, Querier, QueryResult, ReadonlyStorage,
    StdError, StdResult, Storage, Uint128,
};

use crate::msg::{
    space_pad, ContractStatusLevel, HandleAnswer, HandleMsg, InitMsg, QueryAnswer, QueryMsg,
    ResponseStatus::Success,
};
use crate::rand::sha_256;
use sha2::{Digest, Sha256};

use rand::distributions::WeightedIndex;
use rand::prelude::*;
use rand::{SeedableRng};
use rand_chacha::ChaChaRng;

use crate::receiver::Snip20ReceiveMsg;
use crate::staking::{stake, withdraw_to_winner, get_rewards, undelegate};
use crate::state::{
    get_receiver_hash, get_transfers, get_txs, log_string, lottery, lottery_read,
    read_allowance, read_viewing_key, set_receiver_hash, store_burn, store_deposit, store_mint,
    store_redeem, store_transfer, write_allowance, write_viewing_key, Balances, Config, Constants,
    Lottery, ReadonlyBalances, ReadonlyConfig, store_win,
};
use crate::validator_set::{get_validator_set, set_validator_set, ValidatorSet};
use crate::viewing_key::{ViewingKey, VIEWING_KEY_SIZE};
use rust_decimal::prelude::ToPrimitive;

/// We make sure that responses from `handle` are padded to a multiple of this size.
pub const RESPONSE_BLOCK_SIZE: usize = 256;

pub fn init<S: Storage, A: Api, Q: Querier>(
    deps: &mut Extern<S, A, Q>,
    env: Env,
    msg: InitMsg,
) -> StdResult<InitResponse> {
    let init_config = msg.config();
    let mut total_supply: u128 = 0;
    {
        let mut balances = Balances::from_storage(&mut deps.storage);
        let initial_balances = msg.initial_balances.unwrap_or_default();
        // init storage with initial balances, if any
        for balance in initial_balances {
            if !valid_amount(balance.amount.u128()) {
                return Err(StdError::generic_err(
                    "Must deposit a minimum of 1000000 uscrt, or 1 scrt",
                ));
            }
            let amount = balance.amount.u128();
            if let Some(new_total_supply) = total_supply.checked_add(amount) {
                let balance_address = deps.api.canonical_address(&balance.address)?;
                balances.set_account_balance(&balance_address, amount);
                total_supply = new_total_supply;
                continue;
            }
            return Err(StdError::generic_err(
                "The sum of all initial balances exceeds the maximum possible total supply",
            ));
        }
    }
    // Check name, symbol, decimals
    if !is_valid_name(&msg.name) {
        return Err(StdError::generic_err(
            "Name is not in the expected format (3-30 UTF-8 bytes)",
        ));
    }
    if !is_valid_symbol(&msg.symbol) {
        return Err(StdError::generic_err(
            "Ticker symbol is not in expected format [A-Z0-9]{3,6}",
        ));
    }
    if msg.decimals > 39 {
        return Err(StdError::generic_err("Decimals must not exceed 39"));
    }
    let admin = msg.admin.unwrap_or_else(|| env.message.sender.clone());

    let prng_seed_hashed = sha_256(&msg.prng_seed.0);

    let mut config = Config::from_storage(&mut deps.storage);
    config.set_constants(&Constants {
        name: msg.name,
        symbol: msg.symbol,
        decimals: msg.decimals,
        admin: admin.clone(),
        prng_seed: prng_seed_hashed.to_vec(),
        total_supply_is_public: init_config.public_total_supply(),
        deposit_is_enabled: init_config.deposit_enabled(),
        transfer_is_enabled: init_config.transfer_enabled(),
        redeem_is_enabled: init_config.redeem_enabled(),
        mint_is_enabled: init_config.mint_enabled(),
        burn_is_enabled: init_config.burn_enabled(),
    })?;
    config.set_total_supply(total_supply);
    config.set_contract_status(ContractStatusLevel::NormalRun);
    let minters = if init_config.mint_enabled() {
        Vec::from([admin])
    } else {
        Vec::new()
    };
    config.set_minters(minters)?;

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

fn pad_response(response: StdResult<HandleResponse>) -> StdResult<HandleResponse> {
    response.map(|mut response| {
        response.data = response.data.map(|mut data| {
            space_pad(RESPONSE_BLOCK_SIZE, &mut data.0);
            data
        });
        response
    })
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
                HandleMsg::Redeem { amount, memo, .. }
                if contract_status == ContractStatusLevel::StopAllButRedeems =>
                    {
                        try_redeem(deps, env, None, amount, memo)
                    }
                HandleMsg::RedeemTo {
                    recipient,
                    amount,
                    memo,
                    ..
                } if contract_status == ContractStatusLevel::StopAllButRedeems => {
                    try_redeem(deps, env, Some(recipient), amount, memo)
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
        HandleMsg::Redeem { amount, memo, .. } => try_redeem(deps, env, None, amount, memo),
        HandleMsg::RedeemTo {
            recipient,
            amount,
            memo,
            ..
        } => try_redeem(deps, env, Some(recipient), amount, memo),
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
        QueryMsg::TokenInfo {} => query_token_info(&deps.storage),
        QueryMsg::TokenConfig {} => query_token_config(&deps.storage),
        QueryMsg::ExchangeRate {} => query_exchange_rate(&deps.storage),
        QueryMsg::Minters { .. } => query_minters(deps),
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
                QueryMsg::TransferHistory {
                    address,
                    page,
                    page_size,
                    ..
                } => query_transfers(&deps, &address, page.unwrap_or(0), page_size),
                QueryMsg::TransactionHistory {
                    address,
                    page,
                    page_size,
                    ..
                } => query_txs(&deps, &address, page.unwrap_or(0), page_size),
                QueryMsg::Allowance { owner, spender, .. } => {
                    try_check_allowance(deps, owner, spender)
                }
                _ => panic!("This query type does not require authentication"),
            };
        }
    }

    Ok(to_binary(&QueryAnswer::ViewingKeyError {
        msg: "Wrong viewing key for this address or viewing key not set".to_string(),
    })?)
}

fn query_exchange_rate<S: ReadonlyStorage>(storage: &S) -> QueryResult {
    let config = ReadonlyConfig::from_storage(storage);
    let constants = config.constants()?;

    if constants.deposit_is_enabled || constants.redeem_is_enabled {
        let rate: Uint128;
        let denom: String;
        // if token has more decimals than SCRT, you get magnitudes of SCRT per token
        if constants.decimals >= 6 {
            rate = Uint128(10u128.checked_pow((constants.decimals - 6).into()).unwrap());
            denom = "SCRT".to_string();
            // if token has less decimals, you get magnitudes token for SCRT
        } else {
            rate = Uint128(10u128.checked_pow((6 - constants.decimals).into()).unwrap());
            denom = constants.symbol;
        }
        return to_binary(&QueryAnswer::ExchangeRate { rate, denom });
    }
    to_binary(&QueryAnswer::ExchangeRate {
        rate: Uint128(0),
        denom: "Neither deposit nor redeem is enabled for this token.".to_string(),
    })
}

fn query_token_info<S: ReadonlyStorage>(storage: &S) -> QueryResult {
    let config = ReadonlyConfig::from_storage(storage);
    let constants = config.constants()?;

    let total_supply = if constants.total_supply_is_public {
        Some(Uint128(config.total_supply()))
    } else {
        None
    };

    to_binary(&QueryAnswer::TokenInfo {
        name: constants.name,
        symbol: constants.symbol,
        decimals: constants.decimals,
        total_supply,
    })
}

// fn query_lottery_info<S: Storage>(storage: &S) -> QueryResult {
//     let lottery = lottery_read(&storage).load()?;
//     to_binary(&QueryAnswer::LotteryInfo {
//         start_height: lottery.start_height,
//         end_height: lottery.end_height
//     })
// }

fn query_token_config<S: ReadonlyStorage>(storage: &S) -> QueryResult {
    let config = ReadonlyConfig::from_storage(storage);
    let constants = config.constants()?;

    to_binary(&QueryAnswer::TokenConfig {
        public_total_supply: constants.total_supply_is_public,
        deposit_enabled: constants.deposit_is_enabled,
        redeem_enabled: constants.redeem_is_enabled,
        mint_enabled: constants.mint_is_enabled,
        burn_enabled: constants.burn_is_enabled,
    })
}

pub fn query_transfers<S: Storage, A: Api, Q: Querier>(
    deps: &Extern<S, A, Q>,
    account: &HumanAddr,
    page: u32,
    page_size: u32,
) -> StdResult<Binary> {
    let address = deps.api.canonical_address(account)?;
    let txs = get_transfers(&deps.api, &deps.storage, &address, page, page_size)?;

    let result = QueryAnswer::TransferHistory { txs };
    to_binary(&result)
}

pub fn query_txs<S: Storage, A: Api, Q: Querier>(
    deps: &Extern<S, A, Q>,
    account: &HumanAddr,
    page: u32,
    page_size: u32,
) -> StdResult<Binary> {
    let address = deps.api.canonical_address(account)?;
    let txs = get_txs(&deps.api, &deps.storage, &address, page, page_size)?;

    let result = QueryAnswer::TransactionHistory { txs };
    to_binary(&result)
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

fn query_minters<S: Storage, A: Api, Q: Querier>(deps: &Extern<S, A, Q>) -> StdResult<Binary> {
    let minters = ReadonlyConfig::from_storage(&deps.storage).minters();

    let response = QueryAnswer::Minters { minters };
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

    let mut validator_set = get_validator_set(&mut deps.storage)?;
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
    let weights: Vec<u128> = (&a_lottery.entries).into_iter().map(|(_, v, l)|
        if ((a_lottery.end_height - l) / a_lottery.duration) > 1 {
            v.u128()
        } else {
            v.u128() * ((a_lottery.end_height - l) / a_lottery.duration).to_u128().unwrap()
        }
    ).collect();


    log_string(&mut deps.storage).save(&format!("Number of entries = {}", &weights.len()))?;

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

    let winner_human = &deps.api.human_address(&winner.clone()).unwrap();
    log_string(&mut deps.storage).save(&format!("And the winner is {}", winner_human.as_str()))?;

    messages.push(withdraw_to_winner(&validator, &winner_human.clone()));

    let rewards = get_rewards(&deps.querier, &env.contract.address).unwrap();
    let logs = vec![
        log("winner", winner_human.as_str()),
        log("amount", &rewards.to_string()),
    ];

    store_win(
        &mut deps.storage,
        &winner,
        rewards,
        constants.symbol,
        None,
    )?;

    let res = HandleResponse {
        messages,
        log: logs,
        data: Some(to_binary(&HandleAnswer::ClaimRewards {
            status: Success,
            winner: winner_human.clone(),
        })?),
    };

    Ok(res)
}

fn valid_amount(amt: u128) -> bool {
    amt >= 1000000
}

pub fn try_check_allowance<S: Storage, A: Api, Q: Querier>(
    deps: &Extern<S, A, Q>,
    owner: HumanAddr,
    spender: HumanAddr,
) -> StdResult<Binary> {
    let owner_address = deps.api.canonical_address(&owner)?;
    let spender_address = deps.api.canonical_address(&spender)?;

    let allowance = read_allowance(&deps.storage, &owner_address, &spender_address)?;

    let response = QueryAnswer::Allowance {
        owner,
        spender,
        allowance: Uint128(allowance.amount),
        expiration: allowance.expiration,
    };
    to_binary(&response)
}

fn try_deposit<S: Storage, A: Api, Q: Querier>(
    deps: &mut Extern<S, A, Q>,
    env: Env,
    memo: Option<String>,
) -> StdResult<HandleResponse> {
    let constants = Config::from_storage(&mut deps.storage).constants()?;
    if !constants.deposit_is_enabled {
        return Err(StdError::generic_err(
            "Deposit functionality is not enabled for this token.",
        ));
    }

    let mut amount_wrap = Uint128::zero();

    for coin in &env.message.sent_funds {
        if coin.denom == "uscrt" {
            amount_wrap = coin.amount
        }
    }

    let amount = amount_wrap.u128();
    if !valid_amount(amount) {
        return Err(StdError::generic_err(
            "Must deposit a minimum of 1000000 uscrt, or 1 scrt",
        ));
    }

    let mut config = Config::from_storage(&mut deps.storage);
    let total_supply = config.total_supply();
    if let Some(total_supply) = total_supply.checked_add(amount) {
        config.set_total_supply(total_supply);
    } else {
        return Err(StdError::generic_err(
            "This deposit would overflow the currency's total supply",
        ));
    }

    let sender_address = deps.api.canonical_address(&env.message.sender)?;
    let mut balances = Balances::from_storage(&mut deps.storage);
    let account_balance = balances.balance(&sender_address);
    if let Some(account_balance) = account_balance.checked_add(amount) {
        balances.set_account_balance(&sender_address, account_balance);
    } else {
        return Err(StdError::generic_err(
            "This deposit would overflow your balance",
        ));
    }

    store_deposit(
        &mut deps.storage,
        &sender_address,
        amount_wrap,
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
        Uint128::from(account_balance + amount),
        start_height,
    ));

    &a_lottery.entropy.extend(&env.block.height.to_be_bytes());
    &a_lottery.entropy.extend(&env.block.time.to_be_bytes());
    lottery(&mut deps.storage).save(&a_lottery);

    let mut messages: Vec<CosmosMsg> = vec![];

    let mut validator_set = get_validator_set(&deps.storage)?;
    let validator = validator_set.stake(amount_wrap.u128())?;
    messages.push(stake(&validator, amount_wrap.u128()));

    let res = HandleResponse {
        messages,
        log: vec![],
        data: Some(to_binary(&HandleAnswer::Deposit { status: Success })?),
    };

    Ok(res)
}

fn try_redeem<S: Storage, A: Api, Q: Querier>(
    deps: &mut Extern<S, A, Q>,
    env: Env,
    redeem_to: Option<HumanAddr>,
    amount: Uint128,
    memo: Option<String>,
) -> StdResult<HandleResponse> {
    let amount_raw = amount.u128();

    let mut config = Config::from_storage(&mut deps.storage);
    let constants = config.constants()?;
    if !constants.redeem_is_enabled {
        return Err(StdError::generic_err(
            "Redeem functionality is not enabled for this token.",
        ));
    }
    let total_supply = config.total_supply();
    if let Some(total_supply) = total_supply.checked_sub(amount_raw) {
        config.set_total_supply(total_supply);
    } else {
        return Err(StdError::generic_err(
            "You are trying to redeem more tokens than what is available in the total supply",
        ));
    }

    let sender_address = deps.api.canonical_address(&env.message.sender)?;

    let mut balances = Balances::from_storage(&mut deps.storage);
    let account_balance = balances.balance(&sender_address);

    if let Some(account_balance) = account_balance.checked_sub(amount_raw) {
        balances.set_account_balance(&sender_address, account_balance);
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
        constants.symbol,
        memo,
    )?;

    let res = HandleResponse {
        messages,
        log: vec![],
        data: Some(to_binary(&HandleAnswer::Redeem { status: Success })?),
    };

    Ok(res)
}


fn try_add_receiver_api_callback<S: ReadonlyStorage>(
    messages: &mut Vec<CosmosMsg>,
    storage: &S,
    recipient: &HumanAddr,
    msg: Option<Binary>,
    sender: HumanAddr,
    from: HumanAddr,
    amount: Uint128,
) -> StdResult<()> {
    let receiver_hash = get_receiver_hash(storage, recipient);
    if let Some(receiver_hash) = receiver_hash {
        let receiver_hash = receiver_hash?;
        let receiver_msg = Snip20ReceiveMsg::new(sender, from, amount, msg);
        let callback_msg = receiver_msg.into_cosmos_msg(receiver_hash, recipient.clone())?;

        messages.push(callback_msg);
    }
    Ok(())
}


fn insufficient_allowance(allowance: u128, required: u128) -> StdError {
    StdError::generic_err(format!(
        "insufficient allowance: allowance={}, required={}",
        allowance, required
    ))
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

fn is_valid_name(name: &str) -> bool {
    let len = name.len();
    len >= 3 && len <= 30
}

fn is_valid_symbol(symbol: &str) -> bool {
    let len = symbol.len();
    let len_is_valid = 3 <= len && len <= 6;

    // TODO is a number at the 0th idx of a sym, valid?
    len_is_valid
        && symbol
        .bytes()
        .all(|byte| (byte >= b'A' && byte <= b'Z') || (b'0' <= byte && byte <= b'9'))
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
    use cosmwasm_std::{from_binary, BlockInfo, ContractInfo, MessageInfo, QueryResponse, WasmMsg, Decimal, FullDelegation, Validator};
    use std::any::Any;

    // Helper functions

    fn init_helper(
        initial_balances: Vec<InitialBalance>,
    ) -> (
        StdResult<InitResponse>,
        Extern<MockStorage, MockApi, MockQuerier>,
    ) {
        let mut deps = mock_dependencies(20, &[]);
        let env = mock_env("instantiator", &[]);

        let init_msg = InitMsg {
            name: "sec-sec".to_string(),
            admin: Some(HumanAddr("admin".to_string())),
            symbol: "SECSEC".to_string(),
            decimals: 8,
            initial_balances: Some(initial_balances),
            prng_seed: Binary::from("lolz fun yay".as_bytes()),
            config: None,
        };

        (init(&mut deps, env, init_msg), deps)
    }

    fn init_helper_with_config(
        initial_balances: Vec<InitialBalance>,
        enable_deposit: bool,
        enable_redeem: bool,
        enable_mint: bool,
        enable_burn: bool,
        contract_bal: u128,
        validator: String,
    ) -> Extern<MockStorage, MockApi, MockQuerier> {
        let mut deps = mock_dependencies(
            20,
            &[Coin {
                denom: "uscrt".to_string(),
                amount: Uint128(contract_bal),
            }],
        );
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

        let env = mock_env("instantiator", &[]);
        let init_config: InitConfig = from_binary(&Binary::from(
            format!(
                "{{\"public_total_supply\":false,
                    \"enable_deposit\":{},
                    \"enable_redeem\":{},
                    \"enable_mint\":{},
                    \"validator\":\"{}\",
                    \"enable_burn\":{}}}",
                enable_deposit, enable_redeem, enable_mint, validator, enable_burn
            )
                .as_bytes(),
        ))
            .unwrap();
        let init_msg = InitMsg {
            name: "sec-sec".to_string(),
            admin: Some(HumanAddr("admin".to_string())),
            symbol: "SECSEC".to_string(),
            decimals: 8,
            initial_balances: Some(initial_balances),
            prng_seed: Binary::from("lolz fun yay".as_bytes()),
            config: Some(init_config),
        };

        let result = init(&mut deps, env, init_msg);
        assert!(result.is_ok(), "Init failed: {}", result.err().unwrap());

        deps
    }

    /// Will return a ViewingKey only for the first account in `initial_balances`
    fn auth_query_helper(
        initial_balances: Vec<InitialBalance>,
    ) -> (ViewingKey, Extern<MockStorage, MockApi, MockQuerier>) {
        let (init_result, mut deps) = init_helper(initial_balances.clone());
        assert!(
            init_result.is_ok(),
            "Init failed: {}",
            init_result.err().unwrap()
        );

        let account = initial_balances[0].address.clone();
        let create_vk_msg = HandleMsg::CreateViewingKey {
            entropy: "42".to_string(),
            padding: None,
        };
        let handle_response = handle(&mut deps, mock_env(account.0, &[]), create_vk_msg).unwrap();
        let vk = match from_binary(&handle_response.data.unwrap()).unwrap() {
            HandleAnswer::CreateViewingKey { key } => key,
            _ => panic!("Unexpected result from handle"),
        };

        (vk, deps)
    }

    fn extract_error_msg<T: Any>(error: StdResult<T>) -> String {
        match error {
            Ok(response) => {
                let bin_err = (&response as &dyn Any)
                    .downcast_ref::<QueryResponse>()
                    .expect("An error was expected, but no error could be extracted");
                match from_binary(bin_err).unwrap() {
                    QueryAnswer::ViewingKeyError { msg } => msg,
                    _ => panic!("Unexpected query answer"),
                }
            }
            Err(err) => match err {
                StdError::GenericErr { msg, .. } => msg,
                _ => panic!("Unexpected result from init"),
            },
        }
    }

    fn ensure_success(handle_result: HandleResponse) -> bool {
        let handle_result: HandleAnswer = from_binary(&handle_result.data.unwrap()).unwrap();

        match handle_result {
            HandleAnswer::Deposit { status }
            | HandleAnswer::Redeem { status }
            | HandleAnswer::Send { status }
            | HandleAnswer::Burn { status }
            | HandleAnswer::RegisterReceive { status }
            | HandleAnswer::SetViewingKey { status }
            | HandleAnswer::SendFrom { status }
            | HandleAnswer::BurnFrom { status }
            | HandleAnswer::Mint { status }
            | HandleAnswer::ChangeAdmin { status }
            | HandleAnswer::SetContractStatus { status }
            | HandleAnswer::SetMinters { status }
            | HandleAnswer::AddMinters { status }
            | HandleAnswer::RemoveMinters { status } => {
                matches!(status, ResponseStatus::Success {..})
            }
            _ => panic!("HandleAnswer not supported for success extraction"),
        }
    }

    // Init tests

    #[test]
    fn test_init_sanity() {
        let init_amt = 10000000;
        let deps = init_helper_with_config(
            vec![InitialBalance {
                address: HumanAddr("bob".to_string()),
                amount: Uint128(init_amt),
            }],
            true,
            true,
            true,
            true,
            0,
            "v".to_string(),
        );
        let config = ReadonlyConfig::from_storage(&deps.storage);
        let constants = config.constants().unwrap();
        assert_eq!(config.total_supply(), init_amt);
        assert_eq!(config.contract_status(), ContractStatusLevel::NormalRun);
        assert_eq!(constants.name, "sec-sec".to_string());
        assert_eq!(constants.admin, HumanAddr("admin".to_string()));
        assert_eq!(constants.symbol, "SECSEC".to_string());
        assert_eq!(constants.decimals, 8);
        assert_eq!(
            constants.prng_seed,
            sha_256("lolz fun yay".to_owned().as_bytes())
        );
        assert_eq!(constants.total_supply_is_public, false);
    }

    #[test]
    fn test_total_supply_overflow() {
        let _deps = init_helper_with_config(
            vec![InitialBalance {
                address: HumanAddr("lebron".to_string()),
                amount: Uint128(1000000000),
            }],
            true,
            true,
            true,
            true,
            0,
            "v".to_string(),
        );

        let (init_result, _deps) = init_helper(vec![
            InitialBalance {
                address: HumanAddr("lebron".to_string()),
                amount: Uint128(u128::max_value()),
            },
            InitialBalance {
                address: HumanAddr("giannis".to_string()),
                amount: Uint128(1000000000000),
            },
        ]);
        let error = extract_error_msg(init_result);
        assert_eq!(
            error,
            "The sum of all initial balances exceeds the maximum possible total supply"
        );
    }

    // Handle tests

    #[test]
    fn test_handle_create_viewing_key() {
        let mut deps = init_helper_with_config(
            vec![InitialBalance {
                address: HumanAddr("butler".to_string()),
                amount: Uint128(5000000),
            }],
            false,
            true,
            false,
            false,
            1000,
            "v".to_string(),
        );

        let handle_msg = HandleMsg::CreateViewingKey {
            entropy: "".to_string(),
            padding: None,
        };
        let handle_result = handle(&mut deps, mock_env("bob", &[]), handle_msg);
        assert!(
            handle_result.is_ok(),
            "handle() failed: {}",
            handle_result.err().unwrap()
        );
        let answer: HandleAnswer = from_binary(&handle_result.unwrap().data.unwrap()).unwrap();

        let key = match answer {
            HandleAnswer::CreateViewingKey { key } => key,
            _ => panic!("NOPE"),
        };
        let bob_canonical = deps
            .api
            .canonical_address(&HumanAddr("bob".to_string()))
            .unwrap();
        let saved_vk = read_viewing_key(&deps.storage, &bob_canonical).unwrap();
        assert!(key.check_viewing_key(saved_vk.as_slice()));
    }

    #[test]
    fn test_handle_set_viewing_key() {
        let mut deps = init_helper_with_config(
            vec![InitialBalance {
                address: HumanAddr("bob".to_string()),
                amount: Uint128(10000000),
            }],
            true,
            true,
            true,
            true,
            0,
            "v".to_string(),
        );

        // Set VK
        let handle_msg = HandleMsg::SetViewingKey {
            key: "hi lol".to_string(),
            padding: None,
        };
        let handle_result = handle(&mut deps, mock_env("bob", &[]), handle_msg);
        let unwrapped_result: HandleAnswer =
            from_binary(&handle_result.unwrap().data.unwrap()).unwrap();
        assert_eq!(
            to_binary(&unwrapped_result).unwrap(),
            to_binary(&HandleAnswer::SetViewingKey {
                status: ResponseStatus::Success
            })
                .unwrap(),
        );

        // Set valid VK
        let actual_vk = ViewingKey("x".to_string().repeat(VIEWING_KEY_SIZE));
        let handle_msg = HandleMsg::SetViewingKey {
            key: actual_vk.0.clone(),
            padding: None,
        };
        let handle_result = handle(&mut deps, mock_env("bob", &[]), handle_msg);
        let unwrapped_result: HandleAnswer =
            from_binary(&handle_result.unwrap().data.unwrap()).unwrap();
        assert_eq!(
            to_binary(&unwrapped_result).unwrap(),
            to_binary(&HandleAnswer::SetViewingKey { status: Success }).unwrap(),
        );
        let bob_canonical = deps
            .api
            .canonical_address(&HumanAddr("bob".to_string()))
            .unwrap();
        let saved_vk = read_viewing_key(&deps.storage, &bob_canonical).unwrap();
        assert!(actual_vk.check_viewing_key(&saved_vk));
    }


    fn handle_burn_from_setup(
        addr: HumanAddr,
        init_amount: u128,
        enable_burn: bool,
    ) -> Extern<MockStorage, MockApi, MockQuerier> {
        let deps = init_helper_with_config(
            vec![InitialBalance {
                address: addr,
                amount: Uint128(init_amount),
            }],
            true,
            false,
            false,
            enable_burn,
            0,
            "v".to_string(),
        );

        deps
    }


    fn check_handle_result(r: StdResult<HandleResponse>) {
        assert!(r.is_ok(), "handle() failed: {}", r.err().unwrap());
    }


    #[test]
    fn test_handle_change_admin() {
        let mut deps = init_helper_with_config(
            vec![InitialBalance {
                address: HumanAddr("butler".to_string()),
                amount: Uint128(50000000),
            }],
            false,
            true,
            false,
            false,
            1000,
            "v".to_string(),
        );

        let handle_msg = HandleMsg::ChangeAdmin {
            address: HumanAddr("bob".to_string()),
            padding: None,
        };
        let handle_result = handle(&mut deps, mock_env("admin", &[]), handle_msg);
        assert!(
            handle_result.is_ok(),
            "handle() failed: {}",
            handle_result.err().unwrap()
        );

        let admin = ReadonlyConfig::from_storage(&deps.storage)
            .constants()
            .unwrap()
            .admin;
        assert_eq!(admin, HumanAddr("bob".to_string()));
    }

    #[test]
    fn test_handle_set_contract_status() {
        let mut deps = init_helper_with_config(
            vec![InitialBalance {
                address: HumanAddr("admin".to_string()),
                amount: Uint128(1000000),
            }],
            true,
            true,
            true,
            true,
            0,
            "v".to_string(),
        );

        let handle_msg = HandleMsg::SetContractStatus {
            level: ContractStatusLevel::StopAll,
            padding: None,
        };
        let handle_result = handle(&mut deps, mock_env("admin", &[]), handle_msg);
        assert!(
            handle_result.is_ok(),
            "handle() failed: {}",
            handle_result.err().unwrap()
        );

        let contract_status = ReadonlyConfig::from_storage(&deps.storage).contract_status();
        assert!(matches!(contract_status, ContractStatusLevel::StopAll{..}));
    }

    fn handle_redeem_setup(
        addr: HumanAddr,
        init_amount: u128,
        contract_balance: u128,
        enable_redeem: bool,
    ) -> Extern<MockStorage, MockApi, MockQuerier> {
        let deps = init_helper_with_config(
            vec![InitialBalance {
                address: addr,
                amount: Uint128(init_amount),
            }],
            true,
            enable_redeem,
            false,
            false,
            contract_balance,
            "v".to_string(),
        );

        deps
    }

    #[test]
    fn test_handle_redeem_disabled() {
        let seg_addr = HumanAddr("segfaultdoc".to_string());
        let mut deps = handle_redeem_setup(seg_addr.clone(), 500000000, 0, false);

        let handle_msg = HandleMsg::Redeem {
            amount: Uint128(1000),
            denom: None,
            memo: None,
            padding: None,
        };
        let handle_result = handle(&mut deps, mock_env(seg_addr.to_string(), &[]), handle_msg);
        let error = extract_error_msg(handle_result);
        assert!(error.contains("Redeem functionality is not enabled for this token."));
    }

    #[test]
    fn test_handle_redeem_more_than_reserve() {
        let seg_addr = HumanAddr("segfaultdoc".to_string());
        let mut deps = handle_redeem_setup(seg_addr.clone(), 500000000, 1000, true);

        // try to redeem more than reserve
        let handle_msg = HandleMsg::Redeem {
            amount: Uint128(2000),
            denom: None,
            memo: None,
            padding: None,
        };
        let handle_result = handle(&mut deps, mock_env(seg_addr.to_string(), &[]), handle_msg);
    }

    #[test]
    fn test_handle_redeem_happy_path() {
        let seg_addr = HumanAddr("segfaultdoc".to_string());
        let init_amt = 45000000;
        let mut deps = handle_redeem_setup(seg_addr.clone(), init_amt, 2000, true);

        let redeem_amt = 45000000;
        let handle_msg = HandleMsg::Redeem {
            amount: Uint128(redeem_amt),
            denom: None,
            memo: None,
            padding: None,
        };
        check_handle_result(handle(
            &mut deps,
            mock_env(seg_addr.to_string(), &[]),
            handle_msg,
        ));

        let balances = ReadonlyBalances::from_storage(&deps.storage);
        let canonical = deps.api.canonical_address(&seg_addr).unwrap();
        assert_eq!(balances.account_amount(&canonical), init_amt - redeem_amt)
    }

    fn handle_deposit_setup(
        addr: HumanAddr,
        init_amount: u128,
        enable_deposit: bool,
    ) -> Extern<MockStorage, MockApi, MockQuerier> {
        let deps = init_helper_with_config(
            vec![InitialBalance {
                address: addr,
                amount: Uint128(init_amount),
            }],
            enable_deposit,
            false,
            false,
            false,
            0,
            "v".to_string(),
        );

        deps
    }

    #[test]
    fn test_handle_deposit_happy_path() {
        let addr = HumanAddr("segfaultdoc".to_string());
        let mut deps = handle_deposit_setup(addr.clone(), 50000000, true);

        let handle_msg = HandleMsg::Deposit {
            memo: None,
            padding: None,
        };
        let handle_result = handle(
            &mut deps,
            mock_env(
                addr.clone().to_string(),
                &[Coin {
                    denom: "uscrt".to_string(),
                    amount: Uint128(1000000),
                }],
            ),
            handle_msg,
        );
        assert!(
            handle_result.is_ok(),
            "handle() failed: {}",
            handle_result.err().unwrap()
        );

        let balances = ReadonlyBalances::from_storage(&deps.storage);
        let canonical = deps.api.canonical_address(&addr).unwrap();
        assert_eq!(balances.account_amount(&canonical), 51000000)
    }

    #[test]
    fn test_handle_deposit_disabled() {
        let addr = HumanAddr("segfaultdoc".to_string());
        let mut deps = handle_deposit_setup(addr.clone(), 5000000, false);

        let handle_msg = HandleMsg::Deposit {
            memo: None,
            padding: None,
        };
        let handle_result = handle(
            &mut deps,
            mock_env(
                addr.clone().to_string(),
                &[Coin {
                    denom: "uscrt".to_string(),
                    amount: Uint128(1000),
                }],
            ),
            handle_msg,
        );
        let error = extract_error_msg(handle_result);
        assert!(error.contains("Deposit functionality is not enabled for this token."));
    }

    #[test]
    fn test_handle_deposit_min_amount() {
        let addr = HumanAddr("segfaultdoc".to_string());
        let mut deps = handle_deposit_setup(addr.clone(), 500000000, true);
        let handle_msg = HandleMsg::Deposit {
            memo: None,
            padding: None,
        };
        let handle_result = handle(
            &mut deps,
            mock_env(
                addr.clone().to_string(),
                &[Coin {
                    denom: "uscrt".to_string(),
                    amount: Uint128(1000),
                }],
            ),
            handle_msg,
        );
        let error = extract_error_msg(handle_result);
        assert!(error.contains("Must deposit a minimum of 1000000 uscrt, or 1 scrt"));
    }


    // Query tests
    #[test]
    fn test_authenticated_queries() {
        let giannis_addr = HumanAddr("giannis".to_string());
        let mut deps = init_helper_with_config(
            vec![InitialBalance {
                address: giannis_addr.clone(),
                amount: Uint128(5000000000),
            }],
            false,
            false,
            false,
            true,
            0,
            "v".to_string(),
        );

        let no_vk_yet_query_msg = QueryMsg::Balance {
            address: giannis_addr.clone(),
            key: "no_vk_yet".to_string(),
        };
        let query_result = query(&deps, no_vk_yet_query_msg);
        let error = extract_error_msg(query_result);
        assert_eq!(
            error,
            "Wrong viewing key for this address or viewing key not set".to_string()
        );

        let create_vk_msg = HandleMsg::CreateViewingKey {
            entropy: "34".to_string(),
            padding: None,
        };
        let handle_response = handle(&mut deps, mock_env("giannis", &[]), create_vk_msg).unwrap();
        let vk = match from_binary(&handle_response.data.unwrap()).unwrap() {
            HandleAnswer::CreateViewingKey { key } => key,
            _ => panic!("Unexpected result from handle"),
        };

        let query_balance_msg = QueryMsg::Balance {
            address: giannis_addr.clone(),
            key: vk.0,
        };

        let query_response = query(&deps, query_balance_msg).unwrap();
        let balance = match from_binary(&query_response).unwrap() {
            QueryAnswer::Balance { amount } => amount,
            _ => panic!("Unexpected result from query"),
        };
        assert_eq!(balance, Uint128(5000000000));
        let wrong_vk_query_msg = QueryMsg::Balance {
            address: giannis_addr.clone(),
            key: "wrong_vk".to_string(),
        };
        let query_result = query(&deps, wrong_vk_query_msg);
        let error = extract_error_msg(query_result);
        assert_eq!(
            error,
            "Wrong viewing key for this address or viewing key not set".to_string()
        );
    }

    #[test]
    fn test_query_token_info() {
        let init_name = "sec-sec".to_string();
        let init_admin = HumanAddr("admin".to_string());
        let init_symbol = "SECSEC".to_string();
        let init_decimals = 8;
        let init_config: InitConfig = from_binary(&Binary::from(
            format!(
                "{{\"public_total_supply\":{},
            \"enable_deposit\":{},
            \"enable_redeem\":{},
            \"enable_mint\":{},
            \"validator\": \"v\",
            \"enable_burn\":{}}}",
                true, false, false, true, false
            )
                .as_bytes(),
        ))
            .unwrap();

        let init_supply = Uint128(50000000);
        let validators = &[Validator {
            address: HumanAddr("v".to_string()),
            commission: Decimal::percent(1),
            max_commission: Decimal::percent(2),
            max_change_rate: Decimal::percent(3),
        }];
        let delegations = &[FullDelegation {
            delegator: Default::default(),
            validator: Default::default(),
            amount: Default::default(),
            can_redelegate: Default::default(),
            accumulated_rewards: Default::default(),
        }];

        let mut deps = mock_dependencies(20, &[]);
        deps.querier
            .update_staking("SECSEC", validators, delegations);
        let env = mock_env("instantiator", &[]);
        let init_msg = InitMsg {
            name: init_name.clone(),
            admin: Some(init_admin.clone()),
            symbol: init_symbol.clone(),
            decimals: init_decimals.clone(),
            initial_balances: Some(vec![InitialBalance {
                address: HumanAddr("giannis".to_string()),
                amount: init_supply,
            }]),
            prng_seed: Binary::from("lolz fun yay".as_bytes()),
            config: Some(init_config),
        };
        let init_result = init(&mut deps, env, init_msg);
        assert!(
            init_result.is_ok(),
            "Init failed: {}",
            init_result.err().unwrap()
        );

        let query_msg = QueryMsg::TokenInfo {};
        let query_result = query(&deps, query_msg);
        assert!(
            query_result.is_ok(),
            "Init failed: {}",
            query_result.err().unwrap()
        );
        let query_answer: QueryAnswer = from_binary(&query_result.unwrap()).unwrap();
        match query_answer {
            QueryAnswer::TokenInfo {
                name,
                symbol,
                decimals,
                total_supply,
            } => {
                assert_eq!(name, init_name);
                assert_eq!(symbol, init_symbol);
                assert_eq!(decimals, init_decimals);
                assert_eq!(total_supply, Some(init_supply));
            }
            _ => panic!("unexpected"),
        }
    }

    #[test]
    fn test_query_token_config() {
        let init_name = "sec-sec".to_string();
        let init_admin = HumanAddr("admin".to_string());
        let init_symbol = "SECSEC".to_string();
        let init_decimals = 8;
        let init_config: InitConfig = from_binary(&Binary::from(
            format!(
                "{{\"public_total_supply\":{},
            \"enable_deposit\":{},
            \"enable_redeem\":{},
            \"enable_mint\":{},
            \"validator\": \"v\",
            \"enable_burn\":{}}}",
                true, false, false, true, false
            )
                .as_bytes(),
        ))
            .unwrap();

        let init_supply = Uint128(50000000);
        let validators = &[Validator {
            address: HumanAddr("v".to_string()),
            commission: Decimal::percent(1),
            max_commission: Decimal::percent(2),
            max_change_rate: Decimal::percent(3),
        }];
        let delegations = &[FullDelegation {
            delegator: Default::default(),
            validator: Default::default(),
            amount: Default::default(),
            can_redelegate: Default::default(),
            accumulated_rewards: Default::default(),
        }];
        let mut deps = mock_dependencies(20, &[]);
        deps.querier
            .update_staking("SECSEC", validators, delegations);
        let env = mock_env("instantiator", &[]);
        let init_msg = InitMsg {
            name: init_name.clone(),
            admin: Some(init_admin.clone()),
            symbol: init_symbol.clone(),
            decimals: init_decimals.clone(),
            initial_balances: Some(vec![InitialBalance {
                address: HumanAddr("giannis".to_string()),
                amount: init_supply,
            }]),
            prng_seed: Binary::from("lolz fun yay".as_bytes()),
            config: Some(init_config),
        };
        let init_result = init(&mut deps, env, init_msg);
        assert!(
            init_result.is_ok(),
            "Init failed: {}",
            init_result.err().unwrap()
        );

        let query_msg = QueryMsg::TokenConfig {};
        let query_result = query(&deps, query_msg);
        assert!(
            query_result.is_ok(),
            "Init failed: {}",
            query_result.err().unwrap()
        );
        let query_answer: QueryAnswer = from_binary(&query_result.unwrap()).unwrap();
        match query_answer {
            QueryAnswer::TokenConfig {
                public_total_supply,
                deposit_enabled,
                redeem_enabled,
                mint_enabled,
                burn_enabled,
            } => {
                assert_eq!(public_total_supply, true);
                assert_eq!(deposit_enabled, false);
                assert_eq!(redeem_enabled, false);
                assert_eq!(mint_enabled, true);
                assert_eq!(burn_enabled, false);
            }
            _ => panic!("unexpected"),
        }
    }

    #[test]
    fn test_query_exchange_rate() {
        // test more dec than SCRT
        let init_name = "sec-sec".to_string();
        let init_admin = HumanAddr("admin".to_string());
        let init_symbol = "SECSEC".to_string();
        let init_decimals = 8;

        let init_supply = Uint128(50000000);
        let validators = &[Validator {
            address: HumanAddr("v".to_string()),
            commission: Decimal::percent(1),
            max_commission: Decimal::percent(2),
            max_change_rate: Decimal::percent(3),
        }];
        let delegations = &[FullDelegation {
            delegator: Default::default(),
            validator: Default::default(),
            amount: Default::default(),
            can_redelegate: Default::default(),
            accumulated_rewards: Default::default(),
        }];

        let mut deps = mock_dependencies(20, &[]);
        deps.querier
            .update_staking("SECSEC", validators, delegations);
        let env = mock_env("instantiator", &[]);
        let init_config: InitConfig = from_binary(&Binary::from(
            format!(
                "{{\"public_total_supply\":{},
            \"enable_deposit\":{},
            \"enable_redeem\":{},
            \"enable_mint\":{},
            \"validator\": \"v\",
            \"enable_burn\":{}}}",
                true, true, false, false, false
            )
                .as_bytes(),
        ))
            .unwrap();
        let init_msg = InitMsg {
            name: init_name.clone(),
            admin: Some(init_admin.clone()),
            symbol: init_symbol.clone(),
            decimals: init_decimals.clone(),
            initial_balances: Some(vec![InitialBalance {
                address: HumanAddr("giannis".to_string()),
                amount: init_supply,
            }]),
            prng_seed: Binary::from("lolz fun yay".as_bytes()),
            config: Some(init_config),
        };
        let init_result = init(&mut deps, env, init_msg);
        assert!(
            init_result.is_ok(),
            "Init failed: {}",
            init_result.err().unwrap()
        );

        let query_msg = QueryMsg::ExchangeRate {};
        let query_result = query(&deps, query_msg);
        assert!(
            query_result.is_ok(),
            "Init failed: {}",
            query_result.err().unwrap()
        );
        let query_answer: QueryAnswer = from_binary(&query_result.unwrap()).unwrap();
        match query_answer {
            QueryAnswer::ExchangeRate { rate, denom } => {
                assert_eq!(rate, Uint128(100));
                assert_eq!(denom, "SCRT");
            }
            _ => panic!("unexpected"),
        }

        // test same number of decimals as SCRT
        let init_name = "sec-sec".to_string();
        let init_admin = HumanAddr("admin".to_string());
        let init_symbol = "SECSEC".to_string();
        let init_decimals = 6;

        let init_supply = Uint128(5000000);

        let mut deps = mock_dependencies(20, &[]);
        deps.querier
            .update_staking("SECSEC", validators, delegations);
        let env = mock_env("instantiator", &[]);
        let init_config: InitConfig = from_binary(&Binary::from(
            format!(
                "{{\"public_total_supply\":{},
            \"enable_deposit\":{},
            \"enable_redeem\":{},
            \"enable_mint\":{},
            \"validator\": \"v\",
            \"enable_burn\":{}}}",
                true, true, false, false, false
            )
                .as_bytes(),
        ))
            .unwrap();
        let init_msg = InitMsg {
            name: init_name.clone(),
            admin: Some(init_admin.clone()),
            symbol: init_symbol.clone(),
            decimals: init_decimals.clone(),
            initial_balances: Some(vec![InitialBalance {
                address: HumanAddr("giannis".to_string()),
                amount: init_supply,
            }]),
            prng_seed: Binary::from("lolz fun yay".as_bytes()),
            config: Some(init_config),
        };
        let init_result = init(&mut deps, env, init_msg);
        assert!(
            init_result.is_ok(),
            "Init failed: {}",
            init_result.err().unwrap()
        );

        let query_msg = QueryMsg::ExchangeRate {};
        let query_result = query(&deps, query_msg);
        assert!(
            query_result.is_ok(),
            "Init failed: {}",
            query_result.err().unwrap()
        );
        let query_answer: QueryAnswer = from_binary(&query_result.unwrap()).unwrap();
        match query_answer {
            QueryAnswer::ExchangeRate { rate, denom } => {
                assert_eq!(rate, Uint128(1));
                assert_eq!(denom, "SCRT");
            }
            _ => panic!("unexpected"),
        }

        // test less decimal places than SCRT
        let init_name = "sec-sec".to_string();
        let init_admin = HumanAddr("admin".to_string());
        let init_symbol = "SECSEC".to_string();
        let init_decimals = 3;

        let init_supply = Uint128(10000000000000);

        let mut deps = mock_dependencies(20, &[]);
        deps.querier
            .update_staking("SECSEC", validators, delegations);

        let env = mock_env("instantiator", &[]);
        let init_config: InitConfig = from_binary(&Binary::from(
            format!(
                "{{\"public_total_supply\":{},
            \"enable_deposit\":{},
            \"enable_redeem\":{},
            \"enable_mint\":{},
            \"validator\": \"v\",
            \"enable_burn\":{}}}",
                true, true, false, false, false
            )
                .as_bytes(),
        ))
            .unwrap();
        let init_msg = InitMsg {
            name: init_name.clone(),
            admin: Some(init_admin.clone()),
            symbol: init_symbol.clone(),
            decimals: init_decimals.clone(),
            initial_balances: Some(vec![InitialBalance {
                address: HumanAddr("giannis".to_string()),
                amount: init_supply,
            }]),
            prng_seed: Binary::from("lolz fun yay".as_bytes()),
            config: Some(init_config),
        };
        let init_result = init(&mut deps, env, init_msg);
        assert!(
            init_result.is_ok(),
            "Init failed: {}",
            init_result.err().unwrap()
        );

        let query_msg = QueryMsg::ExchangeRate {};
        let query_result = query(&deps, query_msg);
        assert!(
            query_result.is_ok(),
            "Init failed: {}",
            query_result.err().unwrap()
        );
        let query_answer: QueryAnswer = from_binary(&query_result.unwrap()).unwrap();
        match query_answer {
            QueryAnswer::ExchangeRate { rate, denom } => {
                assert_eq!(rate, Uint128(1000));
                assert_eq!(denom, "SECSEC");
            }
            _ => panic!("unexpected"),
        }

        // test depost/redeem not enabled
        let init_name = "sec-sec".to_string();
        let init_admin = HumanAddr("admin".to_string());
        let init_symbol = "SECSEC".to_string();
        let init_decimals = 3;

        let init_supply = Uint128(50000000);
        let init_config: InitConfig = from_binary(&Binary::from(
            format!(
                "{{\"public_total_supply\":{},
            \"enable_deposit\":{},
            \"enable_redeem\":{},
            \"enable_mint\":{},
            \"validator\": \"v\",
            \"enable_burn\":{}}}",
                true, false, false, false, false
            )
                .as_bytes(),
        ))
            .unwrap();
        let mut deps = mock_dependencies(20, &[]);
        deps.querier
            .update_staking("SECSEC", validators, delegations);
        let env = mock_env("instantiator", &[]);
        let init_msg = InitMsg {
            name: init_name.clone(),
            admin: Some(init_admin.clone()),
            symbol: init_symbol.clone(),
            decimals: init_decimals.clone(),
            initial_balances: Some(vec![InitialBalance {
                address: HumanAddr("giannis".to_string()),
                amount: init_supply,
            }]),
            prng_seed: Binary::from("lolz fun yay".as_bytes()),
            config: Some(init_config),
        };
        let init_result = init(&mut deps, env, init_msg);
        assert!(
            init_result.is_ok(),
            "Init failed: {}",
            init_result.err().unwrap()
        );

        let query_msg = QueryMsg::ExchangeRate {};
        let query_result = query(&deps, query_msg);
        assert!(
            query_result.is_ok(),
            "Init failed: {}",
            query_result.err().unwrap()
        );
        let query_answer: QueryAnswer = from_binary(&query_result.unwrap()).unwrap();
        match query_answer {
            QueryAnswer::ExchangeRate { rate, denom } => {
                assert_eq!(rate, Uint128(0));
                assert_eq!(
                    denom,
                    "Neither deposit nor redeem is enabled for this token."
                );
            }
            _ => panic!("unexpected"),
        }
    }


    #[test]
    fn test_query_balance() {
        let init_amount = 100000000;
        let mut deps = init_helper_with_config(
            vec![InitialBalance {
                address: HumanAddr("bob".to_string()),
                amount: Uint128(init_amount),
            }],
            true,
            false,
            false,
            true,
            0,
            "v".to_string(),
        );

        let handle_msg = HandleMsg::SetViewingKey {
            key: "key".to_string(),
            padding: None,
        };
        let handle_result = handle(&mut deps, mock_env("bob", &[]), handle_msg);
        let unwrapped_result: HandleAnswer =
            from_binary(&handle_result.unwrap().data.unwrap()).unwrap();
        assert_eq!(
            to_binary(&unwrapped_result).unwrap(),
            to_binary(&HandleAnswer::SetViewingKey {
                status: ResponseStatus::Success
            })
                .unwrap(),
        );

        let query_msg = QueryMsg::Balance {
            address: HumanAddr("bob".to_string()),
            key: "wrong_key".to_string(),
        };
        let query_result = query(&deps, query_msg);
        let error = extract_error_msg(query_result);
        assert!(error.contains("Wrong viewing key"));

        let query_msg = QueryMsg::Balance {
            address: HumanAddr("bob".to_string()),
            key: "key".to_string(),
        };
        let query_result = query(&deps, query_msg);
        let balance = match from_binary(&query_result.unwrap()).unwrap() {
            QueryAnswer::Balance { amount } => amount,
            _ => panic!("Unexpected"),
        };
        assert_eq!(balance, Uint128(init_amount));
    }
}
