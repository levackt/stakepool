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
use crate::state::{get_receiver_hash, lottery, lottery_read, read_viewing_key, write_viewing_key, Config, Constants, Lottery, ReadonlyConfig, last_lottery_results, last_lottery_results_read, LastLotteryResults, RoundStruct, round, round_read};
use crate::validator_set::{get_validator_set, set_validator_set, ValidatorSet};
use crate::viewing_key::{ViewingKey, VIEWING_KEY_SIZE};
use secret_toolkit::storage::{TypedStore, TypedStoreMut};
use crate::types::{UserInfo, RequestedInfo, RewardPool};
use crate::constants::*;

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

    let time = env.block.time;
    let duration = 600u64;


    //Create first lottery
    let a_lottery = Lottery {
        entries: Vec::default(),
        entropy: prng_seed_hashed.to_vec(),
        start_time: time + 1,
        end_time: time + duration + 1,
        seed: prng_seed_hashed.to_vec(),
        duration,
    };

    let last_lottery = LastLotteryResults{
        winner: Default::default(),
        winning_rewards: Uint128(0),
        number_of_entries: Uint128(0)
    };

    last_lottery_results(&mut deps.storage).save(&last_lottery);

    // Save to state
    lottery(&mut deps.storage).save(&a_lottery)?;

    let round_info = RoundStruct {
        pending_staking_rewards: Uint128(0)
    };
    let _ =round(&mut deps.storage).save(&round_info);

    TypedStoreMut::<RewardPool, S>::attach(&mut deps.storage).store(
        REWARD_POOL_KEY,
        &RewardPool {
            total_tokens_staked: Uint128(0),
            total_rewards_restaked: Uint128(0),
        },
    )?;


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
                        try_withdraw(deps, env, amount, memo)
                    },

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
        HandleMsg::Deposit {  .. } => try_deposit(deps, env),
        HandleMsg::Withdraw { amount, memo, .. } => try_withdraw(deps, env,  amount, memo),

        HandleMsg::ClaimRewards {} => claim_rewards(deps, env),

        HandleMsg::TriggerWithdraw {amount,memo,..  }=>trigger_withdraw(deps, env,  amount, memo),

        // Base
        HandleMsg::CreateViewingKey { entropy, .. } => try_create_key(deps, env, entropy),
        HandleMsg::SetViewingKey { key, .. } => try_set_key(deps, env, key),

        // Other
        HandleMsg::ChangeAdmin { address, .. } => change_admin(deps, env, address),
        HandleMsg::SetContractStatus { level, .. } => set_contract_status(deps, env, level),
    };

    pad_response(response)
}

pub fn query<S: Storage, A: Api, Q: Querier>
(deps: &Extern<S, A, Q>, msg: QueryMsg) -> QueryResult {
    match msg {
        QueryMsg::LotteryInfo {} => {
            // query_lottery_info(&deps.storage)
            let lottery = lottery_read(&deps.storage).load()?;
            to_binary(&QueryAnswer::LotteryInfo {
                start_time: lottery.start_time,
                end_time: lottery.end_time,
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
                QueryMsg::Balance { address,..}=>query_deposit(deps, &address),
                // QueryMsg::AvailableForWithdrawl {address,..}=>query_available_tokens_for_withdrawl(deps,env,&address),



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

fn query_deposit<S: Storage, A: Api, Q: Querier>(
    deps: &Extern<S, A, Q>,
    address: &HumanAddr,
) -> StdResult<Binary> {
    let user = TypedStore::attach(&deps.storage)
        .load(address.0.as_bytes())
        .unwrap_or(UserInfo {
            amount_delegated: Default::default(),
            start_time: 0,
            requested_withdraw: RequestedInfo { amount: Uint128(0), time: 0 }
        });

    to_binary(&QueryAnswer::Balance {
        amount: user.amount_delegated,
    })
}

fn query_available_tokens_for_withdrawl<S: Storage, A: Api, Q: Querier>(
    deps: &Extern<S, A, Q>,
    env:Env,
    address: &HumanAddr,
) -> StdResult<Binary> {

    let user = TypedStore::attach(&deps.storage)
        .load(address.0.as_bytes())
        .unwrap_or(UserInfo {
            amount_delegated: Default::default(),
            start_time: 0,
            requested_withdraw: RequestedInfo { amount: Uint128(0), time: 0 }
        });

    if user.requested_withdraw.time + 1814400 <  env.block.time
    {
        return to_binary(&QueryAnswer::AvailableForWithdrawl {
            amount: Uint128(0)
        })
    }

    let contract_balance = deps.querier.query_balance(env.clone().contract.address, "uscrt").unwrap().amount;
    if contract_balance<user.requested_withdraw.amount{
        return to_binary(&QueryAnswer::AvailableForWithdrawl {
            amount: Uint128(0)
        })
    }


    to_binary(&QueryAnswer::AvailableForWithdrawl {
        amount: user.amount_delegated,
    })
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
    validate_end_time(a_lottery.end_time, env.clone())?;
    validate_start_time(a_lottery.start_time, env.clone())?;

    a_lottery.entropy.extend(&env.block.time.to_be_bytes());
    a_lottery.entropy.extend(&env.block.time.to_be_bytes());

    let entries: Vec<_> = (&a_lottery.entries).into_iter().map(|(Address, _, _)| Address).collect();
    let weights: Vec<u128> = (&a_lottery.entries).into_iter().map(|(_, user_staked_amount, deposit_time)|
        if ((a_lottery.end_time - deposit_time) / a_lottery.duration) >= 1 {
            user_staked_amount.u128()
        } else {
            user_staked_amount.u128() * ((a_lottery.end_time - deposit_time) / a_lottery.duration).to_u128().unwrap()
        }
    ).collect();

    // restart the lottery in the after
    a_lottery.start_time = &env.block.time + 1;
    a_lottery.end_time = &env.block.time + a_lottery.duration + 1;
    lottery(&mut deps.storage).save(&a_lottery)?;

    //Finding the winner
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

    //Querying pending_rewards send back from validator
    // let rewards = get_rewards(&deps.querier, &env.contract.address).unwrap();
    let rewards = Uint128(1000);
    let mut newly_allocated_rewards = Uint128(0);
    if rewards > Uint128(0) {
        newly_allocated_rewards = rewards
    }
    let mut current_round: RoundStruct = round_read(&mut deps.storage).load()?;
    let pending_staking_rewards = current_round.pending_staking_rewards;
    current_round.pending_staking_rewards= Uint128(0);
    let _=round(&mut deps.storage).save(&current_round);

    let mut rewards_store = TypedStoreMut::attach(&mut deps.storage);
    let mut reward_pool: RewardPool = rewards_store.load(REWARD_POOL_KEY)?;
    let winning_amount = reward_pool.total_rewards_restaked + newly_allocated_rewards + pending_staking_rewards;

    reward_pool.total_rewards_restaked =Uint128(0);
    rewards_store.store(REWARD_POOL_KEY, &reward_pool)?;

    if winning_amount == Uint128(0) {
        return Err(StdError::generic_err(
            "no rewards available",
        ));
    }
    let mut messages: Vec<CosmosMsg> = vec![];
    let winner_human = deps.api.human_address(&winner.clone()).unwrap();
    messages.push(undelegate(&validator, reward_pool.total_rewards_restaked));


    let mut user = TypedStore::<UserInfo, S>::attach(&deps.storage)
        .load(winner_human.0.as_bytes())
        .unwrap_or(UserInfo { amount_delegated: Uint128(0), start_time: env.block.time, requested_withdraw:RequestedInfo{ amount: Uint128(0),time:env.block.time} }); // NotFound is the only possible error
    user.requested_withdraw.amount=winning_amount;
    user.requested_withdraw.time = env.block.time;
    TypedStoreMut::<UserInfo, S>::attach(&mut deps.storage).store(winner_human.0.as_bytes(), &user)?;


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


    //updating user data
    let mut user = TypedStore::<UserInfo, S>::attach(&deps.storage)
        .load(env.message.sender.0.as_bytes())
        .unwrap_or(UserInfo { amount_delegated: Uint128(0), start_time: env.block.time, requested_withdraw:RequestedInfo{ amount: Uint128(0),time:env.block.time} }); // NotFound is the only possible error

    let sender_address = deps.api.canonical_address(&env.message.sender)?;
    let account_balance = user.amount_delegated.0;
    let start_time = env.block.time;
    if let Some(final_account_balance) = account_balance.checked_add(deposit_amount.0) {
        user.start_time = start_time;
        user.amount_delegated = Uint128::from(final_account_balance);
        TypedStoreMut::<UserInfo, S>::attach(&mut deps.storage).store(env.message.sender.0.as_bytes(), &user)?;
    } else {
        return Err(StdError::generic_err(
            "This deposit would overflow your balance",
        ));
    }

    // update lottery entries
    let mut a_lottery = lottery(&mut deps.storage).load()?;
    if a_lottery.entries.len() > 0 {
        &a_lottery.entries.retain(|(k, _, _)| k != &sender_address);
    }

    &a_lottery.entries.push((
        sender_address.clone(),
        Uint128::from(account_balance + deposit_amount.0),
        start_time,
    ));

    &a_lottery.entropy.extend(&env.block.time.to_be_bytes());
    &a_lottery.entropy.extend(&env.block.time.to_be_bytes());
    lottery(&mut deps.storage).save(&a_lottery);

    let mut current_round: RoundStruct = round(&mut deps.storage).load()?;
    let amount_to_stake = deposit_amount + current_round.pending_staking_rewards;

    //Updating Rewards store
    let rewards_store = TypedStoreMut::attach(&mut deps.storage);
    let mut reward_pool: RewardPool = rewards_store.load(REWARD_POOL_KEY)?;
    reward_pool.total_tokens_staked += deposit_amount;
    reward_pool.total_rewards_restaked +=current_round.pending_staking_rewards;
    TypedStoreMut::attach(&mut deps.storage).store(REWARD_POOL_KEY, &reward_pool)?;

    //Querying pending_rewards send back from validator
    // let rewards = get_rewards(&deps.querier, &env.contract.address).unwrap();
    let rewards = Uint128(1000);
    let mut lp_pending_staking_rewards = Uint128(0);
    if rewards > Uint128(0) {
        lp_pending_staking_rewards = rewards
    }
    //Updating current_round pending rewards
    current_round.pending_staking_rewards = lp_pending_staking_rewards;
    let _=round(&mut deps.storage).save(&current_round);


    let mut messages: Vec<CosmosMsg> = vec![];
    let mut validator_set = get_validator_set(&deps.storage)?;
    let validator = validator_set.stake(amount_to_stake.u128())?;
    messages.push(stake(&validator, amount_to_stake.u128()));


    Ok(HandleResponse {
        messages,
        log: vec![],
        data: Some(to_binary(&HandleAnswer::Deposit { status: Success })?),
    })
}

fn try_withdraw<S: Storage, A: Api, Q: Querier>(
    deps: &mut Extern<S, A, Q>,
    env: Env,
    amount: Option<Uint128>,
    memo: Option<String>,
) -> StdResult<HandleResponse> {
    //loading configs from storage


    let mut user = TypedStore::<UserInfo, S>::attach(&deps.storage)
        .load(env.message.sender.0.as_bytes())
        .unwrap_or(UserInfo { amount_delegated: Uint128(0), start_time: env.block.time, requested_withdraw:RequestedInfo{ amount: Uint128(0),time:env.block.time}  }); // NotFound is the only possible error
    let mut config = Config::from_storage(&mut deps.storage);
    let constants = config.constants()?;
    //Checking if the redeem functionality is enabled
    if !constants.withdraw_is_enabled {
        return Err(StdError::generic_err(
            "Redeem functionality is not enabled for this token.",
        ));
    }

    if env.block.time<user.requested_withdraw.time+1814400{
        return  Err(StdError::generic_err(format!(
            "Your request cannot be completed. Please try again in {} hours ",((user.requested_withdraw.time+1814400-env.block.time)/3600),
        )))
    }

    let withdraw_amount = amount.unwrap_or(user.requested_withdraw.amount);
    let contract_balance = deps.querier.query_balance(env.clone().contract.address, "uscrt").unwrap().amount;

    if withdraw_amount> contract_balance{
        return Err(StdError::generic_err(" Contract balance not enough"))
    }

    if withdraw_amount> user.requested_withdraw.amount{
        return Err(StdError::generic_err("Trying to withdraw more than requested"))
    }

    // Subtracting from user's balance
    let requested_withdraw_state = user.requested_withdraw.amount.0;

    if let Some(_requested_withdraw) = requested_withdraw_state.checked_sub(withdraw_amount.0) {
        user.requested_withdraw.amount= Uint128::from(_requested_withdraw);
        TypedStoreMut::<UserInfo, S>::attach(&mut deps.storage).store(env.message.sender.0.as_bytes(), &user)?;
    } else {
        return Err(StdError::generic_err(format!(
            "insufficient funds to withdraw: Contract balance={}, required={}",
            contract_balance, withdraw_amount
        )));
    }


    let mut messages: Vec<CosmosMsg> = vec![];
    let withdrawl_coins: Vec<Coin> = vec![Coin {
        denom: "uscrt".to_string(),
        amount:withdraw_amount,
    }];

    messages.push(CosmosMsg::Bank(BankMsg::Send {
        from_address: env.contract.address,
        to_address: env.message.sender,
        amount: withdrawl_coins,
    }));



    let res = HandleResponse {
        messages:vec![],
        log: vec![],
        data: Some(to_binary(&HandleAnswer::Withdraw { status: Success })?),
    };

    Ok(res)
}

fn trigger_withdraw<S: Storage, A: Api, Q: Querier>(
    deps: &mut Extern<S, A, Q>,
    env: Env,
    amount: Option<Uint128>,
    memo: Option<String>,
) -> StdResult<HandleResponse> {


    let mut user = TypedStore::<UserInfo, S>::attach(&deps.storage)
        .load(env.message.sender.0.as_bytes())
        .unwrap_or(UserInfo { amount_delegated: Uint128(0), start_time: env.block.time, requested_withdraw:RequestedInfo{ amount: Uint128(0),time:env.block.time}}); // NotFound is the only possible error

    let withdraw_amount = amount.unwrap_or(user.amount_delegated).0;


    //loading configs from storage
    let mut config = Config::from_storage(&mut deps.storage);
    let constants = config.constants()?;
    //Checking if the redeem functionality is enabled
    if !constants.withdraw_is_enabled {
        return Err(StdError::generic_err(
            "Redeem functionality is not enabled for this token.",
        ));
    }


    //Subtracting from user's balance plus updating the lottery
    let account_balance_state = user.amount_delegated.0;
    if let Some(account_balance) = account_balance_state.checked_sub(withdraw_amount) {
        user.amount_delegated= Uint128::from(account_balance);
        user.requested_withdraw.time=env.block.time;
        user.requested_withdraw.amount= Uint128::from(withdraw_amount);
        // updating lottery entries
        let sender_address = deps.api.canonical_address(&env.message.sender)?;
        let mut lottery = lottery(&mut deps.storage).load()?;
        &lottery.entries.retain(|(k, _, _)| k != &sender_address);
        if account_balance_state > 0 {
            &lottery
                .entries
                .push((sender_address.clone(), Uint128::from(account_balance), user.start_time));
        }
        lottery.entropy.extend(&env.block.time.to_be_bytes());
        lottery.entropy.extend(&env.block.time.to_be_bytes());
        TypedStoreMut::<UserInfo, S>::attach(&mut deps.storage).store(env.message.sender.0.as_bytes(), &user)?;
    } else {
        return Err(StdError::generic_err(format!(
            "insufficient funds to redeem: balance={}, required={}",
            account_balance_state, withdraw_amount
        )));
    }

    //Querying pending_rewards send back from validator
    // let rewards = get_rewards(&deps.querier, &env.contract.address).unwrap();
    let rewards = Uint128(1000);
    let mut lp_pending_staking_rewards = Uint128(0);
    if rewards > Uint128(0) {
        lp_pending_staking_rewards = rewards
    }

    let mut current_round: RoundStruct = round(&mut deps.storage).load()?;
    current_round.pending_staking_rewards += lp_pending_staking_rewards;
    let _=round(&mut deps.storage).save(&current_round);

    //updating the reward pool
    let mut rewards_store = TypedStoreMut::attach(&mut deps.storage);
    let mut reward_pool: RewardPool = rewards_store.load(REWARD_POOL_KEY)?;
    reward_pool.total_tokens_staked =(reward_pool.total_tokens_staked- Uint128::from(withdraw_amount)).unwrap();
    rewards_store.store(REWARD_POOL_KEY, &reward_pool)?;

    //Asking the validator to undelegate the funds
    let mut validator_set = get_validator_set(&mut deps.storage)?;
    let validator = validator_set.get_validator_address().unwrap();
    let mut messages: Vec<CosmosMsg> = vec![];
    messages.push(undelegate(&validator, Uint128(withdraw_amount)));


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


/// validate_end_time returns an error if the lottery ends in the future
fn validate_end_time(end_time: u64, env: Env) -> StdResult<()> {
    if env.block.time <= end_time {
        Err(StdError::generic_err("Lottery end time is in the future"))
    } else {
        Ok(())
    }
}

/// validate_start_time returns an error if the lottery hasn't started
fn validate_start_time(start_time: u64, env: Env) -> StdResult<()> {
    if env.block.time < start_time {
        Err(StdError::generic_err("Lottery start time is in the future"))
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
    use cosmwasm_std::{from_binary, QueryResponse, WasmMsg, Decimal, FullDelegation, Validator, BlockInfo, MessageInfo, ContractInfo, QuerierResult, DistQuery, RewardsResponse};
    use std::convert::TryFrom;

    // Helper functions
    fn init_helper(amount:Option<u64>) -> (
        StdResult<InitResponse>,
        Extern<MockStorage, MockApi, MockQuerier>,
    ) {
        let mut deps = mock_dependencies(20, &[ Coin {
            amount: Uint128(amount.unwrap_or(0) as u128),
            denom: "uscrt".to_string(),
        }]);
        let env = mock_env("admin", &[], 1,0);
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


    pub fn mock_env<U: Into<HumanAddr>>(sender: U, sent: &[Coin], height: u64,time:u64) -> Env {
        Env {
            block: BlockInfo {
                height,
                time: time,
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

    fn deposit_helper_function() -> Extern<MockStorage, MockApi, MockQuerier> {
        let (_init_result, mut deps) = init_helper(None);



        try_deposit(&mut deps, mock_env("Batman",  &[Coin { denom: "uscrt".to_string(), amount: Uint128(1000000000), }], 10,0));
        try_deposit(&mut deps, mock_env("Superman",  &[Coin { denom: "uscrt".to_string(), amount: Uint128(2000000), }], 10,0));
        try_deposit(&mut deps, mock_env("Spider-man",  &[Coin { denom: "uscrt".to_string(), amount: Uint128(3000000), }], 10,0));
        try_deposit(&mut deps, mock_env("Wonder-Women",  &[Coin { denom: "uscrt".to_string(), amount: Uint128(4000000), }], 10,0));
        try_deposit(&mut deps, mock_env("Thor",  &[Coin { denom: "uscrt".to_string(), amount: Uint128(5000000), }], 10,0));
        try_deposit(&mut deps, mock_env("Captain-America",  &[Coin { denom: "uscrt".to_string(), amount: Uint128(2000000), }], 10,0));
        try_deposit(&mut deps, mock_env("Ironman",  &[Coin { denom: "uscrt".to_string(), amount: Uint128(3000000), }], 10,0));
        try_deposit(&mut deps, mock_env("Loki",  &[Coin { denom: "uscrt".to_string(), amount: Uint128(4000000), }], 10,0));

        return deps;
    }


    #[test]
    fn testing_overall_deposit() {
        let mut deps = deposit_helper_function();

        //checking lottery
        let mut a_lottery = lottery(&mut deps.storage).load().unwrap();
        assert_eq!(a_lottery.entries.len(),8);

        //checking reward store
        let rewards_store = TypedStoreMut::attach(&mut deps.storage);
        let mut reward_pool: RewardPool = rewards_store.load(REWARD_POOL_KEY).unwrap();
        assert_eq!(reward_pool.total_tokens_staked,Uint128(1023000000));
        assert_eq!(reward_pool.total_rewards_restaked,Uint128(7000));

        //Current pending rewards
        let mut current_round: RoundStruct = round(&mut deps.storage).load().unwrap();
        assert_eq!(current_round.pending_staking_rewards,Uint128(1000))



    }




    #[test]
    fn testing_deposit_with_wrong_denom() {
        //1)Checking for errors
        let (_init_result, mut deps) = init_helper(None);
        let env = mock_env("Batman",  &[Coin {
            denom: "bitcoin".to_string(),
            amount: Uint128(1000000),
        }], 10,0);

        let handlemsg= HandleMsg::Deposit { memo: Option::from("memo".to_string()), padding: None };
        let response = handle(&mut deps, env.clone(), handlemsg);

        assert_eq!(response.unwrap_err(),StdError::generic_err(
            "Coins send are not Scrt",
        ));
    }
    #[test]
    fn testing_deposit_with_less_than_accepted_amount() {
        //1)Checking for errors
        let (_init_result, mut deps) = init_helper(None);
        let env = mock_env("Batman",  &[Coin {
            denom: "uscrt".to_string(),
            amount: Uint128(999999),
        }], 10,0);

        let handlemsg= HandleMsg::Deposit { memo: Option::from("memo".to_string()), padding: None };
        let response = handle(&mut deps, env.clone(), handlemsg);

        assert_eq!(response.unwrap_err(),StdError::generic_err(
            "Must deposit a minimum of 1000000 uscrt, or 1 scrt",
        ));
    }

    #[test]
    fn testing_deposit_total_supply_overload() {
        //1)Checking for errors
        let (_init_result, mut deps) = init_helper(None);
        let env = mock_env("Batman",  &[Coin {
            denom: "uscrt".to_string(),

            amount: Uint128(100000000000000000)
        }], 10,0);

        let handlemsg= HandleMsg::Deposit { memo: Option::from("memo".to_string()), padding: None };
        let response = handle(&mut deps, env.clone(), handlemsg);
    }

    #[test]
    fn testing_deposit_user_data_update() {
        //1)Checking for errors
        let (_init_result, mut deps) = init_helper(None);
        let env = mock_env("Batman",  &[Coin {
            denom: "uscrt".to_string(),

            //add one more zero and it will start giving error
            amount: Uint128::try_from("100000000000000000000000000000000000000").unwrap()
        }], 10,0);

        let handlemsg= HandleMsg::Deposit { memo: Option::from("memo".to_string()), padding: None };
        let response = handle(&mut deps, env.clone(), handlemsg);


        let user = TypedStore::attach(&deps.storage)
            .load("Batman".as_bytes())
            .unwrap_or(UserInfo {
                amount_delegated: Default::default(),
                start_time: 0,
                requested_withdraw: RequestedInfo { amount: Uint128(0), time: 0 }
            });

        assert_eq!(user.amount_delegated,Uint128::try_from("100000000000000000000000000000000000000").unwrap());
        assert_eq!(user.start_time,0)
    }

    #[test]
    fn testing_deposit_lottery_update() {
        //1)Checking for errors
        let (_init_result, mut deps) = init_helper(None);
        let env = mock_env("Batman",  &[Coin {
            denom: "uscrt".to_string(),

            //add one more zero and it will start giving error
            amount: Uint128::try_from("10000000").unwrap()
        }], 10,0);

        let handlemsg= HandleMsg::Deposit { memo: Option::from("memo".to_string()), padding: None };
        let response = handle(&mut deps, env.clone(), handlemsg);

        let mut a_lottery = lottery(&mut deps.storage).load().unwrap();
        assert_eq!(a_lottery.entries.len(),1)

    }

    #[test]
    fn testing_deposit_rewards_store() {
        //1)Checking for errors
        let (_init_result, mut deps) = init_helper(None);


        try_deposit(&mut deps, mock_env("Batman",  &[Coin { denom: "uscrt".to_string(), amount: Uint128(10000000), }], 10,0));

        let rewards_store = TypedStoreMut::attach(&mut deps.storage);
        let mut reward_pool: RewardPool = rewards_store.load(REWARD_POOL_KEY).unwrap();
        assert_eq!(reward_pool.total_tokens_staked,Uint128(10000000));
        assert_eq!(reward_pool.total_rewards_restaked,Uint128(0))


    }

    #[test]
    fn testing_deposit_current_round() {
        //1)Checking for errors
        let (_init_result, mut deps) = init_helper(None);
        try_deposit(&mut deps, mock_env("Batman",  &[Coin { denom: "uscrt".to_string(), amount: Uint128(10000000), }], 10,0));
        let mut current_round: RoundStruct = round(&mut deps.storage).load().unwrap();
        assert_eq!(current_round.pending_staking_rewards,Uint128(1000))
    }



    #[test]
    fn testing_withdraw() {
        //1)Checking for errors
        let (_init_result, mut deps) = init_helper(None);
        let env = mock_env("Batman",  &[Coin {
            denom: "uscrt".to_string(),
            amount: Uint128(1000000),
        }], 10,0);

        let handlemsg= HandleMsg::Deposit { memo: Option::from("memo".to_string()), padding: None };
        let response = handle(&mut deps, env.clone(), handlemsg);
        let mut user = TypedStore::attach(&deps.storage)
            .load("Batman".as_bytes())
            .unwrap_or(UserInfo { amount_delegated: Uint128(0), start_time: env.block.time, requested_withdraw:RequestedInfo{ amount: Uint128(0),time:env.block.time} }); // NotFound is the only possible error

        assert_eq!(user.amount_delegated,Uint128(1000000));

        let env = mock_env("Batman",  &[Coin {
            denom: "uscrt".to_string(),
            amount: Uint128(0),
        }], 10,0);

        let handlemsg= HandleMsg::Withdraw {
            amount: Some(Uint128(1000000)),
            memo: None,
            padding: None
        };
        let response = handle(&mut deps, env.clone(), handlemsg);
        let mut user = TypedStore::attach(&deps.storage)
            .load("Batman".as_bytes())
            .unwrap_or(UserInfo { amount_delegated: Uint128(0), start_time: env.block.time, requested_withdraw:RequestedInfo{ amount: Uint128(0),time:env.block.time} }); // NotFound is the only possible error

        assert_eq!(user.amount_delegated,Uint128(1000000));

        let reward_store = TypedStore::attach(&deps.storage).load(REWARD_POOL_KEY);
        let reward_pool:RewardPool = reward_store.unwrap();

        assert_eq!(reward_pool.total_tokens_staked, Uint128(1000000));

    }


    #[test]
    fn testing_claim_rewards() {
        //1)Checking for errors
        let (_init_result, mut deps) = init_helper(None);
        let env = mock_env("Batman",  &[Coin {
            denom: "uscrt".to_string(),
            amount: Uint128(1000000),
        }], 10,0);

        let handlemsg= HandleMsg::Deposit { memo: Option::from("memo".to_string()), padding: None };
        let response = handle(&mut deps, env.clone(), handlemsg);
        let mut user = TypedStore::attach(&deps.storage)
            .load("Batman".as_bytes())
            .unwrap_or(UserInfo { amount_delegated: Uint128(0), start_time: env.block.time, requested_withdraw:RequestedInfo{ amount: Uint128(0),time:env.block.time} }); // NotFound is the only possible error

        assert_eq!(user.amount_delegated,Uint128(1000000));


        let reward_store = TypedStore::attach(&deps.storage).load(REWARD_POOL_KEY);
        let reward_pool:RewardPool = reward_store.unwrap();
        assert_eq!(reward_pool.total_tokens_staked, Uint128(1000000));

        let env = mock_env("xyz",  &[Coin {
            denom: "uscrt".to_string(),
            amount: Uint128(0),
        }], 22,602);

        let handlemsg= HandleMsg::ClaimRewards {
        };
        let response = handle(&mut deps, env.clone(), handlemsg);
        // println!("{:?}",response.unwrap());
        let mut user = TypedStore::attach(&deps.storage)
            .load("Batman".as_bytes())
            .unwrap_or(UserInfo { amount_delegated: Uint128(0), start_time: env.block.time, requested_withdraw:RequestedInfo{ amount: Uint128(0),time:env.block.time} }); // NotFound is the only possible error


        let mut a_lottery = lottery(&mut deps.storage).load().unwrap();
        assert_eq!(a_lottery.start_time, 603);


        // let last_lottery = last_lottery_results_read(&deps.storage).load().unwrap();
        // assert_eq!(last_lottery.winner,HumanAddr("Batman".to_string()));


    }
    #[test]
    fn testing_trigger_withdraw() {
        //1)Checking for errors
        let (_init_result, mut deps) = init_helper(Some(1000000 as u64));
        let env = mock_env("Batman",  &[Coin {
            denom: "uscrt".to_string(),
            amount: Uint128(1000000),
        }], 10,0);
        let handlemsg= HandleMsg::Deposit { memo: Option::from("memo".to_string()), padding: None };
        let response = handle(&mut deps, env.clone(), handlemsg);
        let mut user = TypedStore::attach(&deps.storage)
            .load("Batman".as_bytes())
            .unwrap_or(UserInfo { amount_delegated: Uint128(0), start_time: env.block.time, requested_withdraw:RequestedInfo{ amount: Uint128(0),time:env.block.time} }); // NotFound is the only possible error

        assert_eq!(user.amount_delegated,Uint128(1000000));

        let env = mock_env("Batman",  &[Coin {
            denom: "uscrt".to_string(),
            amount: Uint128(0),
        }], 10,0);

        let handlemsg= HandleMsg::TriggerWithdraw {
            amount: Some(Uint128(1000000)),
            memo: None,
            padding: None
        };
        let response = handle(&mut deps, env.clone(), handlemsg);
        let mut user = TypedStore::attach(&deps.storage)
            .load("Batman".as_bytes())
            .unwrap_or(UserInfo { amount_delegated: Uint128(0), start_time: env.block.time, requested_withdraw:RequestedInfo{ amount: Uint128(0),time:env.block.time} }); // NotFound is the only possible error

        assert_eq!(user.amount_delegated,Uint128(0));
        assert_eq!(user.requested_withdraw.amount,Uint128(1000000));


        let env = mock_env("Batman",  &[Coin {
            denom: "uscrt".to_string(),
            amount: Uint128(1000000),
        }], 10,1814400);

        let handlemsg= HandleMsg::Withdraw {
            amount: None,
            memo: None,
            padding: None
        };
        let response = handle(&mut deps, env.clone(), handlemsg);
        let mut user = TypedStore::attach(&deps.storage)
            .load("Batman".as_bytes())
            .unwrap_or(UserInfo { amount_delegated: Uint128(0), start_time: env.block.time, requested_withdraw:RequestedInfo{ amount: Uint128(0),time:env.block.time} }); // NotFound is the only possible error
        assert_eq!(user.requested_withdraw.amount,Uint128(0));


    }


}
