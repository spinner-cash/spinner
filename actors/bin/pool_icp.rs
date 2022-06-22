// TODO
// - [ ] Fee structure
// - [ ] Event queue purging and flushing
// - [ ] Refresh transaction fee
// - [ ] Proof of locking time
// - [ ] Token incentive (reward deposits)
// - [ ] Refund (bundle deposit + withdraw)

use async_recursion::async_recursion;
use ic_cdk::export::{
    candid::{candid_method, CandidType},
    serde::{Deserialize, Serialize},
    Principal,
};
use ic_cdk_macros::*;
use ic_ledger_types::{
    AccountBalanceArgs, AccountIdentifier, BlockIndex, Memo, Subaccount, Tokens, TransferArgs,
    DEFAULT_SUBACCOUNT, MAINNET_LEDGER_CANISTER_ID,
};
use spnr::{
    ledger,
    ledger::{Bytes, BYTES},
};
use spnr_lib::{
    event_queue::{EventId, EventQueue},
    storage::{StableStorage, StorageStack},
};
use std::cell::RefCell;
use std::collections::BTreeSet;
use std::hash::Hash;
use std::ops::Deref;

const EVENT_EXPIRATION: u64 = 3600 * 1000000000; // 1 hour

fn trap<T>(err: String) -> T {
    ic_cdk::api::trap(&err)
}

fn trap_io<T>(err: std::io::Error) -> T {
    trap(format!("{}", err))
}

fn to_hex(bytes: &[u8]) -> String {
    let mut s = String::new();
    for b in bytes {
        s.push_str(&format!("{:02x}", b));
    }
    s
}

#[derive(CandidType, Serialize, Deserialize, Clone, Debug, Hash, PartialEq)]
pub struct Config {
    logger_canister_id: Principal,
    ledgers: Vec<Principal>,
    ledger_canister_id: Principal,
    token_transaction_fee: Tokens,
    ledger_transaction_fee: Fee,
    max_event_queue_size: usize,
}

#[derive(CandidType, Serialize, Deserialize, Copy, Clone, Debug, Hash, PartialEq)]
pub enum Fee {
    // How much per transaction
    Fixed(Tokens),
    // How much per 1 ICP
    Percentage(Tokens),
}

#[derive(
    CandidType, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Clone, Copy, Debug, Hash,
)]
pub struct Nonce(Bytes);

impl Default for Nonce {
    fn default() -> Self {
        Nonce([0; BYTES])
    }
}

impl std::fmt::Display for Nonce {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        use ethereum_types::U256;
        std::fmt::Display::fmt(&U256::from_big_endian(&self.0), f)
    }
}

impl std::fmt::LowerHex for Nonce {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        use ethereum_types::U256;
        std::fmt::LowerHex::fmt(&U256::from_big_endian(&self.0), f)
    }
}

/// The workflow is pictured as follows:
///
///       /---------------/---------------/----------> Error*
///      /               /               /
/// CheckBalance -> Depositing* -> Committed*! -> Deposited*
///
/// Withdrawing -> Releasing*! -> Released*
///
/// Transacting -> Transacted
///
/// Where:
///   - An aterik (*) means the event is logged. Every event must only be logged once.
///   - An bang (!) means the event should be re-tried if it linger in the queue.
///
#[derive(CandidType, Serialize, Deserialize, Clone, Debug, Hash)]
pub enum Event {
    // Deposit
    CheckBalance(TransactionArgs, Principal, Tokens),
    Depositing(TransactionArgs, Subaccount, Tokens, Tokens),
    Committed(TransactionResponse, Subaccount, Tokens),
    Deposited(TransactionResponse, Subaccount, Tokens, BlockIndex),
    // Withdraw
    Withdrawing(TransactionArgs, Remittance),
    Releasing(TransactionResponse, Remittance),
    Released(TransactionResponse),
    // Transaction
    Transacting(TransactionArgs),
    Transacted(TransactionArgs, TransactionResponse),
    // Target of retry (poll)
    PendingRetry(Box<Event>),
    Error(String),
}

impl std::fmt::Display for Event {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        use Event::*;
        match self {
            CheckBalance(_, caller, _) => write!(f, "CheckBalance({})", caller),
            Depositing(_, subaccount, tokens, _) => {
                write!(f, "Depositing({}, {})", to_hex(&subaccount.0), tokens)
            }
            Committed(_, subaccount, tokens) => {
                write!(f, "Committed({}, {})", to_hex(&subaccount.0), tokens)
            }
            Deposited(_, _, tokens, block) => write!(f, "Deposited({}, {})", tokens, block),
            Withdrawing(_, remittance) => write!(f, "Withdrawing({})", remittance.amount),
            Releasing(_, remit) => {
                write!(
                    f,
                    "Releasing({}, {}, {})",
                    remit.recipient, remit.amount, remit.fee
                )
            }
            Released(res) => {
                write!(
                    f,
                    "Released({}, {})",
                    res.remitted
                        .iter()
                        .map(|(x, _)| x.amount)
                        .fold(Tokens::from_e8s(0), |x, y| x + y),
                    res.remitted
                        .iter()
                        .map(|(x, _)| x.fee)
                        .fold(Tokens::from_e8s(0), |x, y| x + y),
                )
            }
            Transacting(_) => write!(f, "Transacting"),
            Transacted(args, res) => write!(
                f,
                "Transacted({},{:?})",
                args.ledger.to_string(),
                res.committed,
            ),
            PendingRetry(_) => write!(f, "PendingRetry"),
            Error(msg) => write!(f, "Error({})", msg),
        }
    }
}

impl Event {
    fn name(&self) -> &str {
        use Event::*;
        match self {
            CheckBalance(_, _, _) => "CheckBalance",
            Depositing(_, _, _, _) => "Depositing",
            Committed(_, _, _) => "Committed",
            Deposited(_, _, _, _) => "Deposited",
            Withdrawing(_, _) => "Withdrawing",
            Releasing(_, _) => "Releasing",
            Released(_) => "Released",
            Transacting(_) => "Transacting",
            Transacted(_, _) => "Transacted",
            PendingRetry(_) => "PendingRetry",
            Error(_) => "Error",
        }
    }

    fn purgeable(&self) -> bool {
        use Event::*;
        matches!(self, Deposited(_, _, _, _) | Released(_) | Error(_))
    }
}

#[derive(CandidType, Serialize, Deserialize, Clone, Debug, Hash)]
pub struct State {
    // Event queue, pruned by expiration.
    queue: EventQueue<Nonce, Event>,
    // Track available balance that is ready to send out.
    available_balance: Tokens,
    // Prevent re-entry using the same subaccount.
    depositing: BTreeSet<Subaccount>,
}

impl Default for Config {
    fn default() -> Self {
        Config {
            logger_canister_id: Principal::anonymous(),
            ledgers: Vec::new(),
            ledger_canister_id: MAINNET_LEDGER_CANISTER_ID,
            token_transaction_fee: Tokens::from_e8s(10_000),
            ledger_transaction_fee: Fee::Fixed(Tokens::from_e8s(10_000)),
            max_event_queue_size: 0,
        }
    }
}

impl Default for State {
    fn default() -> Self {
        State {
            queue: EventQueue::default(),
            available_balance: Tokens::from_e8s(0),
            depositing: BTreeSet::new(),
        }
    }
}

thread_local! {
    static CONFIG: RefCell<Config> = RefCell::new(Config::default());
    static STATE: RefCell<State> = RefCell::new(State::default());
}

#[init]
#[candid_method(init)]
fn init(conf: Config) {
    STATE.with(|s| {
        let mut state = s.borrow_mut();
        state.queue = EventQueue::new(conf.max_event_queue_size);
    });
    CONFIG.with(|c| c.replace(conf));
}

#[pre_upgrade]
fn pre_upgrade() {
    // TODO: Shall we assert the queue has no pending?
    CONFIG.with(|c| {
        let config = c.borrow();
        STATE.with(|s| {
            let state = s.borrow();
            let mut storage = StableStorage::new();
            storage
                .push((config.deref(), state.deref()))
                .unwrap_or_else(trap_io);
            storage.finalize().unwrap_or_else(trap_io);
        })
    })
}

#[post_upgrade]
fn post_upgrade() {
    let (config, state) = StableStorage::new()
        .pop::<(Config, State)>()
        .unwrap_or_else(trap_io);
    CONFIG.with(|c| c.replace(config));
    STATE.with(|s| s.replace(state));
}

#[derive(CandidType, Clone, Debug, Hash)]
struct Stats {
    config: Config,
    queue_size: usize,
    ongoing_deposits: usize,
    available_balance: Tokens,
}

#[query]
#[candid_method(query)]
async fn stats() -> Stats {
    CONFIG.with(|c| {
        let config = c.borrow();
        STATE.with(|s| {
            let state = s.borrow();
            Stats {
                config: config.clone(),
                queue_size: state.queue.len(),
                ongoing_deposits: state.depositing.len(),
                available_balance: state.available_balance,
            }
        })
    })
}

#[derive(CandidType, Serialize, Deserialize, Clone, Debug, Hash)]
pub struct TransactionResponse {
    pub committed: [ledger::Index; 2],
    pub remitted: Option<(Remittance, BlockIndex)>,
}

fn principal_to_subaccount(p: Principal) -> Subaccount {
    let mut bytes = [0; 32];
    let s: &[u8] = p.as_slice();
    bytes[0] = s.len() as u8;
    let end = s.len().min(31);
    bytes[1..(end + 1)].copy_from_slice(&s[0..end]);
    Subaccount(bytes)
}

fn log_event(id: EventId<Nonce>, event: &Event) {
    let logger_canister_id = CONFIG.with(|c| c.borrow().logger_canister_id);
    let message = format!(
        "{}:{}:{:064x}:{}",
        ic_cdk::api::time(),
        &id.expiry,
        &id.nonce,
        event
    );
    ic_cdk::spawn(async move {
        // TODO: handle log failure by remembering it
        ic_cdk::call::<(Vec<String>,), ()>(logger_canister_id, "append", (vec![message],))
            .await
            .ok();
    });
}

// Log error and update event
fn report_error<T>(id: EventId<Nonce>, msg: String, logging: bool) -> Result<T, String> {
    let event = Event::Error(msg.clone());
    update_event(id, event, logging);
    Err(msg)
}

fn update_event(id: EventId<Nonce>, event: Event, logging: bool) {
    if logging {
        log_event(id, &event);
    }
    STATE.with(|s| s.borrow_mut().queue.modify(id, |v| *v = event))
}

fn insert_event(id: EventId<Nonce>, event: Event) -> Result<(), String> {
    STATE
        .with(|s| s.borrow_mut().queue.insert(id, event))
        .map_err(|err| format!("{}", err))
}

fn purge_expired_events(time: u64) {
    STATE.with(|s| s.borrow_mut().queue.purge(time, |evt| evt.purgeable()))
}

#[async_recursion]
async fn process(id: EventId<Nonce>, event: Event, logging: bool) -> Result<(), String> {
    // Make sure event status is reflected in the event queue.
    update_event(id, event.clone(), logging);
    match event {
        Event::CheckBalance(args, caller, amount) => {
            let (ledger_canister_id, account, subaccount) = CONFIG.with(|c| {
                let config = c.borrow();
                let ledger_canister_id = config.ledger_canister_id;
                let subaccount = principal_to_subaccount(caller);
                let account = AccountIdentifier::new(&ic_cdk::api::id(), &subaccount);
                (ledger_canister_id, account, subaccount)
            });
            // Prevent re-entry attack using the same subaccount to deposit
            if !STATE.with(|s| s.borrow_mut().depositing.insert(subaccount)) {
                report_error(
                    id,
                    format!("AnotherDepositInProgress: {}", to_hex(&subaccount.0)),
                    false,
                )?
            }
            let balance = ic_ledger_types::account_balance(
                ledger_canister_id,
                AccountBalanceArgs { account },
            )
            .await
            .or_else(|(code, msg)| {
                STATE.with(|s| s.borrow_mut().depositing.remove(&subaccount));
                report_error(id, format!("CheckBalanceError: {:?} {}", code, msg), false)
            })?;
            process(
                id,
                Event::Depositing(args, subaccount, amount, balance),
                false,
            )
            .await
        }
        Event::Depositing(args, subaccount, amount, balance) => {
            let fee = CONFIG.with(|conf| conf.borrow().token_transaction_fee);
            if amount + fee > balance {
                STATE.with(|s| s.borrow_mut().depositing.remove(&subaccount));
                report_error(
                    id,
                    format!(
                        "InsufficientBalance: {} is less than {} depositing + {} fee.",
                        balance, amount, fee
                    ),
                    true,
                )?
            }
            // TODO: call_with_payment
            let (res,) = ic_cdk::call::<(ledger::Transaction,), (ledger::TransactionResponse,)>(
                args.ledger,
                "transact",
                (args.transaction,),
            )
            .await
            .or_else(|(code, msg)| {
                STATE.with(|s| s.borrow_mut().depositing.remove(&subaccount));
                report_error(id, format!("DepositError: {:?} {}", code, msg), true)
            })?;
            let res = TransactionResponse {
                committed: res.committed,
                remitted: None,
            };

            ic_cdk::spawn(async move {
                process(id, Event::Committed(res, subaccount, amount), true)
                    .await
                    .ok();
            });
            Ok(())
        }
        Event::Committed(response, subaccount, balance) => {
            let (ledger_canister_id, transfer_args) = CONFIG.with(|conf| {
                let conf = conf.borrow();
                (
                    conf.ledger_canister_id,
                    TransferArgs {
                        memo: Memo(0),
                        amount: balance,
                        fee: conf.token_transaction_fee,
                        from_subaccount: Some(subaccount),
                        to: AccountIdentifier::new(&ic_cdk::api::id(), &DEFAULT_SUBACCOUNT),
                        created_at_time: None,
                    },
                )
            });
            let amount = transfer_args.amount;
            let msg = match ic_ledger_types::transfer(ledger_canister_id, transfer_args).await {
                Ok(Ok(block)) => {
                    return process(
                        id,
                        Event::Deposited(response, subaccount, amount, block),
                        true,
                    )
                    .await;
                }
                Ok(Err(err)) => format!("LedgerError: {}", err),
                Err((code, msg)) => format!("LedgerError: {:?} {}", code, msg),
            };
            // NOTE: We are not removing this subaccount from depositing, because
            // it is an ledger error requiring manual intervention.
            let event = Event::Committed(response, subaccount, balance);
            update_event(id, Event::PendingRetry(Box::new(event)), false);
            log_event(id, &Event::Error(msg.clone()));
            Err(msg)
        }
        Event::Deposited(_response, subaccount, amount, _block) => {
            STATE.with(|s| {
                let mut state = s.borrow_mut();
                let available = &mut state.available_balance;
                *available += amount;
                state.depositing.remove(&subaccount);
            });
            Ok(())
        }
        Event::Withdrawing(args, remittance) => {
            // TODO: call_with_payment
            let (res,) = ic_cdk::call::<(ledger::Transaction,), (ledger::TransactionResponse,)>(
                args.ledger,
                "transact",
                (args.transaction,),
            )
            .await
            .map_err(|(code, msg)| format!("WithdrawError: {:?} {}", code, msg))
            .or_else(|msg| report_error(id, msg, true))?;
            let res = TransactionResponse {
                committed: res.committed,
                remitted: None,
            };
            ic_cdk::spawn(async move {
                process(id, Event::Releasing(res, remittance), true)
                    .await
                    .ok();
            });
            Ok(())
        }
        Event::Releasing(mut res, remittance) => {
            let (ledger_canister_id, transfer_args) = CONFIG.with(|conf| {
                let conf = conf.borrow();
                (
                    conf.ledger_canister_id,
                    TransferArgs {
                        memo: Memo(0),
                        amount: remittance.amount - remittance.fee,
                        fee: conf.token_transaction_fee,
                        from_subaccount: None,
                        to: remittance.recipient,
                        created_at_time: None,
                    },
                )
            });
            let deduction = transfer_args.fee + transfer_args.amount;
            STATE.with(|s| {
                let available = &mut s.borrow_mut().available_balance;
                assert!(deduction <= *available); // trap on purpose if fail
                *available -= deduction;
            });
            let credit_back = || {
                STATE.with(|s| {
                    s.borrow_mut().available_balance += deduction;
                })
            };
            let msg = match ic_ledger_types::transfer(ledger_canister_id, transfer_args).await {
                Ok(Ok(block)) => {
                    res.remitted = Some((remittance, block));
                    return Ok(());
                }
                Ok(Err(err)) => format!("OutgoingTransferError({})", err),
                Err(err) => format!("OutgoingTransferError({:?})", err),
            };
            credit_back();
            // Suspend it for retry
            let evt = Event::PendingRetry(Box::new(Event::Releasing(res, remittance)));
            update_event(id, evt, false);
            log_event(id, &Event::Error(msg.clone()));
            Err(msg)
        }
        Event::Released(_) => Ok(()),
        Event::Transacting(args) => {
            let fee = CONFIG.with(|conf| conf.borrow().token_transaction_fee);
            STATE.with(|s| {
                let available = &mut s.borrow_mut().available_balance;
                assert!(*available >= fee);
                *available -= fee;
            });
            // TODO: call_with_payment
            let (res,) = ic_cdk::call::<(ledger::Transaction,), (ledger::TransactionResponse,)>(
                args.ledger,
                "transact",
                (args.transaction.clone(),),
            )
            .await
            .map_err(|(code, msg)| format!("TransactError: {:?} {}", code, msg))
            .or_else(|msg| {
                STATE.with(|s| {
                    let available = &mut s.borrow_mut().available_balance;
                    *available += fee;
                });
                report_error(id, msg, true)
            })?;
            let res = TransactionResponse {
                committed: res.committed,
                remitted: None,
            };
            process(id, Event::Transacted(args, res), true).await
        }
        Event::Transacted(_, _) => Ok(()),
        event => report_error(id, format!("UnsupportedEvent: {:?}", event), false),
    }
}

#[derive(
    CandidType, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Clone, Debug, Hash,
)]
pub struct Remittance {
    recipient: AccountIdentifier,
    amount: Tokens,
    fee: Tokens,
}

fn to_remittance(recipient: AccountIdentifier, amount: Tokens, ledger_fee: Fee) -> Remittance {
    Remittance {
        recipient,
        amount,
        fee: match ledger_fee {
            Fee::Percentage(percent) => {
                let amount = amount.e8s() as u128;
                let denominator = percent.e8s() as u128;
                let numerator = 100000000;
                Tokens::from_e8s((amount * denominator / numerator) as u64)
            }
            Fee::Fixed(fee) => fee,
        },
    }
}

#[derive(Deserialize)]
struct ExtData {
    recipient: String,
}

#[derive(Debug)]
enum RecipientError {
    ParsingError,
    FormatError,
    InvalidAccountId(String),
}

impl std::fmt::Display for RecipientError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        use RecipientError::*;
        match self {
            ParsingError => write!(f, "ParsingError: recipient not found"),
            FormatError => write!(f, "FormatError: recipient must be hexidecimal"),
            InvalidAccountId(err) => write!(f, "INvalidAccountId: {}", err),
        }
    }
}

fn parse_recipient(payload: &str) -> Result<AccountIdentifier, RecipientError> {
    use ethereum_types::U256;
    use RecipientError::*;

    let ext: ExtData = serde_json::from_str(payload).map_err(|_| ParsingError)?;
    let mut bytes = [0; 32];
    let n = U256::from_str_radix(&ext.recipient, 16).map_err(|_| FormatError)?;
    n.to_big_endian(&mut bytes);
    AccountIdentifier::try_from(bytes).map_err(InvalidAccountId)
}

#[derive(Eq, PartialEq, Ord, PartialOrd, Clone, Copy, Debug)]
enum Operation {
    Deposit(u64),
    Withdraw(u64),
}

fn from_amount(bytes: ledger::Bytes) -> Result<Operation, String> {
    use ethereum_types::U256;
    let amount256 = U256::from_big_endian(&bytes);
    let amount = amount256.low_u128() as i128;
    if amount > 0 {
        let deposit_amount = amount as u64;
        if U256::from(deposit_amount) == amount256 {
            Ok(Operation::Deposit(deposit_amount))
        } else {
            Err("Invalid amount".to_string())
        }
    } else {
        let withdraw_amount = (-amount) as u64;
        if U256::from(withdraw_amount).overflowing_add(amount256).0 == U256::zero() {
            Ok(Operation::Withdraw(withdraw_amount))
        } else {
            Err("Invalid amount".to_string())
        }
    }
}

#[derive(CandidType, Serialize, Deserialize, Clone, Debug, Hash)]
pub struct TransactionArgs {
    nonce: Nonce,
    ledger: Principal,
    transaction: ledger::Transaction,
}

#[update]
#[candid_method(update)]
async fn transact(args: TransactionArgs) -> Result<TransactionResponse, String> {
    let respond = |nonce| {
        STATE.with(|s| {
            s.borrow().queue.find(&nonce).map(|(_id, evt)| match evt {
                Event::PendingRetry(evt) => match evt.as_ref() {
                    Event::Committed(res, _, _) => Ok(res.clone()),
                    Event::Releasing(res, _) => Ok(res.clone()),
                    _ => Err("Impossible".to_string()),
                },
                Event::Committed(res, _, _) => Ok(res.clone()),
                Event::Deposited(res, _, _, _) => Ok(res.clone()),
                Event::Releasing(res, _) => Ok(res.clone()),
                Event::Released(res) => Ok(res.clone()),
                Event::Transacted(_, res) => Ok(res.clone()),
                Event::Error(msg) => Err(msg.to_string()),
                evt => Err(evt.name().to_string()),
            })
        })
    };

    // Check if we have seen this request before.
    if let Some(res) = respond(args.nonce) {
        return res;
    }

    // Check if ledger exists
    CONFIG
        .with(|c| {
            c.borrow()
                .ledgers
                .iter()
                .find(|id| **id == args.ledger)
                .cloned()
        })
        .expect("MixerNotFound");

    let nonce = args.nonce;
    let now = ic_cdk::api::time();
    purge_expired_events(now);
    let id = EventId::new(now + EVENT_EXPIRATION, nonce);

    let transaction = &args.transaction;
    // transactions.amount excludes token transaction fees
    // but includes ledger transaction fee.
    let event = match from_amount(transaction.amount)? {
        Operation::Deposit(amount) => {
            Event::CheckBalance(args, ic_cdk::api::caller(), Tokens::from_e8s(amount))
        }
        Operation::Withdraw(amount) => {
            let amount = Tokens::from_e8s(amount);
            let ledger_fee = CONFIG.with(|c| c.borrow().ledger_transaction_fee);
            let fee = CONFIG.with(|c| c.borrow().token_transaction_fee);
            let available = STATE.with(|s| s.borrow().available_balance);
            if amount + fee > available {
                return Err(format!(
                    "InsufficientBalance: requested to withdraw {} but only {} is available",
                    amount + fee,
                    available
                ));
            }

            match parse_recipient(&transaction.payload) {
                Ok(recipient) => {
                    let remittance = to_remittance(recipient, amount, ledger_fee);
                    Event::Withdrawing(args, remittance)
                }
                Err(RecipientError::ParsingError) => {
                    if amount < fee {
                        return Err(format!("InsufficientFee: must be at least {}", fee));
                    }
                    Event::Transacting(args)
                }
                Err(err) => return Err(format!("{:?}", err)),
            }
        }
    };
    insert_event(id, event.clone())?;
    process(id, event, false).await?;

    if let Some(res) = respond(nonce) {
        res
    } else {
        Err("RequestPurged".to_string())
    }
}

#[derive(CandidType, Serialize, Deserialize, Clone, Debug, Hash)]
struct PollArgs {
    nonce: Nonce,
}

#[update]
#[candid_method(update)]
async fn poll(args: PollArgs) -> Result<(), String> {
    // Find the corresponding
    let (id, event) = STATE.with(|s| {
        s.borrow()
            .queue
            .find(&args.nonce)
            .map(|(i, e)| (*i, e.clone()))
            .ok_or_else(|| "NotFound".to_string())
    })?;
    match event {
        Event::PendingRetry(evt) => process(id, *evt, false).await,
        _ => Ok(()),
    }
}

#[cfg(not(any(target_arch = "wasm32", test)))]
fn main() {
    candid::export_service!();
    std::print!("{}", __export_service());
}

#[cfg(any(target_arch = "wasm32", test))]
fn main() {}

#[test]
fn test_from_amount() {
    let mut bytes = [0; 32];
    assert_eq!(from_amount(bytes), Ok(Operation::Withdraw(0)));
    bytes[31] = 77;
    assert_eq!(from_amount(bytes), Ok(Operation::Deposit(77)));
    bytes = [255; 32];
    assert_eq!(from_amount(bytes), Ok(Operation::Withdraw(1)));
    bytes[0..16].copy_from_slice(&[0; 16]);
    assert!(matches!(from_amount(bytes), Err(_)));
}
