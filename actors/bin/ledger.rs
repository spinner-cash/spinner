use ic_cdk::export::candid::{candid_method, CandidType};
use ic_cdk_macros::*;
use spnr::{
    ledger,
    ledger::{Config, State, TreeInfo},
};
use spnr_lib::storage::{StableStorage, StorageStack};
use std::cell::RefCell;
use std::ops::Deref;

thread_local! {
    static CONFIG: RefCell<Config> = RefCell::new(Config::default());
    static STATE: RefCell<State> = RefCell::new(State::default());
}

fn trap<T>(err: String) -> T {
    ic_cdk::api::trap(&err)
}

fn trap_io<T>(err: std::io::Error) -> T {
    trap(format!("{:?}", err))
}

#[init]
#[candid_method(init)]
fn init(config: Config) {
    STATE.with(|s| s.borrow_mut().init(&config));
    CONFIG.with(|c| c.replace(config));
}

#[pre_upgrade]
fn pre_upgrade() {
    CONFIG.with(|c| {
        let config = c.borrow();
        STATE.with(|s| {
            let state = s.borrow_mut();
            let info = state.storage_info(&config);
            let mut storage = StableStorage::new().new_with(info.flat_store_bytes);
            //ic_cdk::println!("pre {:?}", (&info, &state.store_sizes, config.deref()));
            storage
                .push((&state.store_size, config.deref()))
                .unwrap_or_else(trap_io);
            storage.finalize().unwrap_or_else(trap_io);
        })
    })
}

#[post_upgrade]
fn post_upgrade() {
    /*
    let (info, store_sizes, old_config) = StableStorage::new()
        .pop::<(StorageInfo, Vec<u64>, ledger::OldConfig)>()
        .unwrap_or_else(trap_io);
    let config = Config {
        max_level: old_config.max_level,
        token_type: old_config.token_type,
        denominations: old_config.denominations,
        max_recent_roots: old_config.max_recent_roots,
        max_lookup_range: 1024,
    };
    */
    let (store_size, config) = StableStorage::new()
        .pop::<(u64, ledger::Config)>()
        .unwrap_or_else(trap_io);
    //ic_cdk::println!("post {:?}", (&info, &store_sizes, &config));
    let store = ledger::StableStore {
        payload_size: config.payload_size,
    };
    let state = State::restore(&config, store_size, &store).unwrap_or_else(trap);
    CONFIG.with(|c| c.replace(config));
    STATE.with(|s| s.replace(state));
}

#[derive(CandidType, Clone, Debug, Hash)]
struct Stats {
    config: Config,
    tree: TreeInfo,
    nullified: usize,
    committed: usize,
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
                tree: ledger::tree_info(&state),
                nullified: state.nullified.len(),
                committed: state.committed.len(),
            }
        })
    })
}

#[query]
#[candid_method(query)]
async fn merkle_path(args: ledger::MerklePathArgs) -> ledger::MerklePathResponse {
    CONFIG
        .with(|c| {
            let config = c.borrow();
            STATE.with(|s| {
                let state = s.borrow();
                let payload_size = config.payload_size;
                let store = ledger::StableStore { payload_size };
                ledger::merkle_path(&config, &state, &store, args)
            })
        })
        .unwrap_or_else(trap)
}

#[query]
#[candid_method(query)]
async fn scan(range: ledger::Range) -> ledger::ScanResponse {
    CONFIG
        .with(|c| {
            let config = c.borrow();
            STATE.with(|s| {
                let state = s.borrow();
                let payload_size = config.payload_size;
                let store = ledger::StableStore { payload_size };
                ledger::scan(&config, &state, &store, range)
            })
        })
        .unwrap_or_else(trap)
}

#[query]
#[candid_method(query)]
async fn committed(args: Vec<ledger::Bytes>) -> Vec<i64> {
    STATE.with(|s| {
        let state = s.borrow();
        ledger::committed(&state, args)
    })
}

#[query]
#[candid_method(query)]
async fn nullified(args: Vec<ledger::Bytes>) -> Vec<bool> {
    STATE.with(|s| {
        let state = s.borrow();
        ledger::nullified(&state, args)
    })
}

// Only allow caller when allowed_callers list isn't empty, and the
// caller isn't in the list.
fn check_caller(config: &Config) -> Result<(), String> {
    let caller = ic_cdk::api::caller();
    if !config.allowed_callers.is_empty() && !config.allowed_callers.iter().any(|c| c == &caller) {
        Err("CallerNotAllowed".to_string())
    } else {
        Ok(())
    }
}

#[update]
#[candid_method(update)]
async fn transact(args: ledger::Transaction) -> ledger::TransactionResponse {
    CONFIG
        .with(|c| {
            let config = c.borrow();
            check_caller(&config)?;
            STATE.with(|s| {
                let mut state = s.borrow_mut();
                let payload_size = config.payload_size;
                let store = ledger::StableStore { payload_size };
                ledger::transact(&config, &mut state, &store, args)
            })
        })
        .unwrap_or_else(|err| trap(format!("{:?}", err)))
}

#[cfg(not(any(target_arch = "wasm32", test)))]
fn main() {
    candid::export_service!();
    std::print!("{}", __export_service());
}

#[cfg(any(target_arch = "wasm32", test))]
fn main() {}
