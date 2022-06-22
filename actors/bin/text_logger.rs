use ic_cdk::export::{
    candid::{candid_method, CandidType},
    serde::{Deserialize, Serialize},
    Principal,
};
use ic_cdk_macros::*;
use spnr_lib::{
    log::{Log, LogState},
    storage::{StableStorage, StorageStack},
};
use std::cell::RefCell;

const MAX_VIEW_RANGE: u64 = 1024;

#[derive(CandidType, Serialize, Deserialize, Clone, Debug, Hash, PartialEq, Default)]
pub struct Config {
    bucket_size: usize,
    max_buckets: usize,
    allowed: Vec<Principal>,
}

type Logger<'a> = Log<'a, StableStorage, (String,)>;

thread_local! {
    static ALLOWED : RefCell<Vec<Principal>> = RefCell::new(Vec::new());
    static STATE: RefCell<LogState> = RefCell::new(LogState::default());
}

fn trap<T>(err: String) -> T {
    ic_cdk::api::trap(&err)
}

fn trap_io<T>(err: std::io::Error) -> T {
    trap(format!("{}", err))
}

#[init]
#[candid_method(init)]
fn init(config: Config) {
    STATE.with(|l| l.replace(LogState::new(0, config.bucket_size, config.max_buckets)));
    ALLOWED.with(|a| a.replace(config.allowed));
}

#[pre_upgrade]
fn pre_upgrade() {
    //ic_cdk::println!("in pre upgrade");
    let state = STATE.with(|s| s.replace(LogState::new(0, 0, 0)));
    let allowed = ALLOWED.with(|a| a.replace(vec![]));
    //ic_cdk::println!("state = {:?} allowed = {:?}", logger.state, allowed);
    let mut storage = StableStorage::new().new_with(state.offset);
    storage.push((state, allowed)).unwrap_or_else(trap_io);
    storage.finalize().unwrap_or_else(trap_io);
}

#[post_upgrade]
fn post_upgrade() {
    //ic_cdk::println!("in post upgrade");
    let (state, allowed) = StableStorage::new()
        .pop::<(LogState, Vec<Principal>)>()
        .unwrap_or_else(trap_io);
    //ic_cdk::println!("state = {:?} allowed = {:?}", state, allowed);
    STATE.with(|l| l.replace(state));
    ALLOWED.with(|a| a.replace(allowed));
}

#[derive(CandidType, Serialize, Debug)]
struct Stats {
    number_of_entries: u64,
    max_entries_allowed: u64,
    total_bytes_used: u64,
    max_view_range: u64,
}

#[query]
#[candid_method(query)]
async fn stats() -> Stats {
    STATE.with(|s| {
        let state = s.borrow();
        Stats {
            number_of_entries: state.size,
            total_bytes_used: state.offset,
            max_entries_allowed: state.bucket_size as u64 * state.max_buckets as u64,
            max_view_range: MAX_VIEW_RANGE,
        }
    })
}

#[query]
#[candid_method(query)]
async fn view(start_index: u64, end_index: u64) -> Vec<String> {
    assert!(end_index > start_index);
    assert!(end_index - start_index < MAX_VIEW_RANGE);
    STATE.with(|s| {
        let mut state = s.borrow_mut();
        let mut storage = StableStorage::new();
        let logger: Logger<'_> = Log::new(&mut state, &mut storage);
        let mut entries = Vec::with_capacity((end_index - start_index) as usize);
        for i in start_index..(end_index.min(logger.size())) {
            match logger.get(i) {
                Some(entry) => entries.push(entry.0),
                None => break,
            };
        }
        entries
    })
}

#[update]
#[candid_method(update)]
async fn append(entries: Vec<String>) -> usize {
    let caller = ic_cdk::api::caller();
    ALLOWED.with(|a| assert!(a.borrow().iter().any(|x| *x == caller)));
    STATE.with(|s| {
        let mut state = s.borrow_mut();
        let mut storage = StableStorage::new();
        let mut logger: Log<'_, _, (String,)> = Log::new(&mut state, &mut storage);
        let mut n = 0;
        for entry in entries.into_iter() {
            if logger.push((entry,)).is_none() {
                break;
            };
            n += 1;
        }
        n
    })
}

#[cfg(not(any(target_arch = "wasm32", test)))]
fn main() {
    candid::export_service!();
    std::print!("{}", __export_service());
}

#[cfg(any(target_arch = "wasm32", test))]
fn main() {}
