use crate::poseidon::poseidon_hash;
use crate::verifier::{field_size, verify_proof};
use bn::{arith::U256, Fr};
use ic_cdk::api::stable::{stable64_grow, stable64_read, stable64_size, stable64_write};
use ic_cdk::export::{candid::CandidType, Principal};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use spnr_lib::flat_tree::{level_of_node_index, FlatStore, FlatTree, Merkleable, Pos, MAX_LEVEL};
use std::cell::RefCell;
use std::collections::{BTreeMap, BTreeSet, VecDeque};

// Wasm page size is 64KB.
pub const PAGE_SIZE: u64 = 1 << 16;

// Number of bytes in each hash values.
pub const BYTES: usize = 32;

#[derive(CandidType, Serialize, Deserialize, Clone, Debug, Hash, Default)]
pub struct TokenType {
    pub name: String,
    pub decimal: u8,
}

pub type Amount = u64;

pub type Bytes = [u8; BYTES];

#[derive(Copy, Clone, Debug)]
pub struct Hash(Fr);

impl std::hash::Hash for Hash {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        let bytes = Bytes::from(self);
        bytes.hash(state);
    }
}

impl TryFrom<Bytes> for Hash {
    type Error = String;

    fn try_from(bytes: Bytes) -> Result<Self, String> {
        let v =
            U256::from_slice(&bytes).map_err(|_| "Failed to convert bytes to U256".to_string())?;
        Ok(Hash(
            Fr::new(v).ok_or_else(|| "Invalid field value".to_string())?,
        ))
    }
}

impl From<&Hash> for Bytes {
    fn from(hash: &Hash) -> Bytes {
        let mut bytes = [0; BYTES];
        // This unwrap is always safe because BYTES == 32
        hash.0.into_u256().to_big_endian(&mut bytes).unwrap();
        bytes
    }
}

impl std::fmt::Display for Hash {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        use ethereum_types::U256;
        let bytes = Bytes::from(self);
        std::fmt::Display::fmt(&U256::from_big_endian(&bytes), f)
    }
}

impl std::fmt::LowerHex for Hash {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        use ethereum_types::U256;
        let bytes = Bytes::from(self);
        std::fmt::LowerHex::fmt(&U256::from_big_endian(&bytes), f)
    }
}

impl Merkleable for Hash {
    fn zeros(level: usize) -> Self {
        ZEROS.with(|z| z[level])
    }
    fn hash(&self, another: &Self) -> Self {
        Hash(poseidon_hash(&[self.0, another.0]))
    }
}

thread_local! {
    static STABLE_PAGES: RefCell<u64> = RefCell::new(stable64_size());
    static ZEROS: Vec<Hash> = (0..MAX_LEVEL).scan(
        // sha256 of spinner.cash
       Hash(Fr::from_str(
        "16634447132369055297454793671503116842143934528704380699057530544636709094729",
       ).unwrap()), |p, _| {
        let x = *p;
        *p = Hash(poseidon_hash(&[x.0, x.0]));
        Some(x)
       }).collect();
}

// Configuration of the Mixer Canister
#[derive(CandidType, Serialize, Deserialize, Clone, Debug, Hash, Default)]
pub struct Config {
    pub max_level: usize, // number of levels = max_level + 1
    pub token_type: TokenType,
    pub max_recent_roots: usize,
    pub max_scan_range: usize,
    pub allowed_callers: Vec<Principal>,
    pub payload_size: u64, // size of the encrypted part of the payload
}

pub struct StableStore {
    pub payload_size: u64,
}

// Flat store consists rows, each of which consists of:
//  2 hashes from FlatTree + 1 nullifier + 1 extra nullifier + 1 payload
//   \---------------------------------/
//           PREFIX_SIZE = 4 * BYTES
const PREFIX_SIZE: u64 = 4 * BYTES as u64;

impl FlatStore<Hash> for StableStore {
    fn write(&self, offset: u64, value: &Hash) {
        let row = PREFIX_SIZE + self.payload_size;
        let start = (offset / 2) * row + (offset & 1) * BYTES as u64;
        stable64_write(start, &Bytes::from(value))
    }
    fn read(&self, offset: u64, value: &mut Hash) {
        let row = PREFIX_SIZE + self.payload_size;
        let start = (offset / 2) * row + (offset & 1) * BYTES as u64;
        let mut bytes = [0; BYTES];
        //ic_cdk::println!("read offset = {} start = {}", offset, start);
        stable64_read(start, &mut bytes);
        //ic_cdk::println!("read bytes = {:?}", bytes);
        // This panic should never happen unless stable memory is corrupted
        *value = Hash::try_from(bytes).unwrap_or_else(|err| panic!("{}", err))
    }
}

impl FlatStore<Vec<u8>> for StableStore {
    fn write(&self, offset: u64, value: &Vec<u8>) {
        let row = PREFIX_SIZE + self.payload_size;
        let start = offset * row + PREFIX_SIZE;
        assert!(
            value.len() <= self.payload_size as usize,
            "Payload write exceeds payload size"
        );
        stable64_write(start, value);
    }
    fn read(&self, offset: u64, value: &mut Vec<u8>) {
        let row = PREFIX_SIZE + self.payload_size;
        let start = offset * row + PREFIX_SIZE;
        assert!(
            value.len() <= self.payload_size as usize,
            "Payload read exceeds payload size"
        );
        stable64_read(start, value);
    }
}

// Wrapper of nullifier
#[derive(Default)]
pub struct Nullifier(Bytes);

impl FlatStore<Nullifier> for StableStore {
    fn write(&self, offset: u64, value: &Nullifier) {
        let row = PREFIX_SIZE + self.payload_size;
        let start = offset * row + 2 * BYTES as u64;
        stable64_write(start, &value.0);
    }
    fn read(&self, offset: u64, value: &mut Nullifier) {
        let row = PREFIX_SIZE + self.payload_size;
        let start = offset * row + 2 * BYTES as u64;
        stable64_read(start, &mut value.0);
    }
}

// Wrapper of extra nullifier. This is used when the ledger reaches capacity,
// where no more deposit/transfer could be made, but only withdrawal is allowed.
// We need to reserve space to anticipate this happening.
#[derive(Default)]
pub struct ExtraNullifier(Bytes);

impl FlatStore<ExtraNullifier> for StableStore {
    fn write(&self, offset: u64, value: &ExtraNullifier) {
        let row = PREFIX_SIZE + self.payload_size;
        let start = offset * row + 3 * BYTES as u64;
        stable64_write(start, &value.0);
    }
    fn read(&self, offset: u64, value: &mut ExtraNullifier) {
        let row = PREFIX_SIZE + self.payload_size;
        let start = offset * row + 3 * BYTES as u64;
        stable64_read(start, &mut value.0);
    }
}

pub trait FlatHashStore: FlatStore<Hash> {
    fn index_in_range(&self, offset: u64) -> Result<(), String>;
    fn ensure_index_in_range(&self, offset: u64) -> Result<(), String>;
    fn as_flat_store(&self) -> &dyn FlatStore<Hash>;
}

impl FlatHashStore for StableStore {
    fn index_in_range(&self, offset: u64) -> Result<(), String> {
        STABLE_PAGES.with(|stable_pages| {
            let row = PREFIX_SIZE + self.payload_size;
            let last = (offset / 2 + 1) * row - 1;
            let page_index = last / PAGE_SIZE + 1;
            if page_index > *stable_pages.borrow() {
                Err("Index out of range".to_string())
            } else {
                Ok(())
            }
        })
    }
    fn ensure_index_in_range(&self, offset: u64) -> Result<(), String> {
        STABLE_PAGES.with(|stable_pages| {
            /*
            ic_cdk::println!(
                "stable_pages = {} offset = {} self.num_denomiations = {} self.index = {}",
                *stable_pages.borrow(),
                &offset,
                &self.num_denominations,
                &self.index
            );
            */
            let row = PREFIX_SIZE + self.payload_size;
            let last = (offset / 2 + 1) * row - 1;
            let page_index = last / PAGE_SIZE + 1;
            let pages = *stable_pages.borrow();
            if page_index > pages {
                stable64_grow(page_index - pages).map_err(|_| {
                    format!("Out of stable memory, requested page = {}", page_index)
                })?;
                *stable_pages.borrow_mut() = page_index;
            }
            Ok(())
        })
    }
    fn as_flat_store(&self) -> &dyn FlatStore<Hash> {
        self
    }
}

// State of the Mixer Canister
#[derive(Default)]
pub struct State {
    pub store_size: u64,
    pub recent_roots: RecentRoots<Bytes>,
    pub committed: BTreeMap<Bytes, usize>,
    pub nullified: BTreeSet<Bytes>,
    pub extra_nullified: u64,
}

impl State {
    pub fn restore<Store>(config: &Config, store_size: u64, store: &Store) -> Result<Self, String>
    where
        Store: FlatHashStore,
        Store: FlatStore<Nullifier>,
    {
        //ic_cdk::println!("store_sizes = {:?}", store_sizes);
        let mut committed = BTreeMap::new();
        let mut nullified = BTreeSet::new();
        let mut recent_roots = RecentRoots::new(config.max_recent_roots);
        if store_size > 0 {
            store.ensure_index_in_range(store_size - 1)?;
            let tree = FlatTree::new(store.as_flat_store(), store_size);
            for (i, commitment) in tree.iter().enumerate() {
                if committed.insert(Bytes::from(&commitment), i * 2).is_some() {
                    return Err("Repeated commitments in flat store!".to_string());
                }
                let mut nullifier = Nullifier::default();
                store.read(i as u64, &mut nullifier);
                if !nullified.insert(nullifier.0) {
                    return Err("Repeated nullifiers in flat store!".to_string());
                }
            }
            let roots = &mut recent_roots.queue;
            let n = store_size / 2;
            let mut m = n;
            for j in 0..config.max_recent_roots {
                let k = 1 << j;
                let tree = FlatTree::new(store.as_flat_store(), m * 2);
                let root = Root::new(m, Bytes::from(&tree_root(&tree, config.max_level)));
                //ic_cdk::println!("push {} {} {} {}", i, j, k, m);
                roots.push_back(root);
                if m == 0 {
                    break;
                }
                m = (m - 1) / k * k;
            }
        }

        //ic_cdk::println!("recent_roots {:?}", recent_roots);
        // TODO: implement persistence support for extra_nullified
        Ok(Self {
            store_size,
            committed,
            nullified,
            recent_roots,
            extra_nullified: 0,
        })
    }

    pub fn init(&mut self, config: &Config) {
        assert!(config.max_level <= MAX_LEVEL);
        self.store_size = 0;
        self.recent_roots = RecentRoots::new(config.max_recent_roots);
    }

    pub fn storage_info(&self, config: &Config) -> StorageInfo {
        let row = PREFIX_SIZE + config.payload_size;
        let flat_store_bytes = self.store_size / 2 * row;
        StorageInfo { flat_store_bytes }
    }
}

#[derive(CandidType, Serialize, Deserialize, Clone, Debug, PartialEq, Eq, Hash)]
pub struct Root<T> {
    pub width: Width,
    pub value: T,
}

impl<T> Root<T> {
    pub fn new(width: u64, value: T) -> Self {
        Self { width, value }
    }
}

impl Default for Root<Hash> {
    fn default() -> Self {
        Root::new(0, Hash::zeros(0))
    }
}

// A fixed sized queue recording recent roots. The gap between the width of these past
// roots follows the sequence of 2^n.
#[derive(CandidType, Serialize, Deserialize, Clone, Debug, Hash, Default)]
pub struct RecentRoots<T> {
    max_size: usize,
    queue: VecDeque<Root<T>>,
}

impl<T: std::fmt::Debug> RecentRoots<T> {
    pub fn new(max_size: usize) -> Self {
        Self {
            max_size,
            queue: VecDeque::with_capacity(max_size),
        }
    }

    pub fn push(&mut self, root: Root<T>) {
        let n = root.width;
        self.queue.push_front(root);
        let mut queue = VecDeque::with_capacity(self.max_size);
        let mut m = n;
        for i in 0..self.max_size {
            let j = 1 << i;
            while let Some(r) = self.queue.pop_front() {
                match r.width.cmp(&m) {
                    std::cmp::Ordering::Equal => {
                        queue.push_back(r);
                        break;
                    }
                    std::cmp::Ordering::Less => {
                        self.queue.push_front(r);
                        break;
                    }
                    _ => (),
                }
            }
            if m == 0 || queue.len() == self.max_size {
                break;
            }
            m = (m - 1) / j * j;
        }
        self.queue = queue;
    }

    pub fn iter(&self) -> Box<dyn Iterator<Item = &Root<T>> + '_> {
        Box::new(self.queue.iter())
    }
}

#[derive(CandidType, Serialize, Deserialize, Clone, Debug, Hash)]
pub struct TreeInfo {
    pub recent_roots: Vec<Root<Bytes>>,
}

#[derive(CandidType, Serialize, Deserialize, Clone, Debug, Hash)]
pub struct StorageInfo {
    pub flat_store_bytes: u64,
}

#[derive(CandidType, Serialize, Deserialize, Clone, Debug, Hash)]
pub struct Transaction {
    pub proof: Vec<Vec<u8>>,
    pub root: Bytes,
    pub commitments: [Bytes; 2],
    pub nullifiers: [Bytes; 2],
    pub amount: Bytes, // BigEndian of amount, which could be positive (withdraw) or negative (deposit).
    pub payload: String,
}

type Width = u64;
pub type Index = u64;

#[derive(CandidType, Serialize, Deserialize, Clone, Debug, Hash)]
pub enum TransactionError {
    DuplicateNullifier(Bytes),
    DuplicateCommitment(Bytes),
    AlreadyNullified(Bytes),
    AlreadyCommitted(Bytes),
    WrongProofLength,
    NotMatchingRecentRoots,
    InvalidPayload(String),
    InvalidProof(String),
    Rejected(String),
}

use TransactionError::*;

impl From<String> for TransactionError {
    fn from(msg: String) -> TransactionError {
        TransactionError::Rejected(msg)
    }
}

#[derive(CandidType, Serialize, Deserialize, Clone, Debug, Hash)]
pub struct TransactionResponse {
    pub committed: [Index; 2],
}

fn tree_root(tree: &FlatTree<Hash>, max_level: usize) -> Hash {
    let mut root = tree.root();
    let mut n = tree.depth();
    if n == 0 {
        n = 1;
    }
    while n <= max_level {
        root = root.hash(&Hash::zeros(n - 1));
        n += 1;
    }
    root
}

pub fn transact<Store>(
    config: &Config,
    state: &mut State,
    store: &Store,
    args: Transaction,
) -> Result<TransactionResponse, TransactionError>
where
    Store: FlatHashStore,
    Store: FlatStore<Vec<u8>>,
    Store: FlatStore<Nullifier>,
{
    transact_(config, state, store, args, true)
}

#[derive(Deserialize)]
pub struct Payload {
    pub encrypted: [String; 2],
}

fn transact_<Store>(
    config: &Config,
    state: &mut State,
    store: &Store,
    args: Transaction,
    check_proof: bool,
) -> Result<TransactionResponse, TransactionError>
where
    Store: FlatHashStore,
    Store: FlatStore<Vec<u8>>,
    Store: FlatStore<Nullifier>,
{
    use ethereum_types::U256;
    // TODO: check caller and/or take cycles deposit
    let Transaction {
        proof,
        root,
        nullifiers,
        commitments,
        amount,
        payload,
    } = args;

    // Check payload
    let decoded: Payload = serde_json::from_str(&payload)
        .map_err(|_| InvalidPayload("Not a JSON, or missing encrypted field".to_string()))?;
    let encrypted = decoded
        .encrypted
        .clone()
        .into_iter()
        .map(|s| base64::decode(s))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| InvalidPayload("Not base64 encoded".to_string()))?;
    for data in encrypted.iter() {
        if data.len() != config.payload_size as usize {
            return Err(InvalidPayload(format!(
                "Expect {} payload size, but got {}",
                config.payload_size,
                data.len(),
            )));
        }
    }

    // Check proof
    if proof.len() != 8 {
        return Err(WrongProofLength);
    };
    // Check root
    let store_size = state.store_size;
    if store_size > 0 {
        store.index_in_range(store_size - 1)?;
        if !state.recent_roots.iter().any(|x| x.value == root) {
            return Err(NotMatchingRecentRoots);
        };
    }
    // Check nullifier
    let mut nullifier_set = BTreeSet::new();
    for nullifier in nullifiers.iter() {
        let _ = Hash::try_from(nullifier.clone())?;
        if !nullifier_set.insert(nullifier.clone()) {
            return Err(DuplicateNullifier(nullifier.clone()));
        }
        if state.nullified.contains(nullifier) {
            return Err(AlreadyNullified(nullifier.clone()));
        }
    }
    let mut commitment_set = BTreeSet::new();
    for commitment in commitments.iter() {
        let _ = Hash::try_from(commitment.clone())?;
        if !commitment_set.insert(commitment.clone()) {
            return Err(DuplicateCommitment(commitment.clone()));
        }
        if state.committed.get(commitment).is_some() {
            return Err(AlreadyCommitted(commitment.clone()));
        }
    }
    let proof = [
        U256::from_big_endian(&proof[0]),
        U256::from_big_endian(&proof[1]),
        U256::from_big_endian(&proof[2]),
        U256::from_big_endian(&proof[3]),
        U256::from_big_endian(&proof[4]),
        U256::from_big_endian(&proof[5]),
        U256::from_big_endian(&proof[6]),
        U256::from_big_endian(&proof[7]),
    ];
    if check_proof {
        let mut hasher = Sha256::new();
        hasher.update(&payload);
        let checksum = hasher.finalize();
        let fieldsize = field_size();
        let input = [
            U256::from_big_endian(&root),
            U256::from_big_endian(&amount).overflowing_add(fieldsize).0 % fieldsize,
            U256::from_big_endian(&checksum) % fieldsize,
            U256::from_big_endian(&nullifiers[0]),
            U256::from_big_endian(&nullifiers[1]),
            U256::from_big_endian(&commitments[0]),
            U256::from_big_endian(&commitments[1]),
        ];
        if !verify_proof(&proof, &input) {
            return Err(InvalidProof(
                format!(
                    "{}\n{}\n{}\n{}\n{}\n{}\n{}",
                    input[0], input[1], input[2], input[3], input[4], input[5], input[6]
                )
                .to_string(),
            ));
        };
    }
    for nullifier in nullifiers.into_iter() {
        state.nullified.insert(nullifier);
    }
    let mut committed = [0; 2];
    for (i, commitment) in commitments.into_iter().enumerate() {
        let hash = Hash::try_from(commitment)?;
        let store_size = state.store_size;
        let new_store_size = store_size + 2; // each insert adds two values to flat tree store
        store.ensure_index_in_range(new_store_size - 1)?;
        let mut tree = FlatTree::new(store.as_flat_store(), store_size);
        tree.push(hash);
        state.store_size = new_store_size;
        let node_index = 2 * (tree.len() - 1);
        state.committed.insert(commitment, node_index as usize);
        committed[i] = node_index;
        let root = tree_root(&tree, config.max_level);
        state
            .recent_roots
            .push(Root::new(tree.width(), Bytes::from(&root)));
        store.write(store_size / 2, &encrypted[i]);
        store.write(store_size / 2, &Nullifier(nullifiers[i]));
    }
    Ok(TransactionResponse { committed })
}

pub type Level = u8;

#[derive(CandidType, Serialize, Deserialize, Clone, Debug, Hash)]
pub struct PathQuery {
    width: Width,
    node_index: Index, // node_index of a leaf is leaf_index * 2
}

impl PathQuery {
    pub fn new(width: Width, node_index: Index) -> Self {
        Self { width, node_index }
    }
}

#[derive(CandidType, Serialize, Deserialize, Clone, Debug, Hash)]
pub struct MerklePathArgs {
    pub queries: Vec<PathQuery>,
}

#[derive(CandidType, Serialize, Deserialize, Clone, Debug, Hash)]
pub struct MerklePath {
    pub root: Bytes,
    pub path_elements: Vec<Bytes>,
    pub path_index: Vec<u8>,
    pub element: Bytes,
}

#[derive(CandidType, Serialize, Deserialize, Clone, Debug, Hash)]
pub struct MerklePathResponse {
    pub paths: Vec<MerklePath>,
}

pub fn merkle_path(
    config: &Config,
    state: &State,
    store: &dyn FlatHashStore,
    args: MerklePathArgs,
) -> Result<MerklePathResponse, String> {
    // TODO: check caller and/or take cycles deposit
    let mut paths = Vec::new();
    for PathQuery { width, node_index } in args.queries.into_iter() {
        if width == 0 {
            return Err("Width is 0".to_string());
        }
        let mut store_size = state.store_size;
        if width * 2 > store_size {
            return Err(format!("Width {} is to big", width));
        }
        store_size = width * 2;
        let mut root = Hash::zeros(0);
        let mut element = root;
        let mut path_elements = Vec::new();
        let mut path_index = Vec::new();
        let mut level = level_of_node_index(node_index);
        if store_size > 0 {
            store.index_in_range(store_size - 1)?;
            store.index_in_range(node_index)?;
            let tree = FlatTree::new(store.as_flat_store(), store_size);
            for p in tree.full_path_from_node_index(node_index) {
                match p {
                    Pos::Start(r) => {
                        root = r;
                        element = r;
                    }
                    Pos::Left(h) => {
                        path_index.push(1);
                        path_elements.push(Bytes::from(&h));
                        root = Hash(poseidon_hash(&[h.0, root.0]));
                        level += 1;
                    }
                    Pos::Right(h) => {
                        path_index.push(0);
                        path_elements.push(Bytes::from(&h));
                        root = Hash(poseidon_hash(&[root.0, h.0]));
                        level += 1;
                    }
                }
            }
        }
        if level == 0 && store_size > 2 {
            return Err(format!(
                "Node index {} is not found in tree of size {}",
                node_index, store_size
            ));
        }
        while level < config.max_level {
            path_index.push(0);
            let zero = Hash::zeros(level);
            path_elements.push(Bytes::from(&zero));
            root = Hash(poseidon_hash(&[root.0, zero.0]));
            level += 1;
        }
        paths.push(MerklePath {
            element: Bytes::from(&element),
            path_elements,
            path_index,
            root: Bytes::from(&root),
        })
    }
    Ok(MerklePathResponse { paths })
}

pub fn tree_info(state: &State) -> TreeInfo {
    TreeInfo {
        recent_roots: state.recent_roots.iter().cloned().collect::<Vec<_>>(),
    }
}

#[derive(CandidType, Serialize, Deserialize, Clone, Debug, Hash)]
pub struct Range {
    /// Starting index, inclusive.
    start: usize,
    /// Ending index, non-inclusive.
    end: usize,
}

#[derive(CandidType, Serialize, Deserialize, Clone, Debug, Hash)]
pub struct ScanResponse {
    pub range: Range,
    pub commitments: Vec<Bytes>,
    pub nullifiers: Vec<Bytes>,
    pub payloads: Vec<Vec<u8>>,
}

/// Scan stored data by answering a range query.
pub fn scan<Store>(
    config: &Config,
    state: &State,
    store: &Store,
    range: Range,
) -> Result<ScanResponse, String>
where
    Store: FlatHashStore,
    Store: FlatStore<Vec<u8>>,
    Store: FlatStore<Nullifier>,
{
    let store_size = state.store_size;
    let start = range.start as u64;
    let mut end = range.end as u64;
    if store_size == 0 {
        Ok(ScanResponse {
            range: Range { start: 0, end: 0 },
            commitments: vec![],
            nullifiers: vec![],
            payloads: vec![],
        })
    } else {
        store.ensure_index_in_range(store_size - 1)?;
        let tree = FlatTree::new(store.as_flat_store(), store_size);
        let width = tree.width();
        if start >= width {
            return Err("OutOfRange".to_string());
        }
        if end < start {
            return Err("InvalidRange".to_string());
        }
        if end - start > config.max_scan_range as u64 {
            end = start + config.max_scan_range as u64;
        }
        if end > width {
            end = width;
        }
        Ok(ScanResponse {
            range: Range {
                start: start as usize,
                end: end as usize,
            },
            commitments: (start..end)
                .map(|i| Bytes::from(&tree.get(i).expect("MissingLeaf")))
                .collect(),
            nullifiers: (start..end)
                .map(|i| {
                    let mut nullifier = Nullifier::default();
                    store.read(i as u64, &mut nullifier);
                    nullifier.0
                })
                .collect(),
            payloads: (start..end)
                .map(|i| {
                    let mut bytes = vec![0; config.payload_size as usize];
                    store.read(i as u64, &mut bytes);
                    bytes
                })
                .collect::<Vec<Vec<u8>>>(),
        })
    }
}

/// Return the node_index for each of input hashes if they have been
/// inserted into the merkle tree. Otherwise the returned index is -1.
pub fn committed(state: &State, hashs: Vec<Bytes>) -> Vec<i64> {
    hashs
        .iter()
        .map(|h| state.committed.get(h).map(|x| *x as i64).unwrap_or(-1))
        .collect()
}

/// Check whether the input hashes have already been nullified.
pub fn nullified(state: &State, hashs: Vec<Bytes>) -> Vec<bool> {
    hashs.iter().map(|h| state.nullified.contains(h)).collect()
}

#[cfg(test)]
mod test {
    use super::*;
    use assert_matches::assert_matches;
    use hex::FromHex;
    const PAYLOAD_SIZE: u64 = 10;

    fn test_config() -> Config {
        Config {
            max_level: 8,
            token_type: TokenType::default(),
            max_recent_roots: 8,
            max_scan_range: 4096,
            allowed_callers: Vec::new(),
            payload_size: PAYLOAD_SIZE,
        }
    }

    fn add_payload(tx: &mut Transaction, len: usize) {
        use serde_json::json;
        let m = base64::encode(vec![65; len]);
        let n = base64::encode(vec![66; len]);
        let data = json!({ "encrypted": [m, n] });
        tx.payload = serde_json::to_string(&data).unwrap();
    }

    fn test_transaction(
        root: Bytes,
        amount: i64,
        c0: i64,
        c1: i64,
        n0: i64,
        n1: i64,
    ) -> Transaction {
        let to_bytes = |i| Bytes::from_hex(&format!("{:064x}", i)).unwrap();
        let mut tx = Transaction {
            proof: vec![
                vec![],
                vec![],
                vec![],
                vec![],
                vec![],
                vec![],
                vec![],
                vec![],
            ],
            root,
            commitments: [to_bytes(c0), to_bytes(c1)],
            nullifiers: [to_bytes(n0), to_bytes(n1)],
            amount: to_bytes(amount),
            payload: "".to_string(),
        };
        add_payload(&mut tx, PAYLOAD_SIZE as usize);
        return tx;
    }

    #[derive(Default)]
    struct TestStore {
        pages: std::cell::RefCell<Vec<Hash>>,
    }

    impl FlatHashStore for TestStore {
        fn index_in_range(&self, offset: u64) -> Result<(), String> {
            if offset as usize >= self.pages.borrow().len() {
                Err("Out of range".to_string())
            } else {
                Ok(())
            }
        }
        fn ensure_index_in_range(&self, offset: u64) -> Result<(), String> {
            let mut pages = self.pages.borrow_mut();
            let len = PAGE_SIZE as usize / BYTES;
            if offset as usize >= pages.len() {
                pages.resize((offset as usize / len + 1) * len, Hash(Fr::zero()))
            }
            Ok(())
        }
        fn as_flat_store(&self) -> &dyn FlatStore<Hash> {
            self
        }
    }

    impl FlatStore<Hash> for TestStore {
        fn write(&self, offset: u64, value: &Hash) {
            self.pages.borrow_mut()[offset as usize] = *value;
        }
        fn read(&self, offset: u64, value: &mut Hash) {
            *value = self.pages.borrow()[offset as usize];
        }
    }

    impl FlatStore<Vec<u8>> for TestStore {
        fn write(&self, _offset: u64, _value: &Vec<u8>) {}
        fn read(&self, _offset: u64, _value: &mut Vec<u8>) {}
    }

    impl FlatStore<Nullifier> for TestStore {
        fn write(&self, _offset: u64, _value: &Nullifier) {}
        fn read(&self, _offset: u64, _value: &mut Nullifier) {}
    }

    #[test]
    fn test_deposit_and_merkle_paths() {
        let config = test_config();
        let mut state = State::default();
        state.init(&config);
        let store = TestStore::default();
        let root0 = (&<Root<Hash>>::default().value).into();

        // Test payload
        let mut args = test_transaction(root0, 0, 1, 2, 3, 4);
        args.payload = "".to_string();
        let res = transact_(&config, &mut state, &store, args, false);
        assert_matches!(res, Err(InvalidPayload(_)));
        let mut args = test_transaction(root0, 0, 1, 2, 3, 4);
        add_payload(&mut args, (config.payload_size - 1) as usize);
        let res = transact_(&config, &mut state, &store, args, false);
        assert_matches!(res, Err(InvalidPayload(_)));

        // duplicate not allowed
        let args = test_transaction(root0, 0, 1, 1, 3, 4);
        let res = transact_(&config, &mut state, &store, args, false);
        assert_matches!(res, Err(DuplicateCommitment(_)));
        let args = test_transaction(root0, 0, 1, 2, 3, 3);
        let res = transact_(&config, &mut state, &store, args, false);
        assert_matches!(res, Err(DuplicateNullifier(_)));

        // Success
        let args = test_transaction(root0, 0, 1, 2, 3, 4);
        let res = transact_(&config, &mut state, &store, args, false);
        assert_matches!(res, Ok(_));
        assert_eq!(res.unwrap().committed, [0, 2]);

        // roots
        let res = state
            .recent_roots
            .iter()
            .map(|x| x.value)
            .collect::<Vec<_>>();
        assert_eq!(res,
          [ Bytes::from(&Hash(Fr::from_str("13345814569166370306495486240101957422462367875474084800460092210012441893153").unwrap())),
            Bytes::from(&Hash(Fr::from_str("18597775920791890690128302460076654070218988466661900385436595903882349499037").unwrap())),
          ]);
        let root1 = res[0].into();

        // Already Committed
        let args = test_transaction(root1, 0, 7, 2, 5, 6);
        let res = transact_(&config, &mut state, &store, args, false);
        assert_matches!(res, Err(AlreadyCommitted(_)));

        // Already Nullified
        let args = test_transaction(root1, 0, 7, 8, 9, 4);
        let res = transact_(&config, &mut state, &store, args, false);
        assert_matches!(res, Err(AlreadyNullified(_)));

        // Path query
        let path_query = |i| PathQuery::new(state.store_size / 2, i);
        let args = MerklePathArgs {
            queries: vec![path_query(0), path_query(2)],
        };
        let res = merkle_path(&config, &state, &store, args);
        assert_matches!(res, Ok(_));
        let paths = res.unwrap().paths;
        assert_eq!(
            paths[0].root,
            Bytes::from(&Hash(
                Fr::from_str(
                    "13345814569166370306495486240101957422462367875474084800460092210012441893153"
                )
                .unwrap()
            ))
        );
        assert_eq!(
            paths[1].root,
            Bytes::from(&Hash(
                Fr::from_str(
                    "13345814569166370306495486240101957422462367875474084800460092210012441893153"
                )
                .unwrap()
            ))
        )
    }

    use ethereum_types::U256;
    use proptest::prelude::*;

    proptest! {
    #[test]
    fn test_merkle_path(n_: u8, i_: u8, j_: u8) {
        let n = (n_ as usize) % 30;
        if n > 0 {
            let i = (i_ as usize) % n;
            let j = (j_ as usize) % n;
            let config = test_config();
            let mut state = State::default();
            state.init(&config);
            let store = TestStore::default();

            let mut k = 0;
            let root0 = <Root<Hash>>::default();
            let root_ = Root::new(0, (&root0.value).into());
            while k < (n as i64) {
              let root = state.recent_roots.queue.get(0).unwrap_or(&root_).clone().value;
              let args = test_transaction(root, 10, k, k+1, k+2, k+3);
              assert_matches!(transact_(&config, &mut state, &store, args, false), Ok(_));
              println!("k = {} n = {}", k, n);
              k += 2;
            }

            let path_query = |i| PathQuery::new(k as u64, i);

            let root = state.recent_roots.queue.get(0).unwrap().value.clone();
            println!("recent roots = {:?}", state.recent_roots.queue.len());
            println!("root = {:?}", state.recent_roots.queue.get(0));
            if state.recent_roots.queue.len() > 1 { println!("root = {:?}", state.recent_roots.queue.get(1)) };
            let args = MerklePathArgs {
                queries: vec![path_query(2 * i as u64), path_query(2 * j as u64)],
            };
            let res = merkle_path(&config, &mut state, &store, args).unwrap();
            let paths = res.paths;
            println!("paths = {:?}", paths);
            prop_assert_eq!(U256::from_big_endian(&paths[0].element), U256::from(i));
            prop_assert_eq!(U256::from_big_endian(&paths[1].element), U256::from(j));

            prop_assert_eq!(paths[0].root, root);
            prop_assert_eq!(paths[1].root, root);

            fn index_of(index: &[u8]) -> usize {
                let mut s = 0;
                let mut n = 0;
                for i in index {
                    s += (1 << n) * (*i as usize);
                    n += 1;
                }
                s
            }
            prop_assert_eq!(index_of(&paths[0].path_index), i);
            prop_assert_eq!(index_of(&paths[1].path_index), j);
        }
    }
    }

    #[test]
    fn test_recent_roots() {
        let mut r = RecentRoots::new(6);
        let elems = (1..114).map(|x| Root::new(x, x)).collect::<Vec<_>>();
        let eval = |r: &RecentRoots<u64>| r.iter().map(|r| r.value).collect::<Vec<_>>();
        for elem in elems.into_iter() {
            r.push(elem);
            ic_cdk::println!("{:?}", eval(&r));
        }
        assert_eq!(eval(&r), [113, 112, 110, 108, 104, 96]);
    }
}
