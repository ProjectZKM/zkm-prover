use lru::LruCache;
use once_cell::sync::OnceCell;
use parking_lot::Mutex;
use std::num::NonZeroUsize;
use std::sync::{Arc, OnceLock};
use std::time::Duration;
use zkm_core_executor::{Program, ZKMContextBuilder};
use zkm_core_machine::io::ZKMStdin;
#[cfg(feature = "gpu")]
use zkm_gpu_core::{
    merkle_tree::FieldMerkleTreeDeviceCommitter,
    poseidon2::{bn254::DeviceHasherBn254, koala_bear::DeviceHasherKoalaBear},
    stark::StarkProvingKeyDevice,
};
use zkm_prover::{CoreSC, OuterSC, ZKMProver};
#[cfg(not(feature = "gpu"))]
use zkm_stark::StarkProvingKey;
use zkm_stark::{StarkVerifyingKey, ZKMProverOpts};

pub use zkm_sdk;

pub mod agg_prover;
pub mod contexts;
pub mod executor;
#[cfg(feature = "gpu")]
pub mod gpu_scheduler;
pub mod root_prover;
pub mod snark_prover;

pub mod pipeline;
pub mod single_node_prover;

pub const FIRST_LAYER_BATCH_SIZE: usize = 1;

pub struct NetworkProve<'a> {
    pub context_builder: ZKMContextBuilder<'a>,
    pub stdin: ZKMStdin,
    pub opts: ZKMProverOpts,
    pub timeout: Option<Duration>,
}

impl Default for NetworkProve<'_> {
    fn default() -> Self {
        Self {
            context_builder: ZKMContextBuilder::default(),
            stdin: ZKMStdin::default(),
            #[cfg(not(feature = "gpu"))]
            opts: ZKMProverOpts::default(),
            #[cfg(feature = "gpu")]
            opts: zkm_gpu_prover::gpu_prover_opts(),
            timeout: None,
        }
    }
}

impl NetworkProve<'_> {
    pub fn new(shard_size: u32) -> Self {
        if shard_size > 0 {
            std::env::set_var("SHARD_SIZE", shard_size.to_string());
        }
        let keccaks: usize = std::env::var("KECCAK_PER_SHARD")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or_default();

        let mut prove = Self::default();
        if keccaks > 0 {
            prove.opts.core_opts.split_opts.keccak = keccaks;
        }
        if shard_size > 0 {
            std::env::remove_var("SHARD_SIZE");
        }

        prove
    }
}

// #[derive(Debug, Clone, Default, Serialize, Deserialize)]
// pub struct StateWithPublicValues {
//     pub state: ExecutionState,
//     pub public_values: PublicValues<u32, u32>,
// }
//
// #[derive(Debug, Clone, Serialize, Deserialize)]
// pub enum Segment {
//     State(Box<StateWithPublicValues>),
//     Record(Box<ExecutionRecord>),
// }

#[cfg(feature = "gpu")]
type ProverComponents = zkm_gpu_prover::components::GpuProverComponents;
#[cfg(not(feature = "gpu"))]
type ProverComponents = zkm_prover::components::DefaultProverComponents;

static GLOBAL_PROVER: OnceLock<Arc<ZKMProver<ProverComponents>>> = OnceLock::new();

pub fn get_prover() -> Arc<ZKMProver<ProverComponents>> {
    GLOBAL_PROVER
        .get_or_init(|| Arc::new(ZKMProver::new()))
        .clone()
}

#[cfg(not(feature = "gpu"))]
type WrapProvingKey = StarkProvingKey<OuterSC>;
#[cfg(feature = "gpu")]
type WrapProvingKey =
    StarkProvingKeyDevice<OuterSC, FieldMerkleTreeDeviceCommitter<DeviceHasherBn254>>;

static WRAP_KEYS: OnceCell<(WrapProvingKey, StarkVerifyingKey<OuterSC>)> = OnceCell::new();

#[cfg(not(feature = "gpu"))]
type ProvingKey = StarkProvingKey<CoreSC>;
#[cfg(feature = "gpu")]
type ProvingKey =
    StarkProvingKeyDevice<CoreSC, FieldMerkleTreeDeviceCommitter<DeviceHasherKoalaBear>>;
type KeyCacheKey = (u32, String);

pub struct KeyCacheEntry {
    value: OnceLock<(ProvingKey, StarkVerifyingKey<CoreSC>)>,
}

impl KeyCacheEntry {
    pub fn new() -> Self {
        Self {
            value: OnceLock::new(),
        }
    }

    pub fn get_or_init_with<F>(&self, init: F) -> (&ProvingKey, &StarkVerifyingKey<CoreSC>)
    where
        F: FnOnce() -> (ProvingKey, StarkVerifyingKey<CoreSC>),
    {
        self.value.get_or_init(init);
        let pair = self.value.get().expect("key cache entry was initialized");
        (&pair.0, &pair.1)
    }
}

pub struct StarkKeyCache {
    pub cache: LruCache<KeyCacheKey, Arc<KeyCacheEntry>>,
}

impl StarkKeyCache {
    pub fn new(size: usize) -> Self {
        let cache =
            LruCache::<KeyCacheKey, Arc<KeyCacheEntry>>::new(NonZeroUsize::new(size).unwrap());
        Self { cache }
    }

    pub fn get(&mut self, device_id: u32, program_id: &str) -> Option<Arc<KeyCacheEntry>> {
        self.cache.get(&(device_id, program_id.to_owned())).cloned()
    }

    pub fn entry(&mut self, device_id: u32, program_id: String) -> Arc<KeyCacheEntry> {
        if let Some(entry) = self.cache.get(&(device_id, program_id.clone())) {
            entry.clone()
        } else {
            let entry = Arc::new(KeyCacheEntry::new());
            self.cache.push((device_id, program_id), entry.clone());
            entry
        }
    }
}

pub struct ProgramCache {
    pub cache: LruCache<String, Program>,
}

impl ProgramCache {
    pub fn new(size: usize) -> Self {
        let cache = LruCache::<String, Program>::new(NonZeroUsize::new(size).unwrap());
        Self { cache }
    }
    pub fn contains(&mut self, key: &String) -> bool {
        self.cache.get(key).is_some()
    }
    pub fn push(&mut self, key: String, v: Program) {
        self.cache.push(key.clone(), v);
    }
}

pub struct VkCache {
    pub cache: LruCache<String, StarkVerifyingKey<CoreSC>>,
}

impl VkCache {
    pub fn new(size: usize) -> Self {
        let cache =
            LruCache::<String, StarkVerifyingKey<CoreSC>>::new(NonZeroUsize::new(size).unwrap());
        Self { cache }
    }
    pub fn get(&mut self, key: &String) -> Option<StarkVerifyingKey<CoreSC>> {
        self.cache.get(key).cloned()
    }
    pub fn push(&mut self, key: String, v: StarkVerifyingKey<CoreSC>) {
        self.cache.push(key.clone(), v);
    }
}

const DEFAULT_CACHE_SIZE: usize = 5;

lazy_static::lazy_static! {
    pub static ref KEY_CACHE: Mutex<StarkKeyCache> =
        Mutex::new(StarkKeyCache::new(DEFAULT_CACHE_SIZE * 8));
    pub static ref PROGRAM_CACHE: Mutex<ProgramCache> =
        Mutex::new(ProgramCache::new(DEFAULT_CACHE_SIZE * 8));
    pub static ref VK_CACHE: Mutex<VkCache> =
        Mutex::new(VkCache::new(DEFAULT_CACHE_SIZE));
}
