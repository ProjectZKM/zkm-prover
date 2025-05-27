use lru::LruCache;
use once_cell::sync::OnceCell;
use std::sync::{Mutex, MutexGuard};
use std::num::NonZeroUsize;
use std::sync::Mutex;
use std::time::Duration;
use zkm_core_executor::ZKMContextBuilder;
use zkm_core_machine::io::ZKMStdin;
#[cfg(feature = "gpu")]
use zkm_cuda_adaptor::GpuProverComponents;
#[cfg(not(feature = "gpu"))]
use zkm_prover::components::DefaultProverComponents;
use zkm_prover::{CoreSC, OuterSC, ZKMProver};
use zkm_stark::{StarkProvingKey, StarkVerifyingKey, ZKMProverOpts};

pub use zkm_sdk;

pub mod agg_prover;
pub mod contexts;
pub mod executor;
pub mod root_prover;
pub mod snark_prover;

pub mod pipeline;

pub const FIRST_LAYER_BATCH_SIZE: usize = 1;

#[derive(Default)]
pub struct NetworkProve<'a> {
    pub context_builder: ZKMContextBuilder<'a>,
    pub stdin: ZKMStdin,
    pub opts: ZKMProverOpts,
    pub timeout: Option<Duration>,
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

#[cfg(not(feature = "gpu"))]
type ProverComponents = DefaultProverComponents;
#[cfg(feature = "gpu")]
type ProverComponents = GpuProverComponents;
static GLOBAL_PROVER: OnceCell<Mutex<ZKMProver<ProverComponents>>> = OnceCell::new();
fn prover_instance() -> &'static Mutex<ZKMProver<ProverComponents>> {
    GLOBAL_PROVER.get_or_init(|| Mutex::new(ZKMProver::new()))
}

pub fn get_prover() -> MutexGuard<'static, ZKMProver<ProverComponents>> {
    prover_instance()
        .lock()
        .expect("GLOBAL_PROVER lock poisoned")
}

static WRAP_KEYS: OnceCell<(StarkProvingKey<OuterSC>, StarkVerifyingKey<OuterSC>)> =
    OnceCell::new();

const DEFAULT_CACHE_SIZE: usize = 3;

pub struct StarkKeyCache {
    pub cache: LruCache<String, (StarkProvingKey<CoreSC>, StarkVerifyingKey<CoreSC>)>,
}

impl StarkKeyCache {
    pub fn new(size: usize) -> Self {
        let cache = LruCache::<String, (StarkProvingKey<CoreSC>, StarkVerifyingKey<CoreSC>)>::new(
            NonZeroUsize::new(size).unwrap(),
        );
        Self { cache }
    }
    pub fn contains(&mut self, key: &String) -> bool {
        self.cache.get(key).is_some()
    }
    pub fn push(&mut self, key: String, v: (StarkProvingKey<CoreSC>, StarkVerifyingKey<CoreSC>)) {
        self.cache.push(key.clone(), v);
    }
}

lazy_static::lazy_static! {
    pub static ref KEY_CACHE: Mutex<StarkKeyCache> =
        Mutex::new(StarkKeyCache::new(DEFAULT_CACHE_SIZE));
}
