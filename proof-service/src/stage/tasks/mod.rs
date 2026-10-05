pub const TASK_STATE_INITIAL: u32 = 0;
pub const TASK_STATE_UNPROCESSED: u32 = 1;
pub const TASK_STATE_PROCESSING: u32 = 2;
pub const TASK_STATE_SUCCESS: u32 = 3;
pub const TASK_STATE_FAILED: u32 = 4;

pub const TASK_TIMEOUT: u64 = 7200;

pub mod split_task;

use serde_derive::{Deserialize, Serialize};
pub use split_task::SplitTask;

pub mod prove_task;
pub use prove_task::ProveTask;

pub mod agg_task;
pub use agg_task::AggTask;

pub mod generate_task;

pub mod single_node_task;
pub use single_node_task::SingleNodeTask;

pub mod snark_task;

pub use snark_task::SnarkTask;

pub const TASK_ITYPE_SPLIT: i32 = 1;
pub const TASK_ITYPE_PROVE: i32 = 2;
pub const TASK_ITYPE_AGG: i32 = 3;
pub const TASK_ITYPE_FINAL: i32 = 5;

pub enum Task {
    Split(SplitTask),
    Prove(ProveTask),
    Agg(AggTask),
    Snark(SnarkTask),
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct Trace {
    pub start_ts: u64,
    pub finish_ts: u64,
    // FIXME: remove?
    pub node_info: String,
}

impl Trace {
    #[inline(always)]
    pub fn duration(&self) -> u64 {
        self.finish_ts - self.start_ts
    }
}
