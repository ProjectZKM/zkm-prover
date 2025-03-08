use crate::stage::tasks::Trace;
use serde::{Deserialize, Serialize};

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct SplitTask {
    pub task_id: String,
    pub state: u32,
    pub proof_id: String,
    pub base_dir: String,
    pub elf_path: String,
    pub seg_path: String,
    pub public_input_path: String,
    pub private_input_path: String,
    pub output_path: String,
    pub args: String,
    pub block_no: Option<u64>,
    pub seg_size: u32,
    pub recepit_inputs_path: String,

    pub trace: Trace,

    pub total_steps: u64,
}
