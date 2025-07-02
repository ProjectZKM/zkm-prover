use crate::stage::tasks::Trace;
use serde::{Deserialize, Serialize};
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct SingleNodeTask {
    pub task_id: String,
    pub program_id: String,
    pub state: u32,
    pub proof_id: String,
    pub base_dir: String,
    pub elf_path: String,
    pub public_input_path: String,
    pub private_input_path: String,
    pub args: String,
    pub block_no: Option<u64>,
    pub receipt_inputs_path: String,
    pub trace: Trace,
    pub output: Vec<u8>, // receipt: (reduced proof, vk)
}