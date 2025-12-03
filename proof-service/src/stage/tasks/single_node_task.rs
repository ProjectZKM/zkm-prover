use crate::proto::includes::v1::Step;
use crate::stage::tasks::Trace;
use serde::{Deserialize, Serialize};

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct SingleNodeTask {
    pub task_id: String,
    pub program_id: String,
    pub base_dir: String,
    pub state: u32,
    pub proof_id: String,
    pub elf_path: String,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub elf: Vec<u8>,
    pub private_input_path: String,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub private_inputs: Vec<Vec<u8>>,
    pub receipt_inputs_path: String,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub receipt_inputs: Vec<Vec<u8>>,
    pub target_step: Step,
    pub trace: Trace,
    pub proof: Vec<u8>,
    pub public_values: Vec<u8>,
    pub vk: Vec<u8>,
    pub seg_size: u32,
    pub total_cycles: u64,
    #[serde(default)]
    pub local_prover_threads: u32,
}
