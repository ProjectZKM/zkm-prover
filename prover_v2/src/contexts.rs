use serde::{Deserialize, Serialize};
use std::sync::Arc;

#[derive(Clone)]
pub struct SegmentPayload {
    pub index: usize,
    pub token: String,
    pub generated: usize,
    pub bytes: Arc<Vec<u8>>,
}

pub type SegmentCallback = Arc<dyn Fn(SegmentPayload) + Send + Sync>;

#[derive(Clone, Serialize, Deserialize, Default)]
pub struct SplitContext {
    pub base_dir: String,
    pub program_id: String,
    pub elf_path: String,
    pub block_no: Option<u64>,
    pub seg_size: u32,
    pub seg_path: String,
    // TODO: remove
    pub public_input_path: String,
    pub private_input_path: String,
    pub output_path: String,
    pub args: String,
    pub receipt_inputs_path: String,
    #[serde(skip)]
    pub segment_callback: Option<SegmentCallback>,
    pub job_id: String,
}

impl std::fmt::Debug for SplitContext {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SplitContext")
            .field("base_dir", &self.base_dir)
            .field("program_id", &self.program_id)
            .field("elf_path", &self.elf_path)
            .field("block_no", &self.block_no)
            .field("seg_size", &self.seg_size)
            .field("seg_path", &self.seg_path)
            .field("public_input_path", &self.public_input_path)
            .field("private_input_path", &self.private_input_path)
            .field("output_path", &self.output_path)
            .field("args", &self.args)
            .field("receipt_inputs_path", &self.receipt_inputs_path)
            .field("job_id", &self.job_id)
            .finish()
    }
}

impl SplitContext {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        basedir: &str,
        program_id: &str,
        elf_path: &str,
        block_no: Option<u64>,
        seg_size: u32,
        seg_path: &str,
        public_input_path: &str,
        private_input_path: &str,
        output_path: &str,
        args: &str,
        receipt_inputs_path: &str,
        job_id: &str,
    ) -> Self {
        SplitContext {
            base_dir: basedir.to_string(),
            program_id: program_id.to_string(),
            elf_path: elf_path.to_string(),
            block_no,
            seg_size,
            seg_path: seg_path.to_string(),
            public_input_path: public_input_path.to_string(),
            private_input_path: private_input_path.to_string(),
            output_path: output_path.to_string(),
            args: args.to_string(),
            receipt_inputs_path: receipt_inputs_path.to_string(),
            segment_callback: None,
            job_id: job_id.to_string(),
        }
    }
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct SplitResult {
    pub total_steps: u64,
    pub total_segments: u32,
    pub public_values: Vec<u8>,
    pub deferred_inputs: Vec<Vec<u8>>,
}

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub struct ProveContext {
    pub proof_id: String,
    pub program_id: String,
    pub index: usize,
    pub elf_path: String,
    // execution record
    // pub segment: Vec<u8>,
    pub segment: String,
    pub seg_size: u32,
    // pub receipts_input: Vec<Vec<u8>>,
}

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub struct AggContext {
    // for leaf layer proof
    pub vk: Vec<u8>,
    // proofs for leaf layer, proofs and vks for other layers
    pub proofs: Vec<Vec<u8>>,
    pub is_complete: bool,
    // for leaf layer proof
    pub is_first_shard: bool,
    pub is_leaf_layer: bool,
    pub is_deferred: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub struct SnarkContext {
    pub version: i32,
    pub proof_id: String,
    // pub proving_key_path: String,
    pub agg_receipt: Vec<u8>,
    pub from_input: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub struct SingleNodeContext {
    pub program_id: String,
    pub elf_path: String,
    pub base_dir: String,
    pub seg_size: u32,
    pub private_input_path: String,
    pub receipt_inputs_path: String,
    pub target_step: i32,
}
