use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
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
        }
    }
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
    pub private_input_path: String,
    pub receipt_inputs_path: String,
}
