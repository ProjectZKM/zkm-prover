use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub struct SnarkContext {
    pub version: i32,
    pub proof_id: String,
    // pub proving_key_path: String,
    pub agg_receipt: Vec<u8>,
    pub from_input: bool,
}
