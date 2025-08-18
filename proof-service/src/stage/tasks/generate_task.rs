use crate::proto::includes::v1::{Program, ProverVersion, Step};
use serde::{Deserialize, Serialize};
//use zkm_emulator::utils::get_block_path;
use crate::stage::{/*read_block_data, */ safe_read};
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct GenerateTask {
    pub program_id: String,
    pub base_dir: String,
    pub proof_id: String,
    pub version: ProverVersion,
    pub elf_path: String,
    pub seg_path: String,
    pub prove_path: String,
    pub agg_path: String,
    pub snark_path: String,
    pub public_input_path: String,
    pub private_input_path: String,
    pub output_stream_path: String,
    pub block_no: Option<u64>,
    pub seg_size: u32,
    pub max_prover_num: u32,
    pub target_step: Step,
    pub from_step: Step,
    pub single_node: bool,
    pub composite_proof: bool,
    pub receipt_inputs_path: String,
    pub receipts_path: String,
    #[serde(skip_serializing, skip_deserializing)]
    pub program: Option<Program>,
}

impl GenerateTask {
    // load the segement from file_no
    pub fn gen_program(&self) -> Program {
        if self.program.is_some() {
            self.program.clone().unwrap()
        } else {
            let block_data = if let Some(block_no) = self.block_no {
                //let block_path = get_block_path(&self.base_dir, &block_no.to_string(), "");
                //read_block_data(block_no, &block_path)
                // FIXME
                if block_no > 0 {
                    todo!()
                } else {
                    vec![]
                }
            } else {
                vec![]
            };

            let receipts = if !self.receipt_inputs_path.is_empty() {
                let data = common::file::new(&self.receipt_inputs_path)
                    .read()
                    .expect("read receipt_inputs_stream failed");
                bincode::deserialize::<Vec<Vec<u8>>>(&data)
                    .expect("deserialize receipt_inputs_stream failed")
            } else {
                vec![]
            };

            Program {
                version: self.version.into(),
                seg_size: self.seg_size,
                elf_path: self.elf_path.clone(),
                block_no: self.block_no,
                block_data,
                public_input_stream: safe_read(&self.public_input_path),
                private_input_stream: safe_read(&self.private_input_path),
                target_step: self.target_step.into(),
                composite_proof: self.composite_proof,
                proof_id: self.proof_id.clone(),
                receipts,
                output_stream: safe_read(&self.output_stream_path),
            }
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub fn new(
        version: ProverVersion,
        program_id: String,
        proof_id: &str,
        base_dir: &str,
        elf_path: &str,
        seg_path: &str,
        prove_path: &str,
        agg_path: &str,
        snark_path: &str,
        public_input_path: &str,
        private_input_path: &str,
        output_stream_path: &str,
        block_no: Option<u64>,
        seg_size: u32,
        max_prover_num: u32,
        from_step: Step,
        target_step: Step,
        single_node: bool,
        composite_proof: bool,
        receipt_inputs_path: &str,
        receipts_path: &str,
    ) -> Self {
        GenerateTask {
            program_id,
            version,
            proof_id: proof_id.to_string(),
            base_dir: base_dir.to_string(),
            elf_path: elf_path.to_string(),
            seg_path: seg_path.to_string(),
            prove_path: prove_path.to_string(),
            agg_path: agg_path.to_string(),
            snark_path: snark_path.to_string(),
            public_input_path: public_input_path.to_string(),
            private_input_path: private_input_path.to_string(),
            output_stream_path: output_stream_path.to_string(),
            block_no,
            seg_size,
            max_prover_num,
            target_step,
            from_step,
            single_node,
            composite_proof,
            receipt_inputs_path: receipt_inputs_path.to_string(),
            receipts_path: receipts_path.to_string(),
            program: None,
        }
    }
}
