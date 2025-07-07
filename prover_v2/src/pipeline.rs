use crate::agg_prover::AggProver;
use crate::contexts::{AggContext, ProveContext, SingleNodeContext, SnarkContext, SplitContext};
use crate::executor::Executor;
use crate::root_prover::RootProver;
use crate::single_node_prover::SingleNodeProver;
use crate::snark_prover::SnarkProver;

#[derive(Default)]
pub struct Pipeline {
    executor: Executor,
    root_prover: RootProver,
    agg_prover: AggProver,
    snark_prover: SnarkProver,
    single_node_prover: SingleNodeProver,
}

impl Pipeline {
    pub fn new(_base_dir: &str, keys_input_dir: &str) -> Self {
        Pipeline {
            executor: Executor::default(),
            root_prover: RootProver::default(),
            agg_prover: AggProver::default(),
            snark_prover: SnarkProver::new(keys_input_dir),
            single_node_prover: SingleNodeProver::new(keys_input_dir),
        }
    }

    pub fn split(&self, split_context: &SplitContext) -> Result<(bool, u64, u32), String> {
        self.executor
            .split(split_context)
            .map(|(step, segments)| (true, step, segments))
            .map_err(|e| {
                tracing::error!("split error {:#?}", e);
                e.to_string()
            })
    }

    pub fn prove_root(&self, prove_context: &ProveContext) -> Result<(bool, Vec<u8>), String> {
        self.root_prover
            .prove(prove_context)
            .map(|receipt_output| (true, receipt_output))
            .map_err(|e| {
                tracing::error!("prove_root error {:#?}", e);
                e.to_string()
            })
    }

    pub fn prove_aggregate(&self, agg_context: &AggContext) -> Result<(bool, Vec<u8>), String> {
        self.agg_prover
            .prove(agg_context)
            .map(|agg_receipt_output| (true, agg_receipt_output))
            .map_err(|e| {
                tracing::error!("prove_aggregate error {:#?}", e);
                e.to_string()
            })
    }

    pub fn prove_snark(&self, snark_context: &SnarkContext) -> Result<(bool, Vec<u8>), String> {
        self.snark_prover.prove(snark_context).map_err(|e| {
            tracing::error!("prove_snark error {:#?}", e);
            e.to_string()
        })
    }

    pub fn prove_single_node(&self, single_node_context: &SingleNodeContext) -> Result<(bool, Vec<u8>), String> {
        self.single_node_prover
            .prove(single_node_context)
            .map(|output| (true, output))
            .map_err(|e| {
                tracing::error!("prove_single_node error {:#?}", e);
                e.to_string()
            })
    }
}
