use crate::contexts::SnarkContext;
use crate::{get_prover, NetworkProve, WRAP_KEYS};
use std::path::PathBuf;
use tracing::instrument;
use zkm_core_executor::ZKMReduceProof;
use zkm_prover::{InnerSC, OuterSC, ZKMProver, ZKMRecursionProverError};
use zkm_recursion_circuit::machine::ZKMCompressWitnessValues;
use zkm_recursion_circuit::witness::Witnessable;
use zkm_recursion_compiler::config::InnerConfig;
use zkm_recursion_core::Runtime;
use zkm_sdk::ZKMProof;
use zkm_stark::koala_bear_poseidon2::KoalaBearPoseidon2;
use zkm_stark::{
    Challenge, MachineProver, StarkGenericConfig, StarkVerifyingKey, Val, ZKMProverOpts,
};

// It seems we don't need `output_dir`.
#[derive(Default)]
pub struct SnarkProver {
    proving_key_paths: String,
}

impl SnarkProver {
    pub fn new(proving_key_paths: &str) -> Self {
        Self {
            proving_key_paths: proving_key_paths.into(),
        }
    }
    pub fn prove(&self, ctx: &SnarkContext) -> anyhow::Result<(bool, Vec<u8>)> {
        let reduced_proof = if ctx.from_input {
            let receipt: (
                ZKMReduceProof<KoalaBearPoseidon2>,
                StarkVerifyingKey<KoalaBearPoseidon2>,
            ) = bincode::deserialize(&ctx.agg_receipt).map_err(|e| anyhow::anyhow!(e))?;

            receipt.0
        } else {
            let json_str = String::from_utf8_lossy(&ctx.agg_receipt).to_string();
            let proof: ZKMProof =
                serde_json::from_str(&json_str).expect("could not deserialize proof");
            match proof {
                ZKMProof::Compressed(proof) => *proof,
                _ => unreachable!("unexpected proof"),
            }
        };

        let network_prove = NetworkProve::default();
        let gnark_proof = self.prove_groth16(reduced_proof, network_prove.opts)?;

        Ok((true, serde_json::to_vec(&gnark_proof)?))
    }

    fn prove_groth16(
        &self,
        reduced_proof: ZKMReduceProof<InnerSC>,
        opts: ZKMProverOpts,
    ) -> Result<ZKMProof, ZKMRecursionProverError> {
        let prover = get_prover();
        let compress_proof = prover.shrink(reduced_proof, opts)?;
        let outer_proof = self.wrap_bn254(&prover, compress_proof, opts)?;

        let groth16_bn254_artifacts = PathBuf::from(&self.proving_key_paths);
        let proof = prover.wrap_groth16_bn254(outer_proof, &groth16_bn254_artifacts);

        Ok(ZKMProof::Groth16(proof))
    }

    #[instrument(name = "wrap_bn254", level = "info", skip_all)]
    fn wrap_bn254(
        &self,
        prover: &ZKMProver,
        compressed_proof: ZKMReduceProof<InnerSC>,
        opts: ZKMProverOpts,
    ) -> Result<ZKMReduceProof<OuterSC>, ZKMRecursionProverError> {
        let ZKMReduceProof {
            vk: compressed_vk,
            proof: compressed_proof,
        } = compressed_proof;
        let input = ZKMCompressWitnessValues {
            vks_and_proofs: vec![(compressed_vk, compressed_proof)],
            is_complete: true,
        };
        let input_with_vk = prover.make_merkle_proofs(input);

        let program = prover.wrap_program();

        // Run the compress program.
        let mut runtime = Runtime::<Val<InnerSC>, Challenge<InnerSC>, _>::new(
            program.clone(),
            prover.shrink_prover.config().perm.clone(),
        );

        let mut witness_stream = Vec::new();
        Witnessable::<InnerConfig>::write(&input_with_vk, &mut witness_stream);

        runtime.witness_stream = witness_stream.into();

        runtime
            .run()
            .map_err(|e| ZKMRecursionProverError::RuntimeError(e.to_string()))?;

        runtime.print_stats();
        tracing::debug!("wrap program executed successfully");

        // cache wrap_pk and wrap_vk
        let time = std::time::Instant::now();
        let (wrap_pk, wrap_vk) = WRAP_KEYS.get_or_init(|| {
            tracing::info_span!("setup wrap").in_scope(|| prover.wrap_prover.setup(&program))
        });
        let elapsed = time.elapsed();
        tracing::info!("setup wrap time: {:?}", elapsed);

        if prover.wrap_vk.set(wrap_vk.clone()).is_ok() {
            tracing::debug!("wrap verifier key set");
        }

        // Prove the wrap program.
        let mut wrap_challenger = prover.wrap_prover.config().challenger();
        let time = std::time::Instant::now();
        let mut wrap_proof = prover
            .wrap_prover
            .prove(
                wrap_pk,
                vec![runtime.record],
                &mut wrap_challenger,
                opts.recursion_opts,
            )
            .unwrap();
        let elapsed = time.elapsed();
        tracing::debug!("wrap proving time: {:?}", elapsed);
        let mut wrap_challenger = prover.wrap_prover.config().challenger();
        prover
            .wrap_prover
            .machine()
            .verify(wrap_vk, &wrap_proof, &mut wrap_challenger)
            .unwrap();
        tracing::info!("wrapping successful");

        Ok(ZKMReduceProof {
            vk: wrap_vk.clone(),
            proof: wrap_proof.shard_proofs.pop().unwrap(),
        })
    }
}
