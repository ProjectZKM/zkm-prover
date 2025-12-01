use crate::contexts::AggContext;
use crate::{get_prover, NetworkProve, ProverComponents};
use serde::{Deserialize, Serialize};
use zkm_core_executor::ZKMReduceProof;
use zkm_core_machine::utils::setup_logger;
use zkm_prover::build::Witnessable;
use zkm_prover::{InnerSC, ZKMCircuitWitness, ZKMProver, ZKMRecursionProverError};
use zkm_recursion_circuit::machine::{
    ZKMCompressWitnessValues, ZKMDeferredWitnessValues, ZKMRecursionWitnessValues,
};
use zkm_recursion_compiler::config::InnerConfig;
use zkm_recursion_core::Runtime;
use zkm_sdk::ZKMProof;
use zkm_stark::{
    Challenge, MachineProver, MachineProvingKey, StarkGenericConfig, Val, ZKMCoreOpts,
};

#[derive(Default)]
pub struct AggProver {}

impl AggProver {
    pub fn prove(&self, ctx: &AggContext) -> anyhow::Result<Vec<u8>> {
        tracing::info!(
            "Starting aggregation proving for agg_index {}",
            ctx.agg_index
        );
        if ctx.agg_index == 9 {
            // encode ctx and save to debug file
            let debug_file_bytes = bincode::serialize(ctx)?;
            std::fs::write(
                &format!("agg_{:?}_input.bin", ctx.agg_index),
                &debug_file_bytes,
            )?;
        }
        let network_prove = NetworkProve::default();
        let prover = get_prover();
        let input = if ctx.is_leaf_layer {
            if !ctx.is_deferred {
                let shard_proofs = ctx
                    .proofs
                    .iter()
                    .map(|proof| bincode::deserialize(proof).unwrap())
                    .collect();
                let vk = bincode::deserialize(&ctx.vk)?;
                ZKMCircuitWitness::Core(ZKMRecursionWitnessValues {
                    vk,
                    shard_proofs,
                    is_complete: ctx.is_complete,
                    is_first_shard: ctx.is_first_shard,
                    vk_root: prover.recursion_vk_root,
                })
            } else {
                let deferred_witness: ZKMDeferredWitnessValues<_> =
                    bincode::deserialize(&ctx.proofs[0])?;
                ZKMCircuitWitness::Deferred(deferred_witness)
            }
        } else {
            let reduced_proofs: Vec<ZKMReduceProof<_>> = ctx
                .proofs
                .iter()
                .map(|vk_and_proof| {
                    let json_str = String::from_utf8_lossy(vk_and_proof).to_string();
                    let proof: ZKMProof =
                        serde_json::from_str(&json_str).expect("could not deserialize proof");
                    match proof {
                        ZKMProof::Compressed(proof) => *proof,
                        _ => unreachable!("unexpected proof"),
                    }
                })
                .collect();

            ZKMCircuitWitness::Compress(ZKMCompressWitnessValues {
                vks_and_proofs: reduced_proofs
                    .into_iter()
                    .map(|proof| (proof.vk, proof.proof))
                    .collect(),
                is_complete: ctx.is_complete,
            })
        };

        let reduced_proof = self.compress(
            ctx.agg_index,
            &prover,
            input,
            network_prove.opts.recursion_opts,
        )?;

        Ok(serde_json::to_string(&reduced_proof)?.into_bytes())
    }

    fn compress(
        &self,
        agg_index: u32,
        prover: &ZKMProver<ProverComponents>,
        input: ZKMCircuitWitness,
        recursion_opts: ZKMCoreOpts,
    ) -> anyhow::Result<ZKMProof> {
        // Get the program and witness stream.
        let (program, witness_stream) = tracing::debug_span!("get program and witness stream")
            .in_scope(|| match input {
                ZKMCircuitWitness::Core(input) => {
                    let mut witness_stream = Vec::new();
                    Witnessable::<InnerConfig>::write(&input, &mut witness_stream);
                    (prover.recursion_program(&input), witness_stream)
                }
                ZKMCircuitWitness::Deferred(input) => {
                    let mut witness_stream = Vec::new();
                    Witnessable::<InnerConfig>::write(&input, &mut witness_stream);
                    (prover.deferred_program(&input), witness_stream)
                }
                ZKMCircuitWitness::Compress(input) => {
                    let mut witness_stream = Vec::new();

                    let input_with_merkle = prover.make_merkle_proofs(input);

                    Witnessable::<InnerConfig>::write(&input_with_merkle, &mut witness_stream);

                    (prover.compress_program(&input_with_merkle), witness_stream)
                }
            });

        // Execute the runtime.
        let record = tracing::debug_span!("execute runtime").in_scope(|| {
            let mut runtime = Runtime::<Val<InnerSC>, Challenge<InnerSC>, _>::new(
                program.clone(),
                prover.compress_prover.config().perm.clone(),
            );
            runtime.witness_stream = witness_stream.into();
            runtime
                .run()
                .map(|_| runtime.record)
                .map_err(|e| ZKMRecursionProverError::RuntimeError(e.to_string()))
        })?;

        // Generate the dependencies.
        let mut records = vec![record];
        tracing::debug_span!("generate dependencies").in_scope(|| {
            prover.compress_prover.machine().generate_dependencies(
                &mut records,
                &recursion_opts,
                None,
            )
        });

        // Generate the traces.
        let record = records.into_iter().next().unwrap();
        let traces = tracing::debug_span!("generate traces")
            .in_scope(|| prover.compress_prover.generate_traces(&record));

        let (vk, proof) = tracing::debug_span!("batch").in_scope(|| {
            // Get the keys.
            let (pk, vk) = tracing::debug_span!("Setup compress program")
                .in_scope(|| prover.compress_prover.setup(&program));

            // Observe the proving key.
            let mut challenger = prover.compress_prover.config().challenger();
            tracing::debug_span!("observe proving key").in_scope(|| {
                pk.observe_into(&mut challenger);
            });
            #[cfg(feature = "debug")]
            prover.compress_prover.debug_constraints(
                &prover.compress_prover.pk_to_host(&pk),
                vec![record.clone()],
                &mut challenger.clone(),
            );

            // Commit to the record and traces.
            let data = tracing::debug_span!("commit")
                .in_scope(|| prover.compress_prover.commit(&record, traces));

            // Generate the proof.
            let proof = tracing::debug_span!("open").in_scope(|| {
                prover
                    .compress_prover
                    .open(&pk, data, &mut challenger)
                    .unwrap()
            });

            if agg_index == 9 {
                tracing::info!("final_poly {:?}", proof.opening_proof.final_poly);
            }

            // Verify the proof.
            #[cfg(feature = "debug")]
            {
                prover
                    .compress_prover
                    .machine()
                    .verify(
                        &vk,
                        &zkm_stark::MachineProof {
                            shard_proofs: vec![proof.clone()],
                        },
                        &mut prover.compress_prover.config().challenger(),
                    )
                    .expect("debug verification failed");
                tracing::info!("debug verification passed");
            }

            (vk, proof)
        });

        Ok(ZKMProof::Compressed(Box::new(ZKMReduceProof { vk, proof })))
    }
}

#[test]
fn test_agg() {
    setup_logger();

    // This is an example of how to read a debug file and deserialize it back into an AggContext.

    // 1. Specify the task_id of the file you want to debug.
    //    This should match the filename of the file saved previously.
    let task_id_to_debug = "../2112f388-f673-4e42-a46c-83076541d600-agg_9_input.bin";

    let file_path = std::path::Path::new(task_id_to_debug);

    if !file_path.exists() {
        tracing::warn!(
            "Debug file '{}' not found, skipping test.",
            task_id_to_debug
        );
        return;
    }

    // 2. Read the entire file content into a byte vector.
    let file_bytes = std::fs::read(file_path)
        .unwrap_or_else(|e| panic!("Failed to read debug file '{}': {}", task_id_to_debug, e));

    // 3. Deserialize the bytes back into an AggContext object.
    let ctx: AggContext = bincode::deserialize(&file_bytes)
        .unwrap_or_else(|e| panic!("Failed to deserialize AggContext from file: {}", e));
    tracing::info!("agg_index = {:?}", ctx.agg_index);

    for _ in 0..2 {
        let agg_prover = AggProver::default();
        let result = agg_prover.prove(&ctx);
        assert!(result.is_ok());
    }
}
