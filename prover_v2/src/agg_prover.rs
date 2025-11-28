use crate::contexts::AggContext;
use crate::{get_prover, NetworkProve, ProverComponents};
use zkm_core_executor::ZKMReduceProof;
use zkm_prover::build::Witnessable;
use zkm_prover::{InnerSC, ZKMCircuitWitness, ZKMProver, ZKMRecursionProverError};
use zkm_recursion_circuit::machine::{
    ZKMCompressWitnessValues, ZKMDeferredWitnessValues, ZKMRecursionWitnessValues,
};
use zkm_recursion_compiler::config::InnerConfig;
use zkm_recursion_core::Runtime;
use zkm_sdk::ZKMProof;
use zkm_stark::{Challenge, MachineProver, StarkGenericConfig, Val, ZKMCoreOpts};

#[cfg(feature = "gpu")]
use zkm_stark::MachineProvingKey;

#[cfg(feature = "gpu")]
use zkm_gpu_prover::GpuProverHandle;

#[derive(Default)]
pub struct AggProver {}

impl AggProver {
    pub fn prove(&self, ctx: &AggContext) -> anyhow::Result<Vec<u8>> {
        let prover = get_prover();
        self.prove_with_prover(0, &prover, ctx)
    }

    fn prove_with_prover(
        &self,
        idx: usize,
        prover: &ZKMProver<ProverComponents>,
        ctx: &AggContext,
    ) -> anyhow::Result<Vec<u8>> {
        tracing::info!(
            "GPU {} Aggregation job start: leaf_layer={} deferred={} proofs={} first_shard={}",
            idx,
            ctx.is_leaf_layer,
            ctx.is_deferred,
            ctx.proofs.len(),
            ctx.is_first_shard
        );
        let network_prove = NetworkProve::default();
        let input = if ctx.is_leaf_layer {
            if !ctx.is_deferred {
                tracing::info!("GPU {idx} Aggregation job building core witness");
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
                tracing::info!("GPU {idx} Aggregation job using deferred witness");
                let deferred_witness: ZKMDeferredWitnessValues<_> =
                    bincode::deserialize(&ctx.proofs[0])?;
                ZKMCircuitWitness::Deferred(deferred_witness)
            }
        } else {
            tracing::info!("GPU {idx} Aggregation job building compress witness");
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

        tracing::info!("GPU {idx} Aggregation job entering recursive compression");
        let reduced_proof = self.compress(prover, input, network_prove.opts.recursion_opts)?;
        tracing::info!("GPU {idx} Aggregation job finished recursive compression");

        Ok(serde_json::to_string(&reduced_proof)?.into_bytes())
    }

    #[cfg(feature = "gpu")]
    pub fn prove_with_gpu_handle(
        &self,
        idx: usize,
        handle: &GpuProverHandle,
        ctx: &AggContext,
    ) -> anyhow::Result<Vec<u8>> {
        handle
            .with_prover(|prover| self.prove_with_prover(idx, prover, ctx))
            .map_err(|err| anyhow::anyhow!("failed to execute agg proof on GPU: {err}"))?
    }

    fn compress(
        &self,
        prover: &ZKMProver<ProverComponents>,
        input: ZKMCircuitWitness,
        recursion_opts: ZKMCoreOpts,
    ) -> anyhow::Result<ZKMProof> {
        // Get the program and witness stream.
        tracing::info!("Agg compress: building program and witness stream");
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
        tracing::info!("Agg compress: executing runtime");
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
        tracing::info!("Agg compress: generating dependencies");
        let mut records = vec![record];
        tracing::debug_span!("generate dependencies").in_scope(|| {
            prover.compress_prover.machine().generate_dependencies(
                &mut records,
                &recursion_opts,
                None,
            )
        });

        // Generate the traces.
        tracing::info!("Agg compress: generating traces");
        let record = records.into_iter().next().unwrap();
        let traces = tracing::debug_span!("generate traces")
            .in_scope(|| prover.compress_prover.generate_traces(&record));

        let (vk, proof) = tracing::debug_span!("batch").in_scope(|| {
            tracing::info!("Agg compress: setting up keys");
            // Get the keys.
            let (pk, vk) = tracing::debug_span!("Setup compress program")
                .in_scope(|| prover.compress_prover.setup(&program));

            // Observe the proving key.
            tracing::info!("Agg compress: observing proving key");
            let mut challenger = prover.compress_prover.config().challenger();
            tracing::debug_span!("observe proving key").in_scope(|| {
                pk.observe_into(&mut challenger);
            });

            // Commit to the record and traces.
            tracing::info!("Agg compress: committing");
            let data = tracing::debug_span!("commit")
                .in_scope(|| prover.compress_prover.commit(&record, traces));

            // Generate the proof.
            tracing::info!("Agg compress: opening proof");
            let proof = tracing::debug_span!("open").in_scope(|| {
                prover
                    .compress_prover
                    .open(&pk, data, &mut challenger)
                    .unwrap()
            });

            // Verify the proof.
            #[cfg(feature = "debug")]
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
                .unwrap();

            tracing::info!("Agg compress: proof ready");
            (vk, proof)
        });

        Ok(ZKMProof::Compressed(Box::new(ZKMReduceProof { vk, proof })))
    }
}
