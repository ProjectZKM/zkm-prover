use crate::contexts::SingleNodeContext;
use crate::snark_prover::SnarkProver;
use crate::{get_prover, NetworkProve, KEY_CACHE, PROGRAM_CACHE};
use common::file;
use std::path::PathBuf;
use zkm_core_executor::ZKMReduceProof;
use zkm_prover::{ZKMProvingKey, ZKMVerifyingKey};
use zkm_sdk::network::prover::stage_service::Step;
use zkm_sdk::ZKMProof;
use zkm_stark::koala_bear_poseidon2::KoalaBearPoseidon2;
use zkm_stark::{MachineProver, StarkVerifyingKey};

#[derive(Default)]
pub struct SingleNodeProver {
    proving_key_paths: String,
}

impl SingleNodeProver {
    pub fn new(proving_key_paths: &str) -> Self {
        Self {
            proving_key_paths: proving_key_paths.into(),
        }
    }
    pub fn prove(&self, ctx: &SingleNodeContext) -> anyhow::Result<Vec<u8>> {
        let prover = get_prover();
        let mut network_prove = NetworkProve::new(ctx.seg_size);
        let opts = network_prove.opts;
        let context = network_prove.context_builder.build();

        let elf_path = ctx.elf_path.clone();
        let elf = file::new(&elf_path).read()?;

        // write input
        let encoded_input = file::new(&ctx.private_input_path).read()?;
        let inputs_data: Vec<Vec<u8>> = bincode::deserialize(&encoded_input)?;
        inputs_data.into_iter().for_each(|input| {
            network_prove.stdin.write_vec(input);
        });

        if !ctx.receipt_inputs_path.is_empty() {
            let receipt_datas = std::fs::read(&ctx.receipt_inputs_path)?;
            let receipts = bincode::deserialize::<Vec<Vec<u8>>>(&receipt_datas)?;
            for receipt in receipts.iter() {
                let receipt: (
                    ZKMReduceProof<KoalaBearPoseidon2>,
                    StarkVerifyingKey<KoalaBearPoseidon2>,
                ) = bincode::deserialize(receipt).map_err(|e| anyhow::anyhow!(e))?;
                network_prove.stdin.write_proof(receipt.0, receipt.1);
            }
            tracing::info!("Write {} receipts", receipts.len());
        }
        // get program from cache or generate new ones
        let mut program_cache = PROGRAM_CACHE.lock().unwrap();
        let program = if let Some(program) = program_cache.cache.get(&ctx.program_id) {
            tracing::info!("load program from cache");
            program
        } else {
            tracing::info!("No program in cache, generate new program");
            let program = prover
                .get_program(&elf)
                .map_err(|e| anyhow::Error::msg(e.to_string()))?;
            program_cache.push(ctx.program_id.clone(), program);
            program_cache.cache.get(&ctx.program_id).unwrap()
        };
        // get keys from cache or generate new ones
        let mut cache = KEY_CACHE.lock().unwrap();
        let (pk, vk) = if let Some((pk, vk)) = cache.cache.get(&ctx.program_id) {
            tracing::info!("load vk from cache");
            (pk, vk)
        } else {
            tracing::info!("No vk in cache, generate new keys");
            let (pk, vk) = prover.core_prover.setup(program);
            cache.push(ctx.program_id.clone(), (pk, vk));
            let (pk, vk) = &cache.cache.get(&ctx.program_id).unwrap();
            (pk, vk)
        };
        let vk_bytes = bincode::serialize(&vk)?;
        file::new(&format!("{}/vk.bin", ctx.base_dir)).write_all(&vk_bytes)?;
        let zkm_vk = ZKMVerifyingKey { vk: vk.clone() };
        let zkm_pk = ZKMProvingKey {
            pk: pk.clone(),
            elf,
            vk: zkm_vk.clone(),
        };
        let core_proof = prover.prove_core(&zkm_pk, &network_prove.stdin, opts, context)?;
        let deferred_proofs = network_prove
            .stdin
            .proofs
            .iter()
            .map(|(reduce_proof, _)| reduce_proof.clone())
            .collect();
        let public_values = core_proof.public_values.clone();
        // Generate the compressed proof.
        let reduced_proof = prover.compress(&zkm_vk, core_proof, deferred_proofs, opts)?;
        let proof = match Step::from_i32(ctx.target_step) {
            Some(Step::InAgg) => ZKMProof::Compressed(Box::new(reduced_proof)),
            Some(Step::InSnark) => {
                // generate snark proof
                tracing::info!("Generating snark proof for task: {}", ctx.program_id);
                let snark_prover = SnarkProver::new(&self.proving_key_paths);
                let compress_proof = prover.shrink(reduced_proof, opts)?;
                let outer_proof = snark_prover.wrap_bn254(&prover, compress_proof, opts)?;
                let groth16_bn254_artifacts = PathBuf::from(&self.proving_key_paths);
                let proof = prover.wrap_groth16_bn254(outer_proof, &groth16_bn254_artifacts);
                ZKMProof::Groth16(proof)
            }
            _ => {
                unreachable!("Unsupported target step: {}", ctx.target_step);
            }
        };
        let public_values_stream = public_values.to_vec();
        // write public values to file
        let public_values_path = format!("{}/wrap/public_values.bin", ctx.base_dir);
        file::new(&public_values_path).write_all(&public_values_stream)?;
        Ok(serde_json::to_string(&proof)?.into_bytes())
    }
}
