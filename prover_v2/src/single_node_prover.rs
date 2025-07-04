use crate::contexts::SingleNodeContext;
use crate::{CLIENT_CACHE, KEY_CACHE};
use common::file;
use zkm_core_executor::ZKMReduceProof;
use zkm_core_machine::io::ZKMStdin;
use zkm_prover::{ZKMProvingKey, ZKMVerifyingKey};
use zkm_sdk::network::prover::stage_service::Step;
use zkm_stark::koala_bear_poseidon2::KoalaBearPoseidon2;
use zkm_stark::StarkVerifyingKey;

#[derive(Default)]
pub struct SingleNodeProver {}

impl SingleNodeProver {
    pub fn prove(&self, ctx: &SingleNodeContext) -> anyhow::Result<Vec<u8>> {
        let mut stdin = ZKMStdin::new();
        let client = CLIENT_CACHE.clone();
        let elf_path = ctx.elf_path.clone();
        let elf = file::new(&elf_path).read()?;

        // write input
        let encoded_input = file::new(&ctx.private_input_path).read()?;
        let inputs_data: Vec<Vec<u8>> = bincode::deserialize(&encoded_input)?;
        inputs_data.into_iter().for_each(|input| {
            stdin.write_vec(input);
        });

        if !ctx.receipt_inputs_path.is_empty() {
            let receipt_datas = std::fs::read(&ctx.receipt_inputs_path)?;
            let receipts = bincode::deserialize::<Vec<Vec<u8>>>(&receipt_datas)?;
            for receipt in receipts.iter() {
                let receipt: (
                    ZKMReduceProof<KoalaBearPoseidon2>,
                    StarkVerifyingKey<KoalaBearPoseidon2>,
                ) = bincode::deserialize(receipt).map_err(|e| anyhow::anyhow!(e))?;
                stdin.write_proof(receipt.0, receipt.1);
            }
            tracing::info!("Write {} receipts", receipts.len());
        }

        let mut cache = KEY_CACHE.lock().unwrap();
        let (pk, vk) = if let Some((pk, vk)) = cache.cache.get(&ctx.program_id) {
            tracing::info!("load (pk, vk) from cache");
            (pk, vk)
        } else {
            tracing::info!("No (pk, vk) in cache, generate new keys");
            let (pk, vk) = client.setup(&elf);
            cache.push(ctx.program_id.clone(), (pk.pk, vk.vk));
            let (pk, vk) = &cache.cache.get(&ctx.program_id).unwrap();
            (pk, vk)
        };
        let zkm_vk = ZKMVerifyingKey { vk: vk.clone() };
        let zkm_pk = ZKMProvingKey {
            pk: pk.clone(),
            elf,
            vk: zkm_vk,
        };
        let proof = match Step::from_i32(ctx.target_step) {
            Some(Step::InAgg) => {
                tracing::info!("Singe node: generate Compressed proof");
                client.prove(&zkm_pk, stdin).compressed().run()?
            }
            Some(Step::InSnark) => {
                tracing::info!("Singe node: generate Snark proof");
                client.prove(&zkm_pk, stdin).groth16().run()?
            }
            _ => {
                unreachable!("Unsupported target step: {}", ctx.target_step);
            }
        };
        let reduced_proof = proof.proof;
        let public_values_stream = proof.public_values.to_vec();
        // write public values to file
        let public_values_path = format!("{}/wrap/public_values.bin", ctx.base_dir);
        file::new(&public_values_path).write_all(&public_values_stream)?;
        Ok(serde_json::to_string(&reduced_proof)?.into_bytes())
    }
}
