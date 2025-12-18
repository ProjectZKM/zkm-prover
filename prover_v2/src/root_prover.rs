use crate::contexts::ProveContext;
use crate::{get_prover, CheckpointPacket, NetworkProve, KEY_CACHE, PROGRAM_CACHE};
use common::file;
use zkm_core_machine::utils::trace_checkpoint;
use zkm_prover::CoreSC;
use zkm_stark::{MachineProver, MachineProvingKey, MachineRecord, StarkGenericConfig};

#[derive(Default)]
pub struct RootProver {}

impl RootProver {
    pub fn prove(&self, ctx: &ProveContext) -> anyhow::Result<Vec<u8>> {
        let now = std::time::Instant::now();
        let checkpoint_packet = bincode::deserialize::<CheckpointPacket>(&ctx.segment)
            .map_err(|e| anyhow::anyhow!("deserialize checkpoint packet failed: {e}"))?;
        tracing::info!("read checkpoint packet time: {:?}", now.elapsed());

        let network_prove = NetworkProve::new(ctx.seg_size);
        let opts = network_prove.opts.core_opts;
        let prover = get_prover();

        let mut program_cache = PROGRAM_CACHE.lock();
        let program = if let Some(program) = program_cache.cache.get(&ctx.program_id) {
            tracing::info!("load program from cache");
            program
        } else {
            tracing::info!("No program in cache, generate new program");
            let elf = file::new(&ctx.elf_path).read()?;
            let program = prover
                .get_program(&elf)
                .map_err(|e| anyhow::Error::msg(e.to_string()))?;
            program_cache.push(ctx.program_id.clone(), program);
            program_cache.cache.get(&ctx.program_id).unwrap()
        };

        let checkpoint_state = bincode::deserialize::<zkm_core_executor::ExecutionState>(
            &checkpoint_packet.checkpoint,
        )
        .map_err(|e| anyhow::anyhow!("deserialize checkpoint failed: {e}"))?;

        let now = std::time::Instant::now();
        let (mut records, _) = tracing::debug_span!("trace checkpoint").in_scope(|| {
            trace_checkpoint::<CoreSC>(
                program.clone(),
                checkpoint_state,
                opts,
                prover.core_shape_config.as_ref(),
            )
        });
        tracing::info!("trace checkpoint time: {:?}", now.elapsed());

        let expected_record_count = checkpoint_packet.record_count() as usize;
        let mut deferred = zkm_core_executor::ExecutionRecord::new(program.clone().into());
        for record in records.iter_mut() {
            deferred.append(&mut record.defer());
        }
        let mut deferred_records = deferred.split(checkpoint_packet.done, None, opts.split_opts);
        records.append(&mut deferred_records);

        if records.len() != expected_record_count {
            return Err(anyhow::anyhow!(
                "record count mismatch: expected={}, actual={}",
                expected_record_count,
                records.len()
            ));
        }
        let mut record = records
            .into_iter()
            .nth(ctx.index)
            .ok_or_else(|| anyhow::anyhow!("record index out of bounds: {}", ctx.index))?;

        let now = std::time::Instant::now();
        let mut cache = KEY_CACHE.lock();
        let pk = if let Some((pk, _)) = cache.cache.get(&ctx.program_id) {
            pk
        } else {
            let (pk, vk) = prover.core_prover.setup(&record.program);
            cache.push(ctx.program_id.clone(), (pk, vk));
            &cache.cache.get(&ctx.program_id).unwrap().0
        };
        tracing::info!("setup time: {:?}", now.elapsed());
        let now = std::time::Instant::now();
        prover.core_prover.machine().generate_dependencies(
            std::slice::from_mut(&mut record),
            &opts,
            None,
        );
        tracing::info!("generate dependencies time: {:?}", now.elapsed());

        // Fix the shape of the record.
        let now = std::time::Instant::now();
        if let Some(shape_config) = &prover.core_shape_config {
            shape_config.fix_shape(&mut record)?;
        }
        tracing::info!("fix shape time: {:?}", now.elapsed());
        let now = std::time::Instant::now();
        let main_trace = prover.core_prover.generate_traces(&record);
        tracing::info!("generate traces time: {:?}", now.elapsed());

        let mut challenger = prover.core_prover.config().challenger();
        pk.observe_into(&mut challenger);
        let now = std::time::Instant::now();
        let main_data = prover.core_prover.commit(&record, main_trace);
        tracing::info!("commit time: {:?}", now.elapsed());
        let now = std::time::Instant::now();
        let proof = prover.core_prover.open(pk, main_data, &mut challenger)?;
        tracing::info!("open time: {:?}", now.elapsed());

        Ok(bincode::serialize(&proof)?)
    }
}
