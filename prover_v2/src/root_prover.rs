use crate::contexts::ProveContext;
use crate::rkyv_io::read_record_owned_mmap_rkyv;
use crate::{get_prover, NetworkProve, KEY_CACHE};
use zkm_stark::{MachineProver, MachineProvingKey, StarkGenericConfig};
use std::path::Path;

#[derive(Default)]
pub struct RootProver {}

impl RootProver {
    pub fn prove(&self, ctx: &ProveContext) -> anyhow::Result<Vec<u8>> {
        let mmap_start = std::time::Instant::now();
        let mut record =
            read_record_owned_mmap_rkyv(Path::new(&ctx.segment)).expect("mmap read failed");
        tracing::info!("mmap + deserialize record time: {:?}", mmap_start.elapsed());

        let now = std::time::Instant::now();
        let network_prove = NetworkProve::new(ctx.seg_size);
        tracing::info!("create network prove time: {:?}", now.elapsed());
        let opts = network_prove.opts.core_opts;
        let prover = get_prover();

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
