use crate::contexts::ProveContext;
use crate::{get_prover, NetworkProve, ProverComponents, Segment, KEY_CACHE, PROGRAM_CACHE};
use common::file;
use zkm_core_machine::utils::trace_checkpoint;
use zkm_prover::CoreSC;
use zkm_stark::{MachineProver, StarkGenericConfig};

#[cfg(feature = "gpu")]
use zkm_stark::MachineProvingKey;

#[cfg(feature = "gpu")]
use zkm_gpu_core::cuda_runtime;

#[cfg(feature = "gpu")]
use zkm_gpu_prover::GpuProverHandle;
use zkm_prover::ZKMProver;

#[derive(Default)]
pub struct RootProver {}

impl RootProver {
    pub fn prove(&self, ctx: &ProveContext) -> anyhow::Result<Vec<u8>> {
        let segment = Self::prepare_segment(ctx)?;
        let prover = get_prover();
        self.prove_with_prover(0, &prover, ctx, segment)
    }

    pub fn prove_from_segment(
        &self,
        ctx: &ProveContext,
        segment: Segment,
    ) -> anyhow::Result<Vec<u8>> {
        let prover = get_prover();
        self.prove_with_prover(0, &prover, ctx, segment)
    }

    fn prepare_segment(ctx: &ProveContext) -> anyhow::Result<Segment> {
        if !ctx.segment_bytes.is_empty() {
            Self::decode_segment(&ctx.segment_bytes)
        } else {
            Self::read_segment_from_file(&ctx.segment)
        }
    }

    fn prove_with_prover(
        &self,
        idx: usize,
        prover: &ZKMProver<ProverComponents>,
        ctx: &ProveContext,
        segment: Segment,
    ) -> anyhow::Result<Vec<u8>> {
        tracing::info!("use GPU {idx} to prove");
        let network_prove = NetworkProve::new(ctx.seg_size);
        let opts = network_prove.opts.core_opts;

        let mut record = match segment {
            Segment::State(state) => {
                let mut program_cache = PROGRAM_CACHE.lock();
                let program = if let Some(program) = program_cache.cache.get(&ctx.program_id) {
                    tracing::info!("load program from cache");
                    program
                } else {
                    tracing::info!("No program in cache, generate new program");
                    let elf = if !ctx.elf.is_empty() {
                        ctx.elf.clone()
                    } else {
                        file::new(&ctx.elf_path).read()?
                    };
                    let program = prover
                        .get_program(&elf)
                        .map_err(|e| anyhow::Error::msg(e.to_string()))?;
                    program_cache.push(ctx.program_id.clone(), program);
                    program_cache.cache.get(&ctx.program_id).unwrap()
                };
                let public_values = state.public_values;
                let (records, _) = tracing::debug_span!("trace checkpoint").in_scope(|| {
                    trace_checkpoint::<CoreSC>(
                        program.clone(),
                        state.state,
                        opts,
                        prover.core_shape_config.as_ref(),
                    )
                });
                let mut record = records.into_iter().next().unwrap();
                let _ = record.defer();
                record.public_values = public_values;
                record
            }
            Segment::Record(record) => *record,
        };

        tracing::info!("record loaded");
        let now = std::time::Instant::now();
        let mut cache = KEY_CACHE.lock();
        tracing::info!("get key cache");
        let device_id = idx as u32;
        let (pk, _) = loop {
            if let Some((pk, vk)) = cache.get(device_id, &ctx.program_id) {
                break (pk, vk);
            }
            let (pk, vk) = prover.core_prover.setup(&record.program);
            cache.push(device_id, ctx.program_id.clone(), (pk, vk));
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

        tracing::info!("use GPU {idx} end");

        Ok(bincode::serialize(&proof)?)
    }

    #[cfg(feature = "gpu")]
    pub fn prove_with_gpu_handle(
        &self,
        idx: usize,
        handle: &GpuProverHandle,
        ctx: &ProveContext,
    ) -> anyhow::Result<Vec<u8>> {
        let segment = Self::prepare_segment(ctx)?;
        let proof = handle
            .with_prover(|prover| self.prove_with_prover(idx, prover, ctx, segment))
            .map_err(|err| anyhow::anyhow!("failed to execute root proof on GPU: {err}"))??;
        cuda_runtime::sync_device().map_err(|err| {
            anyhow::anyhow!("failed to synchronize GPU {idx} after root prove: {err}")
        })?;
        Ok(proof)
    }

    fn decode_segment(bytes: &[u8]) -> anyhow::Result<Segment> {
        let decoded = zstd::stream::decode_all(bytes)
            .map_err(|e| anyhow::anyhow!("zstd decode failed: {e}"))?;
        Ok(bincode::deserialize::<Segment>(&decoded)
            .map_err(|e| anyhow::anyhow!("segment deserialize failed: {e}"))?)
    }

    fn read_segment_from_file(path: &str) -> anyhow::Result<Segment> {
        let now = std::time::Instant::now();
        let mut retries = 0;
        const MAX_RETRIES: usize = 10;

        loop {
            let result = std::fs::read(path)
                .and_then(|segment| {
                    zstd::stream::decode_all(&*segment)
                        .map_err(|e| std::io::Error::other(format!("zstd decode failed: {e}")))
                })
                .and_then(|decoded| {
                    bincode::deserialize::<Segment>(&decoded).map_err(|e| {
                        std::io::Error::new(
                            std::io::ErrorKind::InvalidData,
                            format!("deserialize failed: {e}"),
                        )
                    })
                });

            match result {
                Ok(r) => {
                    tracing::info!("read segment time: {:?}", now.elapsed());
                    break Ok(r);
                }
                Err(e) => {
                    if retries >= MAX_RETRIES {
                        break Err(anyhow::anyhow!(
                            "Segment read/decode failed after {} retries: {}",
                            MAX_RETRIES,
                            e
                        ));
                    }
                    tracing::warn!("Segment {:?} error: {}, retrying...", path, e);
                    retries += 1;
                    std::thread::sleep(std::time::Duration::from_millis(300));
                }
            }
        }
    }
}
