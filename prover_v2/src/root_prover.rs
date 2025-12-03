use crate::contexts::ProveContext;
use crate::{get_prover, NetworkProve, ProverComponents, KEY_CACHE};
use zkm_core_executor::ExecutionRecord;
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
        segment: ExecutionRecord,
    ) -> anyhow::Result<Vec<u8>> {
        let prover = get_prover();
        self.prove_with_prover(0, &prover, ctx, segment)
    }

    fn prepare_segment(ctx: &ProveContext) -> anyhow::Result<ExecutionRecord> {
        if let Some(segment) = ctx.segment_obj.clone() {
            Ok(segment)
        } else if !ctx.segment_bytes.is_empty() {
            Self::decode_record(&ctx.segment_bytes)
        } else {
            Self::read_record_from_file(&ctx.segment)
        }
    }

    fn prove_with_prover(
        &self,
        idx: usize,
        prover: &ZKMProver<ProverComponents>,
        ctx: &ProveContext,
        mut record: ExecutionRecord,
    ) -> anyhow::Result<Vec<u8>> {
        let segment_index = ctx.index;
        tracing::info!("GPU {idx} starting root proof for segment {segment_index}");
        let network_prove = NetworkProve::new(ctx.seg_size);
        let opts = network_prove.opts.core_opts;

        tracing::info!("GPU {idx} segment {segment_index}: record loaded");
        let now = std::time::Instant::now();
        let device_id = idx as u32;
        let entry = {
            let mut cache = KEY_CACHE.lock();
            cache.entry(device_id, ctx.program_id.clone())
        };
        tracing::info!("GPU {idx} segment {segment_index}: acquiring key cache entry");
        let (pk, _) = entry.get_or_init_with(|| {
            tracing::info!("GPU {idx} segment {segment_index}: running setup");
            prover.core_prover.setup(&record.program)
        });
        tracing::info!("GPU {idx} setup time: {:?}", now.elapsed());
        let now = std::time::Instant::now();
        tracing::info!("GPU {idx} segment {segment_index}: generating dependencies");
        prover.core_prover.machine().generate_dependencies(
            std::slice::from_mut(&mut record),
            &opts,
            None,
        );
        tracing::info!("GPU {idx} generate dependencies time: {:?}", now.elapsed());

        // Fix the shape of the record.
        let now = std::time::Instant::now();
        if let Some(shape_config) = &prover.core_shape_config {
            tracing::info!("GPU {idx} segment {segment_index}: fixing shape");
            shape_config.fix_shape(&mut record)?;
        }
        tracing::info!("GPU {idx} fix shape time: {:?}", now.elapsed());
        let now = std::time::Instant::now();
        tracing::info!("GPU {idx} segment {segment_index}: generating traces");
        let main_trace = prover.core_prover.generate_traces(&record);
        tracing::info!("GPU {idx} generate traces time: {:?}", now.elapsed());

        let mut challenger = prover.core_prover.config().challenger();
        pk.observe_into(&mut challenger);
        let now = std::time::Instant::now();
        tracing::info!("GPU {idx} segment {segment_index}: committing main trace");
        let main_data = prover.core_prover.commit(&record, main_trace);
        tracing::info!("GPU {idx} commit time: {:?}", now.elapsed());
        let now = std::time::Instant::now();
        tracing::info!("GPU {idx} segment {segment_index}: opening proof");
        let proof = prover.core_prover.open(pk, main_data, &mut challenger)?;
        tracing::info!("GPU {idx} open time: {:?}", now.elapsed());

        tracing::info!("GPU {idx} finished segment {segment_index}");

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

        Ok(proof)
    }

    fn decode_record(bytes: &[u8]) -> anyhow::Result<ExecutionRecord> {
        let decoded = zstd::stream::decode_all(bytes)
            .map_err(|e| anyhow::anyhow!("zstd decode failed: {e}"))?;
        Ok(bincode::deserialize::<ExecutionRecord>(&decoded)
            .map_err(|e| anyhow::anyhow!("segment deserialize failed: {e}"))?)
    }

    fn read_record_from_file(path: &str) -> anyhow::Result<ExecutionRecord> {
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
                    bincode::deserialize::<ExecutionRecord>(&decoded).map_err(|e| {
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
