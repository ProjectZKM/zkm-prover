#![cfg_attr(
    not(feature = "gpu"),
    allow(unused_imports, dead_code, unused_variables)
)]

use crate::contexts::{AggContext, ProveContext, SingleNodeContext, SnarkContext, SplitContext};
use crate::executor::Executor;
#[cfg(feature = "gpu")]
use crate::gpu_scheduler::{GpuJobDispatcher, GpuJobPool};
use crate::snark_prover::SnarkProver;
use crate::{get_prover, NetworkProve, FIRST_LAYER_BATCH_SIZE, KEY_CACHE, PROGRAM_CACHE};
use anyhow::{anyhow, Context};
use common::file;
use std::cmp;
use std::collections::{BTreeMap, VecDeque};
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{mpsc, Arc, OnceLock};
use zkm_core_executor::ZKMReduceProof;
#[cfg(feature = "gpu")]
use zkm_gpu_prover::MultiGpuProver;
use zkm_prover::ZKMVerifyingKey;
use zkm_sdk::network::prover::stage_service::Step;
use zkm_sdk::ZKMProof;
use zkm_stark::koala_bear_poseidon2::KoalaBearPoseidon2;
use zkm_stark::{MachineProver, StarkVerifyingKey};

#[cfg(feature = "gpu")]
struct AggregatorConfig {
    total_segments: usize,
    deferred_inputs: Vec<(usize, Vec<u8>)>,
    vk_bytes: Vec<u8>,
}

#[cfg(feature = "gpu")]
struct UpperLayerState {
    expected_inputs: usize,
    processed_inputs: usize,
    chunk_count: usize,
    buffer: BTreeMap<usize, Vec<u8>>,
}

#[cfg(feature = "gpu")]
impl UpperLayerState {
    fn new(expected_inputs: usize) -> Self {
        let chunk_count = if expected_inputs == 0 {
            0
        } else {
            (expected_inputs + 1) / 2
        };
        Self {
            expected_inputs,
            processed_inputs: 0,
            chunk_count,
            buffer: BTreeMap::new(),
        }
    }
}

#[cfg(feature = "gpu")]
struct StreamingAggregator {
    vk_bytes: Vec<u8>,
    is_complete: bool,
    first_layer_expected: usize,
    produced_first_layer: usize,
    first_shard_emitted: bool,
    upper_layers: Vec<UpperLayerState>,
    final_result: Option<Vec<u8>>,
    next_job_id: u64,
    pending_jobs: BTreeMap<u64, (usize, usize)>,
}

#[cfg(feature = "gpu")]
impl StreamingAggregator {
    fn new(vk_bytes: Vec<u8>, total_segments: usize, deferred_len: usize) -> Self {
        let first_layer_batch_size = cmp::max(FIRST_LAYER_BATCH_SIZE, 1);
        let chunk_ranges = (total_segments + first_layer_batch_size - 1) / first_layer_batch_size;

        let first_layer_expected = chunk_ranges + deferred_len;
        let mut upper_layers = Vec::new();
        let mut remaining = first_layer_expected;
        while remaining > 1 {
            upper_layers.push(UpperLayerState::new(remaining));
            remaining = (remaining + 1) / 2;
        }

        Self {
            vk_bytes,
            is_complete: total_segments == 1 && deferred_len == 0,
            first_layer_expected,
            produced_first_layer: 0,
            first_shard_emitted: false,
            upper_layers,
            final_result: None,
            next_job_id: 0,
            pending_jobs: BTreeMap::new(),
        }
    }

    fn push_normal_chunk(
        &mut self,
        proofs: Vec<Vec<u8>>,
        is_first_chunk: bool,
        output_index: usize,
    ) -> anyhow::Result<Vec<AggJobRequest>> {
        self.push_first_layer(proofs, is_first_chunk, false, output_index)
    }

    fn push_deferred(
        &mut self,
        proof: Vec<u8>,
        output_index: usize,
    ) -> anyhow::Result<Vec<AggJobRequest>> {
        self.push_first_layer(vec![proof], false, true, output_index)
    }

    fn push_first_layer(
        &mut self,
        proofs: Vec<Vec<u8>>,
        mark_first_chunk: bool,
        is_deferred: bool,
        output_index: usize,
    ) -> anyhow::Result<Vec<AggJobRequest>> {
        self.produced_first_layer += 1;
        let mut is_first_shard = false;
        if !is_deferred && mark_first_chunk && !self.first_shard_emitted {
            self.first_shard_emitted = true;
            is_first_shard = true;
        }

        let ctx = AggContext {
            vk: self.vk_bytes.clone(),
            proofs,
            is_complete: self.is_complete,
            is_first_shard,
            is_leaf_layer: true,
            is_deferred,
        };
        let next_layer = if self.upper_layers.is_empty() {
            self.upper_layers.len()
        } else {
            0
        };
        Ok(vec![self.enqueue_job(ctx, next_layer, output_index)])
    }

    fn handle_job_completion(
        &mut self,
        job_id: u64,
        proof: Vec<u8>,
    ) -> anyhow::Result<Vec<AggJobRequest>> {
        let Some((next_layer, index)) = self.pending_jobs.remove(&job_id) else {
            return Err(anyhow!("received completion for unknown aggregation job"));
        };
        Ok(self.process_upper_layers(proof, next_layer, index))
    }

    fn process_upper_layers(
        &mut self,
        proof: Vec<u8>,
        start_layer: usize,
        index: usize,
    ) -> Vec<AggJobRequest> {
        let mut jobs = Vec::new();
        let last_layer_index = self.upper_layers.len();
        let mut current_proof = proof;
        let mut current_index = index;

        for idx in start_layer..=last_layer_index {
            if idx == last_layer_index {
                self.final_result = Some(current_proof);
                break;
            }

            let layer_last = last_layer_index - 1;
            let layer = &mut self.upper_layers[idx];
            layer.processed_inputs += 1;
            layer.buffer.insert(current_index, current_proof);
            let is_final_chunk = layer.chunk_count == 1 && idx == layer_last;
            let chunk_idx = current_index / 2;
            let left_idx = chunk_idx * 2;
            let right_idx = left_idx + 1;

            let ctx_option =
                if layer.buffer.contains_key(&left_idx) && layer.buffer.contains_key(&right_idx) {
                    let left = layer.buffer.remove(&left_idx).unwrap();
                    let right = layer.buffer.remove(&right_idx).unwrap();
                    Some((
                        chunk_idx,
                        AggContext {
                            vk: Vec::new(),
                            proofs: vec![left, right],
                            is_complete: is_final_chunk,
                            is_first_shard: false,
                            is_leaf_layer: false,
                            is_deferred: false,
                        },
                    ))
                } else if layer.processed_inputs == layer.expected_inputs {
                    if let Some((&remaining_index, _)) = layer.buffer.iter().next() {
                        let remaining = layer.buffer.remove(&remaining_index).unwrap();
                        Some((
                            remaining_index / 2,
                            AggContext {
                                vk: Vec::new(),
                                proofs: vec![remaining],
                                is_complete: is_final_chunk,
                                is_first_shard: false,
                                is_leaf_layer: false,
                                is_deferred: false,
                            },
                        ))
                    } else {
                        None
                    }
                } else {
                    None
                };

            if let Some((next_index, ctx)) = ctx_option {
                jobs.push(self.enqueue_job(ctx, idx + 1, next_index));
                break;
            } else {
                break;
            }
        }

        jobs
    }

    fn enqueue_job(
        &mut self,
        ctx: AggContext,
        next_layer: usize,
        output_index: usize,
    ) -> AggJobRequest {
        let job_id = self.next_job_id;
        self.next_job_id += 1;
        self.pending_jobs.insert(job_id, (next_layer, output_index));
        AggJobRequest { id: job_id, ctx }
    }

    fn is_done(&self) -> bool {
        self.final_result.is_some()
            && self.produced_first_layer == self.first_layer_expected
            && self
                .upper_layers
                .iter()
                .all(|layer| layer.processed_inputs == layer.expected_inputs)
    }

    fn take_final(self) -> anyhow::Result<Vec<u8>> {
        self.final_result
            .ok_or_else(|| anyhow!("aggregation finished without result"))
    }
}

#[cfg(feature = "gpu")]
struct AggJobRequest {
    id: u64,
    ctx: AggContext,
}

#[cfg(feature = "gpu")]
fn dispatch_agg_jobs<I>(
    dispatcher: &GpuJobDispatcher,
    result_tx: &mpsc::Sender<(u64, anyhow::Result<Vec<u8>>)>,
    jobs: I,
    pending_gpu_jobs: &mut usize,
) -> anyhow::Result<()>
where
    I: IntoIterator<Item = AggJobRequest>,
{
    for job in jobs.into_iter() {
        dispatcher
            .submit_agg(job.id, job.ctx, result_tx.clone())
            .map_err(|e| anyhow!("failed to dispatch aggregation job: {e}"))?;
        *pending_gpu_jobs += 1;
    }
    Ok(())
}

#[cfg(feature = "gpu")]
fn run_aggregator(
    config_rx: mpsc::Receiver<AggregatorConfig>,
    proof_rx: mpsc::Receiver<anyhow::Result<(usize, Vec<u8>)>>,
    snark_tx: Option<mpsc::Sender<Vec<u8>>>,
    dispatcher: GpuJobDispatcher,
    remaining_roots: Arc<AtomicUsize>,
    gpu_capacity: usize,
) -> anyhow::Result<Vec<u8>> {
    use std::time::Duration;

    let config = config_rx
        .recv()
        .context("aggregator config channel closed before receiving config")?;

    let chunk_size = cmp::max(FIRST_LAYER_BATCH_SIZE, 1);
    let mut chunk_ranges = Vec::new();
    let mut start = 0usize;
    while start < config.total_segments {
        let end = cmp::min(start + chunk_size, config.total_segments);
        chunk_ranges.push((start, end));
        start = end;
    }

    let mut aggregator = StreamingAggregator::new(
        config.vk_bytes.clone(),
        config.total_segments,
        config.deferred_inputs.len(),
    );
    let mut proofs = BTreeMap::<usize, Vec<u8>>::new();
    let mut next_chunk_index = 0usize;
    let mut deferred_inputs = config.deferred_inputs;
    deferred_inputs.sort_by_key(|(idx, _)| *idx);
    let mut deferred_processed = false;

    let mut queued_jobs = VecDeque::new();
    let mut allow_agg = false;

    let (agg_job_tx, agg_job_rx) = mpsc::channel::<(u64, anyhow::Result<Vec<u8>>)>();
    let mut pending_gpu_jobs = 0usize;
    let mut root_channel_open = true;
    let mut deferred_next_index = chunk_ranges.len();

    loop {
        if !allow_agg && remaining_roots.load(Ordering::Relaxed) <= gpu_capacity {
            allow_agg = true;
            dispatch_agg_jobs(
                &dispatcher,
                &agg_job_tx,
                queued_jobs.drain(..),
                &mut pending_gpu_jobs,
            )?;
        }

        while let Ok((job_id, result)) = agg_job_rx.try_recv() {
            pending_gpu_jobs = pending_gpu_jobs.saturating_sub(1);
            let followups = match result {
                Ok(proof) => aggregator.handle_job_completion(job_id, proof)?,
                Err(err) => return Err(err),
            };
            if allow_agg {
                dispatch_agg_jobs(&dispatcher, &agg_job_tx, followups, &mut pending_gpu_jobs)?;
            } else {
                queued_jobs.extend(followups);
            }
        }

        if next_chunk_index == chunk_ranges.len() && !deferred_processed {
            for (_, proof) in deferred_inputs.iter() {
                let jobs = aggregator.push_deferred(proof.clone(), deferred_next_index)?;
                if allow_agg {
                    dispatch_agg_jobs(&dispatcher, &agg_job_tx, jobs, &mut pending_gpu_jobs)?;
                } else {
                    queued_jobs.extend(jobs);
                }
                deferred_next_index += 1;
            }
            deferred_processed = true;
        }

        if aggregator.is_done() && pending_gpu_jobs == 0 {
            let result = aggregator.take_final()?;
            if let Some(tx) = snark_tx {
                tx.send(result.clone())
                    .map_err(|_| anyhow!("failed to send aggregate proof to snark"))?;
            }
            return Ok(result);
        }

        let mut scheduled_chunk = false;
        while next_chunk_index < chunk_ranges.len() {
            let (start_idx, end_idx) = chunk_ranges[next_chunk_index];
            if (start_idx..end_idx).all(|idx| proofs.contains_key(&idx)) {
                let mut chunk_proofs = Vec::with_capacity(end_idx - start_idx);
                for idx in start_idx..end_idx {
                    chunk_proofs.push(proofs.remove(&idx).unwrap());
                }
                let jobs = aggregator.push_normal_chunk(
                    chunk_proofs,
                    next_chunk_index == 0,
                    next_chunk_index,
                )?;
                if allow_agg {
                    dispatch_agg_jobs(&dispatcher, &agg_job_tx, jobs, &mut pending_gpu_jobs)?;
                } else {
                    queued_jobs.extend(jobs);
                }
                next_chunk_index += 1;
                scheduled_chunk = true;
            } else {
                break;
            }
        }
        if scheduled_chunk {
            continue;
        }

        if root_channel_open {
            match proof_rx.recv_timeout(Duration::from_millis(10)) {
                Ok(Ok((index, proof))) => {
                    proofs.insert(index, proof);
                    remaining_roots.fetch_sub(1, Ordering::Relaxed);
                }
                Ok(Err(err)) => return Err(err),
                Err(mpsc::RecvTimeoutError::Timeout) => {}
                Err(mpsc::RecvTimeoutError::Disconnected) => {
                    root_channel_open = false;
                }
            }
        } else if pending_gpu_jobs > 0 {
            match agg_job_rx.recv() {
                Ok((job_id, result)) => {
                    pending_gpu_jobs = pending_gpu_jobs.saturating_sub(1);
                    let followups = match result {
                        Ok(proof) => aggregator.handle_job_completion(job_id, proof)?,
                        Err(err) => return Err(err),
                    };
                    dispatch_agg_jobs(&dispatcher, &agg_job_tx, followups, &mut pending_gpu_jobs)?;
                }
                Err(_) => {
                    return Err(anyhow!("aggregation job channel closed"));
                }
            }
        } else {
            if next_chunk_index < chunk_ranges.len() {
                return Err(anyhow!(
                    "root prover channel closed before all segments were proven"
                ));
            }
            if !deferred_processed {
                continue;
            }
        }
    }
}

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
    pub fn prove(&self, ctx: &SingleNodeContext) -> anyhow::Result<(u64, Vec<u8>)> {
        if ctx.local_prover_threads > 1 {
            #[cfg(feature = "gpu")]
            {
                self.prove_in_process(ctx)
            }
            #[cfg(not(feature = "gpu"))]
            unimplemented!("multi-provers proving is only supported with GPU feature")
        } else {
            self.prove_legacy(ctx)
        }
    }

    #[cfg(feature = "gpu")]
    fn prove_in_process(&self, ctx: &SingleNodeContext) -> anyhow::Result<(u64, Vec<u8>)> {
        let target_step = Step::from_i32(ctx.target_step)
            .ok_or_else(|| anyhow!("unsupported target step: {}", ctx.target_step))?;

        let requested_workers = ctx.local_prover_threads.max(1);
        let (gpu_pool, gpu_worker_count) = {
            let pool = get_local_provers();
            let total = pool.len();
            if total == 0 {
                return Err(anyhow!("no local GPU provers detected"));
            }
            let workers = requested_workers.min(total);
            let pool = GpuJobPool::new(pool, workers)?;
            (pool, workers)
        };
        let gpu_dispatcher_main = gpu_pool.dispatcher();
        let remaining_roots = Arc::new(AtomicUsize::new(0));
        let (segment_tx, segment_rx) = mpsc::channel::<(usize, Vec<u8>)>();
        let (proof_tx, proof_rx) = mpsc::channel::<anyhow::Result<(usize, Vec<u8>)>>();
        let (config_tx, config_rx) = mpsc::channel::<AggregatorConfig>();
        let (agg_result_tx, agg_result_rx) = mpsc::channel::<anyhow::Result<Vec<u8>>>();

        let (snark_tx, snark_handle) = match target_step {
            Step::InSnark => {
                let (tx, rx) = mpsc::channel::<Vec<u8>>();
                let proving_key_paths = self.proving_key_paths.clone();
                let proof_id = ctx.proof_id.clone();

                let handle = std::thread::spawn(move || -> anyhow::Result<Vec<u8>> {
                    let agg_receipt = rx
                        .recv()
                        .map_err(|_| anyhow!("failed to receive aggregate proof for snark"))?;
                    let snark_ctx = SnarkContext {
                        proof_id,
                        agg_receipt,
                        from_input: false,
                        ..Default::default()
                    };
                    let snark_prover = SnarkProver::new(&proving_key_paths);
                    let (_, proof) = snark_prover.prove(&snark_ctx)?;
                    Ok(proof)
                });
                (Some(tx), Some(handle))
            }
            _ => (None, None),
        };

        let dispatcher_for_agg = gpu_dispatcher_main.clone();
        let dispatcher_for_root = gpu_dispatcher_main.clone();
        let remaining_for_agg = Arc::clone(&remaining_roots);
        let aggregator_handle = std::thread::spawn(move || {
            let result = run_aggregator(
                config_rx,
                proof_rx,
                snark_tx,
                dispatcher_for_agg,
                remaining_for_agg,
                gpu_worker_count,
            );
            let _ = agg_result_tx.send(result);
        });
        drop(gpu_dispatcher_main);

        let split_ctx = SplitContext {
            base_dir: ctx.base_dir.clone(),
            program_id: ctx.program_id.clone(),
            elf_path: ctx.elf_path.clone(),
            elf: ctx.elf.clone(),
            block_no: None,
            seg_size: ctx.seg_size,
            seg_path: String::new(),
            public_input_path: String::new(),
            private_input_path: ctx.private_input_path.clone(),
            private_inputs: ctx.private_inputs.clone(),
            output_path: String::new(),
            args: String::new(),
            receipt_inputs_path: ctx.receipt_inputs_path.clone(),
            receipt_inputs: ctx.receipt_inputs.clone(),
        };

        let worker_ctx = ProveContext {
            proof_id: ctx.proof_id.clone(),
            program_id: ctx.program_id.clone(),
            elf_path: ctx.elf_path.clone(),
            elf: ctx.elf.clone(),
            seg_size: ctx.seg_size,
            ..Default::default()
        };
        let proof_sender_for_root = proof_tx.clone();
        let remaining_for_root = Arc::clone(&remaining_roots);
        let segment_handle = std::thread::spawn(move || -> anyhow::Result<()> {
            let template = worker_ctx;
            while let Ok((index, segment_bytes)) = segment_rx.recv() {
                let mut ctx = template.clone();
                ctx.index = index;
                ctx.segment_bytes = segment_bytes;
                remaining_for_root.fetch_add(1, Ordering::Relaxed);
                dispatcher_for_root.submit_root(ctx, proof_sender_for_root.clone())?;
            }
            Ok(())
        });

        let executor = Executor::default();
        let (total_steps, total_segments, _public_values, deferred_inputs, vk_bytes) =
            executor.split_streaming(&split_ctx, segment_tx)?;

        config_tx
            .send(AggregatorConfig {
                total_segments: total_segments as usize,
                deferred_inputs,
                vk_bytes,
            })
            .map_err(|_| anyhow!("aggregator dropped config receiver"))?;
        drop(config_tx);

        match segment_handle.join() {
            Ok(Ok(())) => {}
            Ok(Err(e)) => return Err(e),
            Err(join_err) => return Err(anyhow!("segment dispatcher panicked: {:?}", join_err)),
        }
        drop(proof_tx);

        let aggregated_result = match agg_result_rx.recv() {
            Ok(res) => res,
            Err(_) => {
                let _ = aggregator_handle.join();
                return Err(anyhow!("failed to receive aggregation result"));
            }
        };
        let agg_receipt = match aggregated_result {
            Ok(proof) => proof,
            Err(err) => {
                let _ = aggregator_handle.join();
                return Err(err);
            }
        };

        match aggregator_handle.join() {
            Ok(()) => {}
            Err(join_err) => {
                return Err(anyhow!("aggregator thread panicked: {:?}", join_err));
            }
        }

        let aggregated_bytes = agg_receipt;
        let final_proof = match snark_handle {
            Some(handle) => match handle.join() {
                Ok(snark_result) => snark_result?,
                Err(join_err) => {
                    return Err(anyhow!("snark thread panicked: {:?}", join_err));
                }
            },
            None => aggregated_bytes,
        };

        Ok((total_steps, final_proof))
    }

    fn prove_legacy(&self, ctx: &SingleNodeContext) -> anyhow::Result<(u64, Vec<u8>)> {
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
        let mut program_cache = PROGRAM_CACHE.lock();
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
        let mut cache = KEY_CACHE.lock();
        let device_id = 0;
        let (pk, vk) = loop {
            if let Some((pk, vk)) = cache.get(device_id, &ctx.program_id) {
                break (pk, vk);
            }
            let (pk, vk) = prover.core_prover.setup(program);
            cache.push(device_id, ctx.program_id.clone(), (pk, vk));
        };

        let vk_bytes = bincode::serialize(&vk)?;
        file::new(&format!("{}/vk.bin", ctx.base_dir)).write_all(&vk_bytes)?;

        let core_proof =
            prover.prove_core(pk, program.clone(), &network_prove.stdin, opts, context)?;

        let deferred_proofs = network_prove
            .stdin
            .proofs
            .iter()
            .map(|(reduce_proof, _)| reduce_proof.clone())
            .collect();

        let public_values = core_proof.public_values.clone();
        let cycles = core_proof.cycles;

        // Generate the compressed proof.
        let reduced_proof = prover.compress(
            &ZKMVerifyingKey { vk: vk.clone() },
            core_proof,
            deferred_proofs,
            opts,
        )?;

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

        Ok((cycles, serde_json::to_string(&proof)?.into_bytes()))
    }
}

#[cfg(feature = "gpu")]
static LOCAL_PROVERS: OnceLock<Arc<MultiGpuProver>> = OnceLock::new();

#[cfg(feature = "gpu")]
pub fn get_local_provers() -> Arc<MultiGpuProver> {
    LOCAL_PROVERS
        .get_or_init(|| Arc::new(MultiGpuProver::autodetect().unwrap()))
        .clone()
}
