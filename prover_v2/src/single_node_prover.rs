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
use std::collections::{BTreeMap, HashMap, VecDeque};
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{mpsc, Arc, OnceLock};
use zkm_core_executor::{ExecutionRecord, ZKMReduceProof};
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
struct StreamingAggregator {
    vk_bytes: Vec<u8>,
    is_complete: bool,
    first_layer_expected: usize,
    produced_first_layer: usize,
    first_shard_emitted: bool,
    plan: AggregationPlan,
    nodes: Vec<AggNodeState>,
    final_result: Option<Vec<u8>>,
    next_job_id: u64,
    pending_jobs: HashMap<u64, usize>,
}

#[cfg(feature = "gpu")]
struct AggregationPlan {
    level_counts: Vec<usize>,
    level_offsets: Vec<usize>,
    parents: Vec<Option<(usize, usize)>>,
    expected_inputs: Vec<usize>,
    layers: Vec<usize>,
    indices: Vec<usize>,
}

#[cfg(feature = "gpu")]
impl AggregationPlan {
    fn new(total_leaves: usize) -> Self {
        let mut level_counts = Vec::new();
        let mut count = cmp::max(total_leaves, 1);
        loop {
            level_counts.push(count);
            if count == 1 {
                break;
            }
            count = (count + 1) / 2;
        }

        let mut level_offsets = Vec::with_capacity(level_counts.len());
        let mut offset = 0usize;
        for &c in &level_counts {
            level_offsets.push(offset);
            offset += c;
        }
        let total_nodes = offset;
        let mut parents = vec![None; total_nodes];
        let mut expected_inputs = vec![0; total_nodes];
        let mut layers = vec![0; total_nodes];
        let mut indices = vec![0; total_nodes];

        for (layer, &count) in level_counts.iter().enumerate() {
            let base = level_offsets[layer];
            for idx in 0..count {
                let node_id = base + idx;
                layers[node_id] = layer;
                indices[node_id] = idx;
            }
        }

        for layer in 0..level_counts.len().saturating_sub(1) {
            let child_base = level_offsets[layer];
            let parent_base = level_offsets[layer + 1];
            for idx in 0..level_counts[layer] {
                let child_id = child_base + idx;
                let parent_idx = idx / 2;
                let slot = idx % 2;
                let parent_id = parent_base + parent_idx;
                parents[child_id] = Some((parent_id, slot));
                expected_inputs[parent_id] += 1;
            }
        }

        Self {
            level_counts,
            level_offsets,
            parents,
            expected_inputs,
            layers,
            indices,
        }
    }

    fn total_nodes(&self) -> usize {
        self.parents.len()
    }

    fn leaf_node_id(&self, index: usize) -> usize {
        self.level_offsets[0] + index
    }

    fn parent(&self, node_id: usize) -> Option<(usize, usize)> {
        self.parents.get(node_id).copied().flatten()
    }

    fn expected_inputs(&self, node_id: usize) -> usize {
        *self.expected_inputs.get(node_id).unwrap_or(&0)
    }

    fn is_leaf(&self, node_id: usize) -> bool {
        self.layers.get(node_id).copied().unwrap_or(0) == 0
    }

    fn is_top_level(&self, node_id: usize) -> bool {
        if let Some(layer) = self.layers.get(node_id) {
            layer + 1 == self.level_counts.len()
        } else {
            false
        }
    }

    fn layer_of(&self, node_id: usize) -> usize {
        self.layers.get(node_id).copied().unwrap_or(0)
    }

    fn index_within_layer(&self, node_id: usize) -> usize {
        self.indices.get(node_id).copied().unwrap_or(0)
    }
}

#[cfg(feature = "gpu")]
#[derive(Clone, Default)]
struct AggNodeState {
    received_inputs: usize,
    inputs: [Option<Vec<u8>>; 2],
    job_inflight: bool,
}

#[cfg(feature = "gpu")]
impl StreamingAggregator {
    fn new(vk_bytes: Vec<u8>, total_segments: usize, deferred_len: usize) -> Self {
        let first_layer_batch_size = cmp::max(FIRST_LAYER_BATCH_SIZE, 1);
        let chunk_ranges = (total_segments + first_layer_batch_size - 1) / first_layer_batch_size;

        let first_layer_expected = chunk_ranges + deferred_len;
        let plan = AggregationPlan::new(cmp::max(first_layer_expected, 1));
        let nodes = vec![AggNodeState::default(); plan.total_nodes()];

        Self {
            vk_bytes,
            is_complete: total_segments == 1 && deferred_len == 0,
            first_layer_expected,
            produced_first_layer: 0,
            first_shard_emitted: false,
            plan,
            nodes,
            final_result: None,
            next_job_id: 0,
            pending_jobs: HashMap::new(),
        }
    }

    fn push_normal_chunk(
        &mut self,
        proofs: Vec<Vec<u8>>,
        is_first_chunk: bool,
        output_index: usize,
    ) -> anyhow::Result<Vec<AggJobRequest>> {
        self.schedule_leaf_job(proofs, is_first_chunk, false, output_index)
    }

    fn push_deferred(
        &mut self,
        proof: Vec<u8>,
        output_index: usize,
    ) -> anyhow::Result<Vec<AggJobRequest>> {
        self.schedule_leaf_job(vec![proof], false, true, output_index)
    }

    fn schedule_leaf_job(
        &mut self,
        proofs: Vec<Vec<u8>>,
        mark_first_chunk: bool,
        is_deferred: bool,
        output_index: usize,
    ) -> anyhow::Result<Vec<AggJobRequest>> {
        if output_index >= self.first_layer_expected {
            return Err(anyhow!("invalid leaf index {output_index}"));
        }
        self.produced_first_layer += 1;
        let mut is_first_shard = false;
        if !is_deferred && mark_first_chunk && !self.first_shard_emitted {
            self.first_shard_emitted = true;
            is_first_shard = true;
        }

        let node_id = self.plan.leaf_node_id(output_index);
        let ctx = AggContext {
            vk: self.vk_bytes.clone(),
            proofs,
            is_complete: self.is_complete && self.plan.is_top_level(node_id),
            is_first_shard,
            is_leaf_layer: true,
            is_deferred,
        };
        Ok(vec![self.enqueue_job(node_id, ctx)])
    }

    fn handle_job_completion(
        &mut self,
        job_id: u64,
        proof: Vec<u8>,
    ) -> anyhow::Result<Vec<AggJobRequest>> {
        let Some(node_id) = self.pending_jobs.remove(&job_id) else {
            return Err(anyhow!("received completion for unknown aggregation job"));
        };
        if let Some(state) = self.nodes.get_mut(node_id) {
            state.job_inflight = false;
        }
        tracing::info!(
            "Aggregator job {} completed for node {} layer {} index {}",
            job_id,
            node_id,
            self.plan.layer_of(node_id),
            self.plan.index_within_layer(node_id)
        );
        Ok(self.propagate_output(node_id, proof))
    }

    fn propagate_output(&mut self, node_id: usize, proof: Vec<u8>) -> Vec<AggJobRequest> {
        if let Some((parent_id, slot)) = self.plan.parent(node_id) {
            tracing::info!(
                "Aggregator node {} sending proof to parent {} slot {}",
                node_id,
                parent_id,
                slot
            );
            if let Some(state) = self.nodes.get_mut(parent_id) {
                state.inputs[slot] = Some(proof);
                state.received_inputs += 1;
            }
            self.try_schedule_node(parent_id)
        } else {
            tracing::info!("Aggregator reached final result at node {}", node_id);
            self.final_result = Some(proof);
            Vec::new()
        }
    }

    fn try_schedule_node(&mut self, node_id: usize) -> Vec<AggJobRequest> {
        if self.plan.is_leaf(node_id) {
            return Vec::new();
        }
        let expected = self.plan.expected_inputs(node_id);
        if expected == 0 {
            return Vec::new();
        }
        let state = &mut self.nodes[node_id];
        if state.job_inflight || state.received_inputs < expected {
            tracing::debug!(
                "Aggregator node {} waiting for inputs {}/{}",
                node_id,
                state.received_inputs,
                expected
            );
            return Vec::new();
        }
        let mut proofs = Vec::with_capacity(expected);
        for slot in 0..2 {
            if let Some(data) = state.inputs[slot].take() {
                proofs.push(data);
                if proofs.len() == expected {
                    break;
                }
            }
        }
        debug_assert_eq!(proofs.len(), expected);
        state.received_inputs = 0;
        let ctx = AggContext {
            vk: Vec::new(),
            proofs,
            is_complete: self.plan.is_top_level(node_id),
            is_first_shard: false,
            is_leaf_layer: false,
            is_deferred: false,
        };
        vec![self.enqueue_job(node_id, ctx)]
    }

    fn enqueue_job(&mut self, node_id: usize, ctx: AggContext) -> AggJobRequest {
        let job_id = self.next_job_id;
        self.next_job_id += 1;
        self.pending_jobs.insert(job_id, node_id);
        if let Some(state) = self.nodes.get_mut(node_id) {
            state.job_inflight = true;
        }
        tracing::info!(
            "Aggregator enqueue job {} for node {} layer {} index {}",
            job_id,
            node_id,
            self.plan.layer_of(node_id),
            self.plan.index_within_layer(node_id)
        );
        AggJobRequest { id: job_id, ctx }
    }

    fn is_done(&self) -> bool {
        self.final_result.is_some()
            && self.produced_first_layer == self.first_layer_expected
            && self.pending_jobs.is_empty()
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
        tracing::info!(
            "Dispatching aggregation job {} current_pending={}",
            job.id,
            pending_gpu_jobs
        );
        dispatcher
            .submit_agg(job.id, job.ctx, result_tx.clone())
            .map_err(|e| anyhow!("failed to dispatch aggregation job: {e}"))?;
        *pending_gpu_jobs += 1;
        tracing::info!(
            "Aggregation job {} submitted, pending_gpu_jobs={}",
            job.id,
            pending_gpu_jobs
        );
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
    tracing::info!(
        "Aggregator initialized: total_segments={} chunk_size={} deferred_inputs={}",
        config.total_segments,
        chunk_size,
        config.deferred_inputs.len()
    );
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
        tracing::debug!(
            "Aggregator loop state: remaining_roots={} pending_gpu_jobs={} queued_jobs={} next_chunk={} allow_agg={} is_done={}",
            remaining_roots.load(Ordering::Relaxed),
            pending_gpu_jobs,
            queued_jobs.len(),
            next_chunk_index,
            allow_agg,
            aggregator.is_done()
        );
        if !allow_agg {
            let current_roots = remaining_roots.load(Ordering::Relaxed);
            if current_roots <= gpu_capacity {
                allow_agg = true;
                tracing::info!(
                    "Enabling aggregation dispatch: remaining_roots={}, gpu_capacity={}, queued_jobs={}",
                    current_roots,
                    gpu_capacity,
                    queued_jobs.len()
                );
                dispatch_agg_jobs(
                    &dispatcher,
                    &agg_job_tx,
                    queued_jobs.drain(..),
                    &mut pending_gpu_jobs,
                )?;
            }
        }

        while let Ok((job_id, result)) = agg_job_rx.try_recv() {
            pending_gpu_jobs = pending_gpu_jobs.saturating_sub(1);
            let followups = match result {
                Ok(proof) => aggregator.handle_job_completion(job_id, proof)?,
                Err(err) => return Err(err),
            };
            tracing::info!(
                "Aggregation job {} finished, pending_gpu_jobs={} allow_agg={}",
                job_id,
                pending_gpu_jobs,
                allow_agg
            );
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
            tracing::info!(
                "Aggregator completed: pending_gpu_jobs=0, queued_jobs={}",
                queued_jobs.len()
            );
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
                tracing::info!(
                    "Scheduling aggregation chunk {} (segments {}-{}) allow_agg={}",
                    next_chunk_index,
                    start_idx,
                    end_idx,
                    allow_agg
                );
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
                    tracing::info!(
                        "Root channel closed after processing all segments; proofs_len={}",
                        proofs.len()
                    );
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
                    tracing::info!(
                        "Blocking receive completed job {} pending_gpu_jobs={} allow_agg={}",
                        job_id,
                        pending_gpu_jobs,
                        allow_agg
                    );
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
        let (segment_tx, segment_rx) = mpsc::channel::<(usize, ExecutionRecord)>();
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
            while let Ok((index, record)) = segment_rx.recv() {
                let mut ctx = template.clone();
                ctx.index = index;
                ctx.segment_bytes.clear();
                ctx.segment_obj = Some(record);
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
        let device_id = 0;
        let entry = {
            let mut cache = KEY_CACHE.lock();
            cache.entry(device_id, ctx.program_id.clone())
        };
        let (pk, vk) = entry.get_or_init_with(|| prover.core_prover.setup(program));

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
