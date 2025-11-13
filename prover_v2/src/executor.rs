use common::file;
use std::borrow::Borrow;
use std::fs::File;
use std::io::{self, Seek, Write};
use std::sync::{
    mpsc::sync_channel,
    OnceLock, {Arc, Mutex},
};
use std::thread::ScopedJoinHandle;
use std::time::Instant;

use p3_maybe_rayon::prelude::*;
use zkm_core_executor::{
    events::{format_table_line, sorted_table_lines},
    ExecutionRecord, ExecutionReport, ExecutionState, Executor as Runtime, Program,
    SubproofVerifier, ZKMContext, ZKMReduceProof,
};
use zkm_core_machine::{
    io::ZKMStdin,
    shape::CoreShapeConfig,
    utils::{concurrency::TurnBasedSync, trace_checkpoint, ZKMCoreProverError},
};
use zkm_prover::components::ZKMProverComponents;
use zkm_prover::{CoreSC, ZKMProver};
use zkm_stark::koala_bear_poseidon2::KoalaBearPoseidon2;
use zkm_stark::{
    MachineProver, MachineRecord, PublicValues, StarkGenericConfig, StarkVerifyingKey, ZKMCoreOpts,
};

pub use crate::contexts::SplitContext;
use crate::{
    get_prover, NetworkProve, ProverComponents, FIRST_LAYER_BATCH_SIZE, KEY_CACHE, PROGRAM_CACHE,
    VK_CACHE,
};

pub trait SegmentSink: Send + Sync {
    fn on_segments(&self, base_index: usize, segments: Vec<ExecutionRecord>);

    fn on_segment_count(&self, _total: usize) {}

    fn on_deferred(&self, _index: usize, _data: Vec<u8>) {}
}

pub struct FileSegmentSink<'a> {
    base_path: &'a str,
}

impl<'a> FileSegmentSink<'a> {
    pub fn new(base_path: &'a str) -> Self {
        Self { base_path }
    }

    fn segment_path(&self, index: usize) -> String {
        format!("{}/{}", self.base_path, index)
    }

    fn deferred_path(&self, index: usize) -> String {
        format!("{}/deferred_proof_{}", self.base_path, index)
    }
}

impl<'a> SegmentSink for FileSegmentSink<'a> {
    fn on_segments(&self, base_index: usize, segments: Vec<ExecutionRecord>) {
        for (offset, segment) in segments.into_iter().enumerate() {
            let encoded_segment = bincode::serialize(&segment).unwrap();
            // use zstd to compress, level = 2 or 3
            let compressed_segment =
                zstd::stream::encode_all(&*encoded_segment, 2).expect("zstd compress failed");

            write_file(self.segment_path(base_index + offset), &compressed_segment)
                .expect("Failed to write segment");
        }
    }

    fn on_segment_count(&self, total: usize) {
        write_file(
            format!("{}/segments.txt", self.base_path),
            total.to_string().as_bytes(),
        )
        .expect("Failed to write segment count");
    }

    fn on_deferred(&self, index: usize, data: Vec<u8>) {
        file::new(&self.deferred_path(index))
            .write_all(&data)
            .expect("Failed to write deferred proof");
    }
}

pub struct ChannelSegmentSink {
    sender: std::sync::mpsc::Sender<(usize, ExecutionRecord)>,
    total_segments: Mutex<usize>,
    deferred: Mutex<Vec<(usize, Vec<u8>)>>,
}

impl ChannelSegmentSink {
    pub fn new(sender: std::sync::mpsc::Sender<(usize, ExecutionRecord)>) -> Self {
        Self {
            sender,
            total_segments: Mutex::new(0),
            deferred: Mutex::new(Vec::new()),
        }
    }

    pub fn total_segments(&self) -> usize {
        *self.total_segments.lock().unwrap()
    }

    pub fn deferred_inputs(&self) -> Vec<(usize, Vec<u8>)> {
        self.deferred.lock().unwrap().clone()
    }
}

impl SegmentSink for ChannelSegmentSink {
    fn on_segments(&self, base_index: usize, segments: Vec<ExecutionRecord>) {
        for (offset, record) in segments.into_iter().enumerate() {
            self.sender
                .send((base_index + offset, record))
                .expect("segment receiver dropped");
        }
    }

    fn on_segment_count(&self, total: usize) {
        *self.total_segments.lock().unwrap() = total;
    }

    fn on_deferred(&self, index: usize, data: Vec<u8>) {
        self.deferred.lock().unwrap().push((index, data));
    }
}

#[derive(Default)]
pub struct Executor {}
impl Executor {
    pub fn split(&self, ctx: &SplitContext) -> anyhow::Result<(u64, u32)> {
        let prover = get_prover();
        let mut network_prove = NetworkProve::new(ctx.seg_size);

        let inputs_data: Vec<Vec<u8>> = if !ctx.private_inputs.is_empty() {
            ctx.private_inputs.clone()
        } else {
            let encoded_input = file::new(&ctx.private_input_path).read()?;
            bincode::deserialize(&encoded_input)?
        };
        inputs_data.into_iter().for_each(|input| {
            network_prove.stdin.write_vec(input);
        });

        if !ctx.receipt_inputs.is_empty() || !ctx.receipt_inputs_path.is_empty() {
            let receipts = if !ctx.receipt_inputs.is_empty() {
                ctx.receipt_inputs.clone()
            } else {
                let receipt_datas = std::fs::read(&ctx.receipt_inputs_path)?;
                bincode::deserialize::<Vec<Vec<u8>>>(&receipt_datas)?
            };
            for receipt in receipts.iter() {
                let receipt: (
                    ZKMReduceProof<KoalaBearPoseidon2>,
                    StarkVerifyingKey<KoalaBearPoseidon2>,
                ) = bincode::deserialize(receipt).map_err(|e| anyhow::anyhow!(e))?;
                network_prove.stdin.write_proof(receipt.0, receipt.1);
            }
            tracing::info!("Write {} receipts", receipts.len());
        }

        let program = {
            let mut program_cache = PROGRAM_CACHE.lock();
            if let Some(program) = program_cache.cache.get(&ctx.program_id) {
                tracing::info!("load program from cache");
                program.clone()
            } else {
                tracing::info!("No program in cache, generate new program");
                let elf = if !ctx.elf.is_empty() {
                    ctx.elf.clone()
                } else {
                    let elf_path = ctx.elf_path.clone();
                    file::new(&elf_path).read()?
                };
                let program = prover
                    .get_program(&elf)
                    .map_err(|e| anyhow::Error::msg(e.to_string()))?;
                program_cache.push(ctx.program_id.clone(), program.clone());
                program
            }
        };

        let device_id = 0;
        let entry = {
            let mut cache = KEY_CACHE.lock();
            cache.entry(device_id, ctx.program_id.clone())
        };
        let (_, vk) = entry.get_or_init_with(|| prover.core_prover.setup(&program));
        let vk_bytes = bincode::serialize(&vk)?;
        file::new(&format!("{}/vk.bin", ctx.base_dir)).write_all(&vk_bytes)?;

        let context = network_prove.context_builder.build();
        let segment_sink = FileSegmentSink::new(&ctx.seg_path);
        let (total_steps, total_segments, public_values_stream) = self.split_with_context(
            &prover,
            ctx,
            &program,
            vk,
            &network_prove.stdin,
            network_prove.opts.core_opts,
            context,
            prover.core_shape_config.as_ref(),
            &segment_sink,
        )?;
        // write public_values_stream
        // file::new(&ctx.output_path).write(&public_values_stream)?;
        let public_values_path = format!("{}/wrap/public_values.bin", ctx.base_dir);
        file::new(&public_values_path).write_all(&public_values_stream)?;

        Ok((total_steps, total_segments))
    }

    pub fn split_streaming(
        &self,
        ctx: &SplitContext,
        sender: std::sync::mpsc::Sender<(usize, ExecutionRecord)>,
    ) -> anyhow::Result<(u64, u32, Vec<u8>, Vec<(usize, Vec<u8>)>, Vec<u8>)> {
        // To prevent the executor from occupying a GPU exclusively,
        // the prover used here doesn’t use GPU resources.
        let prover = get_executor();
        let mut network_prove = NetworkProve::new(ctx.seg_size);

        let inputs_data: Vec<Vec<u8>> = if !ctx.private_inputs.is_empty() {
            ctx.private_inputs.clone()
        } else {
            let encoded_input = file::new(&ctx.private_input_path).read()?;
            bincode::deserialize(&encoded_input)?
        };
        inputs_data.into_iter().for_each(|input| {
            network_prove.stdin.write_vec(input);
        });

        if !ctx.receipt_inputs.is_empty() || !ctx.receipt_inputs_path.is_empty() {
            let receipts = if !ctx.receipt_inputs.is_empty() {
                ctx.receipt_inputs.clone()
            } else {
                let receipt_datas = std::fs::read(&ctx.receipt_inputs_path)?;
                bincode::deserialize::<Vec<Vec<u8>>>(&receipt_datas)?
            };
            for receipt in receipts.iter() {
                let receipt: (
                    ZKMReduceProof<KoalaBearPoseidon2>,
                    StarkVerifyingKey<KoalaBearPoseidon2>,
                ) = bincode::deserialize(receipt).map_err(|e| anyhow::anyhow!(e))?;
                network_prove.stdin.write_proof(receipt.0, receipt.1);
            }
            tracing::info!("Write {} receipts", receipts.len());
        }

        let program = {
            let mut program_cache = PROGRAM_CACHE.lock();
            if let Some(program) = program_cache.cache.get(&ctx.program_id) {
                tracing::info!("load program from cache");
                program.clone()
            } else {
                tracing::info!("No program in cache, generate new program");
                let elf = if !ctx.elf.is_empty() {
                    ctx.elf.clone()
                } else {
                    let elf_path = ctx.elf_path.clone();
                    file::new(&elf_path).read()?
                };
                let program = prover
                    .get_program(&elf)
                    .map_err(|e| anyhow::Error::msg(e.to_string()))?;
                program_cache.push(ctx.program_id.clone(), program.clone());
                program
            }
        };

        let vk = {
            let mut vk_cache = VK_CACHE.lock();
            if let Some(vk) = vk_cache.get(&ctx.program_id) {
                vk
            } else {
                let (_, vk) = prover.core_prover.setup(&program);
                vk_cache.push(ctx.program_id.clone(), vk.clone());
                vk
            }
        };
        let vk_bytes = bincode::serialize(&vk)?;

        let context = network_prove.context_builder.build();
        let segment_sink = Arc::new(ChannelSegmentSink::new(sender));
        let (total_steps, total_segments, public_values_stream) = self.split_with_context(
            &prover,
            ctx,
            &program,
            &vk,
            &network_prove.stdin,
            network_prove.opts.core_opts,
            context,
            prover.core_shape_config.as_ref(),
            segment_sink.as_ref(),
        )?;

        Ok((
            total_steps,
            total_segments,
            public_values_stream,
            segment_sink.deferred_inputs(),
            vk_bytes,
        ))
    }

    #[allow(clippy::too_many_arguments)]
    pub fn split_with_context<'a, S: SegmentSink, C: ZKMProverComponents>(
        &self,
        prover: &'a ZKMProver<C>,
        _ctx: &SplitContext,
        program: &Program,
        vk: &StarkVerifyingKey<CoreSC>,
        stdin: &ZKMStdin,
        opts: ZKMCoreOpts,
        mut context: ZKMContext<'a>,
        shape_config: Option<&CoreShapeConfig<<CoreSC as StarkGenericConfig>::Val>>,
        segment_sink: &S,
    ) -> anyhow::Result<(u64, u32, Vec<u8>)> {
        context.subproof_verifier = Some(prover as &dyn SubproofVerifier);
        // Setup the runtime.
        let mut runtime = Runtime::with_context(program.clone(), opts, context);
        runtime.maximal_shapes = shape_config.map(|config| {
            config
                .maximal_core_shapes(opts.shard_size.ilog2() as usize)
                .into_iter()
                .collect()
        });
        runtime.write_vecs(&stdin.buffer);
        for proof in stdin.proofs.iter() {
            let (proof, vk) = proof.clone();
            runtime.write_proof(proof, vk);
        }

        // Record the start of the process.
        let split_start = Instant::now();
        let span = tracing::Span::current().clone();
        std::thread::scope(move |s| {
            let _span = span.enter();

            // Spawn the checkpoint generator thread.
            let checkpoint_generator_span = tracing::Span::current().clone();
            let (checkpoints_tx, checkpoints_rx) =
                sync_channel::<(usize, File, bool)>(opts.checkpoints_channel_capacity);
            let checkpoint_generator_handle: ScopedJoinHandle<Result<_, ZKMCoreProverError>> = s
                .spawn(move || {
                    let _span = checkpoint_generator_span.enter();
                    tracing::debug_span!("checkpoint generator").in_scope(|| {
                        let mut index = 0;

                        loop {
                            // Enter the span.
                            let span = tracing::debug_span!("batch");
                            let _span = span.enter();

                            // Execute the runtime until we reach a checkpoint.t
                            let (checkpoint, done) = runtime
                                .execute_state(false)
                                .map_err(ZKMCoreProverError::ExecutionError)?;

                            let serialized = bincode::serialize(&checkpoint)
                                .expect("Failed to serialize checkpoint");
                            tracing::info!("Checkpoint size: {} bytes", serialized.len());

                            // Save the checkpoint to a temp file.
                            let mut checkpoint_file =
                                tempfile::tempfile().map_err(ZKMCoreProverError::IoError)?;
                            checkpoint
                                .save(&mut checkpoint_file)
                                .map_err(ZKMCoreProverError::IoError)?;

                            // Send the checkpoint.
                            checkpoints_tx.send((index, checkpoint_file, done)).unwrap();

                            // If we've reached the final checkpoint, break out of the loop.
                            if done {
                                break Ok(runtime.state.public_values_stream);
                            }

                            // Update the index.
                            index += 1;
                        }
                    })
                });

            // Spawn the phase 2 record generator thread.
            let p2_record_gen_sync = Arc::new(TurnBasedSync::new());
            let checkpoints_rx = Arc::new(Mutex::new(checkpoints_rx));
            let segment_index = Arc::new(Mutex::new(0));

            let report_aggregate = Arc::new(Mutex::new(ExecutionReport::default()));
            let state = Arc::new(Mutex::new(PublicValues::<u32, u32>::default().reset()));
            let deferred = Arc::new(Mutex::new(ExecutionRecord::new(program.clone().into())));
            let mut p2_record_and_trace_gen_handles = Vec::new();
            for _ in 0..opts.trace_gen_workers {
                let record_gen_sync = Arc::clone(&p2_record_gen_sync);
                let checkpoints_rx = Arc::clone(&checkpoints_rx);
                let segment_index = Arc::clone(&segment_index);

                let report_aggregate = Arc::clone(&report_aggregate);
                let state = Arc::clone(&state);
                let deferred = Arc::clone(&deferred);
                let program = program.clone();

                let span = tracing::Span::current().clone();

                let handle = s.spawn(move || {
                    let _span = span.enter();
                    tracing::debug_span!("phase 2 trace generation").in_scope(|| {
                        loop {
                            // Receive the latest checkpoint.
                            let received = { checkpoints_rx.lock().unwrap().recv() };
                            if let Ok((index, mut checkpoint, done)) = received {
                                // Trace the checkpoint and reconstruct the execution records.
                                let now = Instant::now();
                                let mut reader = std::io::BufReader::new(&checkpoint);
                                let exe_state: ExecutionState =
                                    bincode::deserialize_from(&mut reader)
                                        .expect("failed to deserialize state");
                                let (mut records, report) =
                                    tracing::debug_span!("trace checkpoint").in_scope(|| {
                                        trace_checkpoint::<CoreSC>(
                                            program.clone(),
                                            exe_state.clone(),
                                            opts,
                                            shape_config,
                                        )
                                    });
                                tracing::info!(
                                    "generated {} records in {:?}",
                                    records.len(),
                                    now.elapsed()
                                );
                                // debug_assert_eq!(records.len(), 1);
                                *report_aggregate.lock().unwrap() += report;
                                // reset_seek(&mut checkpoint);
                                checkpoint
                                    .seek(io::SeekFrom::Start(0))
                                    .expect("failed to seek to start of tempfile");

                                // Wait for our turn to update the state.
                                record_gen_sync.wait_for_turn(index);

                                // Update the public values & prover state for the shards which contain
                                // "cpu events".
                                let mut state = state.lock().unwrap();
                                for record in records.iter_mut() {
                                    state.shard += 1;
                                    state.execution_shard = record.public_values.execution_shard;
                                    state.start_pc = record.public_values.start_pc;
                                    state.next_pc = record.public_values.next_pc;
                                    state.committed_value_digest =
                                        record.public_values.committed_value_digest;
                                    state.deferred_proofs_digest =
                                        record.public_values.deferred_proofs_digest;
                                    record.public_values = *state;
                                }

                                // Defer events that are too expensive to include in every shard.
                                let mut deferred = deferred.lock().unwrap();
                                for record in records.iter_mut() {
                                    deferred.append(&mut record.defer());
                                }

                                // See if any deferred shards are ready to be committed to.
                                let mut deferred = deferred.split(done, None, opts.split_opts);
                                tracing::info!("deferred {} records", deferred.len());

                                // Update the public values & prover state for the shards which do not
                                // contain "cpu events" before committing to them.
                                if !done {
                                    state.execution_shard += 1;
                                }
                                for record in deferred.iter_mut() {
                                    state.shard += 1;
                                    state.previous_init_addr_bits =
                                        record.public_values.previous_init_addr_bits;
                                    state.last_init_addr_bits =
                                        record.public_values.last_init_addr_bits;
                                    state.previous_finalize_addr_bits =
                                        record.public_values.previous_finalize_addr_bits;
                                    state.last_finalize_addr_bits =
                                        record.public_values.last_finalize_addr_bits;
                                    state.start_pc = state.next_pc;
                                    record.public_values = *state;
                                }
                                records.append(&mut deferred);

                                let mut segment_index = segment_index.lock().unwrap();
                                let base_index = *segment_index;
                                *segment_index += records.len();

                                segment_sink.on_segment_count(*segment_index);

                                // Let another worker update the state.
                                record_gen_sync.advance_turn();

                                let last_pv = records.last().unwrap().public_values();
                                segment_sink.on_segments(base_index, records);

                                // process deferred proofs
                                if done && !stdin.proofs.is_empty() {
                                    let last_proof_pv = last_pv.as_slice().borrow();
                                    let deferred_proofs = stdin
                                        .proofs
                                        .iter()
                                        .map(|(reduce_proof, _)| reduce_proof.clone())
                                        .collect::<Vec<_>>();
                                    let deferred_inputs = prover.get_recursion_deferred_inputs(
                                        vk,
                                        last_proof_pv,
                                        &deferred_proofs,
                                        FIRST_LAYER_BATCH_SIZE,
                                    );

                                    deferred_inputs.par_iter().enumerate().for_each(
                                        |(i, deferred_input)| {
                                            let encoded_proof =
                                                bincode::serialize(&deferred_input).unwrap();
                                            segment_sink.on_deferred((1 << 16) | i, encoded_proof);
                                        },
                                    );
                                }
                            } else {
                                break;
                            }
                        }
                    })
                });
                p2_record_and_trace_gen_handles.push(handle);
            }
            // Wait until the checkpoint generator handle has fully finished.
            let public_values_stream = checkpoint_generator_handle.join().unwrap().unwrap();
            // file::new(&ctx.public_input_path).write(&public_values_stream)?;                    // write public_values_stream

            // Wait until the records and traces have been fully generated for phase 2.
            p2_record_and_trace_gen_handles
                .into_iter()
                .for_each(|handle| handle.join().unwrap());
            let total_segments = {
                let segment_index = segment_index.lock().unwrap();
                *segment_index
            };

            // Log some of the `ExecutionReport` information.
            let report_aggregate = report_aggregate.lock().unwrap();
            tracing::info!(
                "execution report (totals): total_cycles={}, total_syscall_cycles={}, touched_memory_addresses={}",
                report_aggregate.total_instruction_count(),
                report_aggregate.total_syscall_count(),
                report_aggregate.touched_memory_addresses,
            );

            // Print the opcode and syscall count tables like `du`: sorted by count (descending) and
            // with the count in the first column.
            tracing::info!("execution report (opcode counts):");
            let (width, lines) = sorted_table_lines(report_aggregate.opcode_counts.as_ref());
            for (label, count) in lines {
                if *count > 0 {
                    tracing::info!("  {}", format_table_line(&width, &label, count));
                } else {
                    tracing::debug!("  {}", format_table_line(&width, &label, count));
                }
            }

            tracing::info!("execution report (syscall counts):");
            let (width, lines) = sorted_table_lines(report_aggregate.syscall_counts.as_ref());
            for (label, count) in lines {
                if *count > 0 {
                    tracing::info!("  {}", format_table_line(&width, &label, count));
                } else {
                    tracing::debug!("  {}", format_table_line(&width, &label, count));
                }
            }

            let cycles = report_aggregate.total_instruction_count();

            // Print the summary.
            let split_time = split_start.elapsed().as_secs_f64();
            tracing::info!(
                "summary: cycles={}, executor={}s, khz={:.2}",
                cycles,
                split_time,
                cycles as f64 / (split_time * 1000.0),
            );

            Ok((cycles, total_segments as u32, public_values_stream))
        })
    }
}

fn write_file(path: String, buf: &[u8]) -> anyhow::Result<()> {
    let tmp_path = format!("{path}.tmp");
    let mut file = File::create(&tmp_path)?;
    file.write_all(buf)?;
    file.sync_all()?;
    std::fs::rename(tmp_path, path)?;

    Ok(())
}

static EXECUTOR: OnceLock<Arc<ZKMProver>> = OnceLock::new();

pub fn get_executor() -> Arc<ZKMProver> {
    EXECUTOR.get_or_init(|| Arc::new(ZKMProver::new())).clone()
}
