use crate::database;
use crate::database::{Database, StageTask};
use crate::proto::includes::v1::Step;
use crate::proto::stage_service;
use crate::prover_client;
use crate::stage::{
    stage::get_timestamp,
    stage::{SplitMeta, Stage},
    tasks::{Task, TASK_ITYPE_FINAL, TASK_ITYPE_SPLIT, TASK_STATE_FAILED, TASK_STATE_SUCCESS},
    GenerateTask,
};
use crate::TlsConfig;
use anyhow::Context;
use common::file;
use prover_v2::contexts::SplitContext;
use prover_v2::executor::Executor;
use prover_v2::SplitItem;
// use std::collections::HashMap;
use std::sync::Arc;
// use std::sync::Mutex;
use crate::stage::tasks::SplitTask;
use tokio::sync::{mpsc, Semaphore};
use tokio::time;
use tracing::{error, info, instrument, warn};

macro_rules! save_task {
    ($task:ident, $db_pool:ident, $type:expr) => {
        if $task.state == TASK_STATE_FAILED || $task.state == TASK_STATE_SUCCESS {
            tracing::info!(
                "begin to save task: {:?} type {:?} status {}",
                $task.task_id,
                $type,
                $task.state
            );
            // TODO: should remove the content from database, store it by FS.
            let content = serde_json::to_string(&$task).unwrap();
            let prove_task = database::ProveTask {
                id: $task.task_id,
                itype: $type,
                proof_id: $task.proof_id,
                status: $task.state as i32,
                node_info: $task.trace.node_info.clone(),
                content: Some(content),
                time_cost: ($task.trace.duration()) as i64,
                ..Default::default()
            };
            if let Err(e) = $db_pool.insert_prove_task(&prove_task).await {
                tracing::error!("save task error: {:?}", e)
            }
        }
    };
}

/// Helper function to dispatch a task to a prover client in a new tokio task.
///
/// This encapsulates the common pattern of:
/// 1. Spawning a new asynchronous task.
/// 2. Calling a specific `prover_client` function.
/// 3. Wrapping the specific result type (e.g., `ProveTask`) into the general `Task` enum.
/// 4. Sending the wrapped task back through the results channel.
///
/// # Type Parameters
/// * `T`: The specific task type (e.g., `SplitTask`, `ProveTask`).
/// * `F`: The type of the asynchronous client call function.
/// * `Fut`: The future returned by the client call.
/// * `W`: The type of the closure that wraps the result `T` into a `Task`.
fn dispatch_task<T, F, Fut, W>(
    task_payload: T,
    client_call: F,
    wrapper: W,
    tx: mpsc::Sender<Task>,
    tls_config: Option<TlsConfig>,
    cur_prover_num: Arc<tokio::sync::Mutex<u32>>,
    max_prover_num: u32,
) where
    T: Send + 'static,
    F: FnOnce(T, Option<TlsConfig>, Arc<tokio::sync::Mutex<u32>>, u32) -> Fut + Send + 'static,
    Fut: std::future::Future<Output = Option<T>> + Send,
    W: FnOnce(T) -> Task + Send + 'static,
{
    tokio::spawn(async move {
        if let Some(response_payload) =
            client_call(task_payload, tls_config, cur_prover_num, max_prover_num).await
        {
            let task_result = wrapper(response_payload);
            if let Err(e) = tx.send(task_result).await {
                error!("Failed to send task result back to main loop: {}", e);
            }
        }
    });
}

/// Handles the logic for a single-node proving task.
#[instrument(level = "info", skip_all, fields(proof_id = %task.id))]
async fn run_single_node_task(
    task: &StageTask,
    mut stage: Stage,
    tls_config: Option<TlsConfig>,
    db: &Database,
    task_start_time: std::time::Instant,
) {
    if task.step != Step::Init as i32 {
        tracing::debug!("single node task, but it has already been processed");
        return;
    }

    let single_node_task = stage.get_single_node_task();
    let mut split_task = SplitTask {
        task_id: uuid::Uuid::new_v4().to_string(),
        proof_id: single_node_task.proof_id.clone(),
        ..Default::default()
    };

    let response = prover_client::single_node(
        single_node_task,
        tls_config,
        db.clone(),
        &task.id,
        task.check_at as u64,
        get_timestamp(),
    )
    .await;

    let mut result = vec![];
    if let Ok(single_node_task) = response {
        stage.on_single_node_task(&single_node_task);
        if stage.generate_task.target_step == Step::Snark {
            result = single_node_task.output;
        }
        split_task.total_steps = single_node_task.total_cycles;
        split_task.state = TASK_STATE_SUCCESS;
    } else {
        stage.is_error = true;
        split_task.state = TASK_STATE_FAILED;
    }
    save_task!(split_task, db, TASK_ITYPE_SPLIT);

    // Finalize task status in the database
    finalize_stage_task(task, &stage, task_start_time, result, db).await;
}

#[instrument(level = "info", skip_all, fields(proof_id = %task.id))]
async fn run_stage_task(mut task: StageTask, tls_config: Option<TlsConfig>, db: Database) {
    info!("Running stage task");
    if let Some(ref context) = task.context {
        let task_decoded = serde_json::from_str::<GenerateTask>(&context);
        match task_decoded {
            Ok(generate_context) => {
                let task_start_time = std::time::Instant::now();

                let mut stage = Stage::new(generate_context.clone());

                // single node handler.
                if generate_context.single_node {
                    run_single_node_task(&task, stage, tls_config, &db, task_start_time).await;
                    return;
                }

                // Distributed (multi-node) handler
                let mut check_at = get_timestamp();
                let (tx, mut rx) = mpsc::channel(128);
                stage.dispatch();

                // update db, record the latest status and step
                let _ = db
                    .update_stage_task_check_at(
                        &task.id,
                        task.check_at as u64,
                        check_at,
                        stage.step.into(),
                    )
                    .await;
                task.check_at = check_at as i64;
                check_at = get_timestamp();

                let mut interval = time::interval(time::Duration::from_millis(200));
                let max_prover_num = stage.generate_task.max_prover_num;
                let cur_prover_num = Arc::new(tokio::sync::Mutex::new(0u32));
                let mut split_started = false;
                let mut split_rx: Option<mpsc::Receiver<SplitItem>> = None;
                let mut split_handle: Option<tokio::task::JoinHandle<()>> = None;
                loop {
                    let current_step = stage.step;
                    match stage.step {
                        Step::Prove => {
                            if !split_started {
                                if let Some(_task_payload) = stage.get_split_task() {
                                    split_started = true;
                                    let (split_tx_async, rx_tmp_async) =
                                        mpsc::channel::<SplitItem>(256);
                                    split_rx = Some(rx_tmp_async);
                                    let split_ctx = SplitContext::new(
                                        &stage.generate_task.base_dir,
                                        &stage.generate_task.program_id,
                                        &stage.generate_task.elf_path,
                                        stage.generate_task.block_no,
                                        stage.generate_task.seg_size,
                                        &stage.generate_task.seg_path,
                                        &stage.generate_task.public_input_path,
                                        &stage.generate_task.private_input_path,
                                        &stage.generate_task.output_stream_path,
                                        &stage.split_task.args,
                                        &stage.generate_task.receipt_inputs_path,
                                    );
                                    let split_handle_tmp = tokio::task::spawn_blocking(move || {
                                        let executor = Executor::default();
                                        if let Err(e) =
                                            executor.split_streaming(&split_ctx, split_tx_async.clone())
                                        {
                                            let _ = split_tx_async
                                                .blocking_send(SplitItem::Error(e.to_string()));
                                        }
                                    });
                                    split_handle = Some(split_handle_tmp);
                                }
                            }

                            // Dispatch prove tasks until the concurrent prover limit is reached.
                            while stage.count_processing_prove_tasks() < max_prover_num as usize {
                                if let Some(task_payload) = stage.get_prove_task() {
                                    dispatch_task(
                                        task_payload,
                                        prover_client::prove,
                                        Task::Prove,
                                        tx.clone(),
                                        tls_config.clone(),
                                        cur_prover_num.clone(),
                                        max_prover_num,
                                    );
                                } else {
                                    // No more prove tasks available, break the inner loop.
                                    break;
                                }
                            }

                            // Dispatch aggregate tasks if conditions are met.
                            while stage.is_tasks_gen_done
                                && stage.count_unfinished_prove_tasks() < max_prover_num as usize
                            {
                                if let Some(task_payload) = stage.get_agg_task() {
                                    tracing::debug!("get_agg_task: true");
                                    dispatch_task(
                                        task_payload,
                                        prover_client::aggregate,
                                        Task::Agg,
                                        tx.clone(),
                                        tls_config.clone(),
                                        cur_prover_num.clone(),
                                        max_prover_num,
                                    );
                                } else {
                                    // No more aggregation tasks available, break the inner loop.
                                    tracing::debug!("get_agg_task: false");
                                    break;
                                }
                            }
                        }
                        Step::Snark => {
                            if let Some(task_payload) = stage.get_snark_task() {
                                dispatch_task(
                                    task_payload,
                                    prover_client::snark_proof,
                                    Task::Snark,
                                    tx.clone(),
                                    tls_config.clone(),
                                    cur_prover_num.clone(),
                                    max_prover_num,
                                );
                            }
                        }
                        _ => {}
                    }

                    let split_fut = async {
                        if let Some(rx) = split_rx.as_mut() {
                            rx.recv().await
                        } else {
                            None
                        }
                    };
                    let split_handle_fut = async {
                        if let Some(handle) = split_handle.as_mut() {
                            if handle.is_finished() {
                                Some(handle.await)
                            } else {
                                None
                            }
                        } else {
                            None
                        }
                    };

                    tokio::select! {
                        split_res = split_fut => {
                            if let Some(item) = split_res {
                                match item {
                                    SplitItem::Segment { index, compressed } => {
                                        stage.push_split_segment(index, compressed);
                                    }
                                    SplitItem::DeferredProof { index, bytes } => {
                                        stage.push_split_deferred(index, bytes);
                                    }
                                    SplitItem::Meta {
                                        total_steps,
                                        total_segments,
                                        vk_bytes,
                                        public_values_stream,
                                    } => {
                                        let mut split_task = stage.split_task.clone();
                                        split_task.total_steps = total_steps;
                                        split_task.total_segments = total_segments;
                                        split_task.state = TASK_STATE_SUCCESS;
                                        split_task.trace.finish_ts = get_timestamp();
                                        stage.apply_split_meta(SplitMeta {
                                            total_steps,
                                            total_segments,
                                            vk_bytes,
                                            public_values_stream,
                                        });
                                        stage.split_task = split_task.clone();
                                        save_task!(split_task, db, TASK_ITYPE_SPLIT);
                                    }
                                    SplitItem::Error(msg) => {
                                        stage.is_error = true;
                                        let mut split_task = stage.split_task.clone();
                                        split_task.state = TASK_STATE_FAILED;
                                        split_task.trace.finish_ts = get_timestamp();
                                        split_task.output = msg.into_bytes();
                                        stage.split_task = split_task.clone();
                                        save_task!(split_task, db, TASK_ITYPE_SPLIT);
                                    }
                                }
                            }
                        },
                        split_join = split_handle_fut => {
                            if let Some(Err(join_err)) = split_join {
                                stage.is_error = true;
                                let mut split_task = stage.split_task.clone();
                                split_task.state = TASK_STATE_FAILED;
                                split_task.trace.finish_ts = get_timestamp();
                                split_task.output = format!("split task panic: {join_err}").into_bytes();
                                stage.split_task = split_task.clone();
                                save_task!(split_task, db, TASK_ITYPE_SPLIT);
                                split_handle = None;
                            } else if split_join.is_some() {
                                split_handle = None;
                            }
                        },
                        task = rx.recv() => {
                            if let Some(task) = task {
                                match task {
                                    Task::Split(mut data) => {
                                        stage.on_split_task(&mut data);
                                        save_task!(data, db, TASK_ITYPE_SPLIT);
                                    },
                                    Task::Prove(mut data) => {
                                        stage.on_prove_task(&mut data);
                                        // save_task!(data, db, TASK_ITYPE_PROVE);
                                    },
                                    Task::Agg(mut data) => {
                                        stage.on_agg_task(&mut data);
                                        // save_task!(data, db, TASK_ITYPE_AGG);
                                    },
                                    Task::Snark(mut data) => {
                                        stage.on_snark_task(&mut data);
                                        save_task!(data, db, TASK_ITYPE_FINAL);
                                    },
                                };
                            }
                        },
                        _ = interval.tick() => {
                        }
                    }
                    if stage.is_success() || stage.is_error() {
                        break;
                    }
                    stage.dispatch();

                    let ts_now = get_timestamp();
                    if check_at + 10 < ts_now || current_step != stage.step {
                        check_at = ts_now;
                        let rows_affected = db
                            .update_stage_task_check_at(
                                &task.id,
                                task.check_at as u64,
                                check_at,
                                stage.step.into(),
                            )
                            .await;
                        if let Ok(rows_affected) = rows_affected {
                            if rows_affected == 1 {
                                task.check_at = check_at as i64;
                            }
                        }
                    }
                }

                let result = if stage.is_success() && generate_context.target_step == Step::Snark {
                    file::new(&generate_context.snark_path)
                        .read()
                        .unwrap_or_default()
                } else {
                    vec![]
                };
                finalize_stage_task(&task, &stage, task_start_time, result, &db).await;
            }
            Err(_) => {
                let _ = db
                    .update_stage_task(
                        &task.id,
                        stage_service::v1::Status::InternalError.into(),
                        "",
                    )
                    .await;
            }
        }
    }
}

/// Updates the final status of a StageTask in the database after it has completed or failed.
async fn finalize_stage_task(
    task: &StageTask,
    stage: &Stage,
    task_start_time: std::time::Instant,
    result: Vec<u8>,
    db: &Database,
) {
    if stage.is_error() {
        let get_status = || match stage.step {
            Step::Split => stage_service::v1::Status::SplitError,
            Step::Prove => stage_service::v1::Status::ProveError,
            Step::Agg => stage_service::v1::Status::AggError,
            Step::Snark => stage_service::v1::Status::SnarkError,
            _ => stage_service::v1::Status::InternalError,
        };
        let status = get_status();
        if let Err(e) = db.update_stage_task(&task.id, status.into(), "").await {
            error!("Failed to update stage task to error status: {:?}", e);
        }
    } else if stage.is_success() {
        // Task is successful
        let task_duration = task_start_time.elapsed().as_millis() as u64;

        // update the step, and store the duration in the `check_at` field.
        if let Err(e) = db
            .update_stage_task_check_at(
                &task.id,
                task.check_at as u64,
                task_duration,
                stage.step.into(),
            )
            .await
        {
            error!("Failed to update stage task check_at on success: {:?}", e);
        }

        let result_str = String::from_utf8(result).expect("Invalid UTF-8 bytes in proof result");
        if let Err(e) = db
            .update_stage_task(
                &task.id,
                stage_service::v1::Status::Success.into(),
                &result_str,
            )
            .await
        {
            error!("Failed to update stage task to success status: {:?}", e);
        }

        info!(
            "[stage] finished {:?} total_time {} ms",
            stage, task_duration
        );
    }
}

pub struct TaskManager {
    pub db: Database,
    task_receiver: mpsc::Receiver<StageTask>,
    pub semaphore: Arc<Semaphore>,
}

impl TaskManager {
    pub fn new(
        db: Database,
        max_concurrent_tasks: Option<usize>,
    ) -> (Self, mpsc::Sender<StageTask>) {
        let max_concurrent_tasks = max_concurrent_tasks.unwrap_or(1);
        let (task_sender, task_receiver) = mpsc::channel(256);
        let semaphore = Arc::new(Semaphore::new(max_concurrent_tasks));
        (
            Self {
                db,
                task_receiver,
                semaphore,
            },
            task_sender,
        )
    }

    pub async fn process_tasks(&mut self, tls_config: Option<TlsConfig>) {
        info!("Starting task processor...");

        while let Some(task) = self.task_receiver.recv().await {
            let permit = self.semaphore.clone().acquire_owned().await.unwrap();

            let tls_clone = tls_config.clone();
            let db = self.db.clone();
            tokio::spawn(async move {
                run_stage_task(task, tls_clone, db).await;
                drop(permit);
            });
        }
    }

    pub fn start(mut self, tls: Option<TlsConfig>) {
        tokio::spawn(async move { self.process_tasks(tls).await });
    }

    pub async fn load_incomplete_tasks_from_db(
        &self,
        task_sender: mpsc::Sender<StageTask>,
    ) -> anyhow::Result<mpsc::Sender<StageTask>> {
        info!("Loading incomplete tasks from database...");

        let tasks = self
            .db
            .get_incomplete_stage_tasks(
                stage_service::v1::Status::Computing.into(),
                get_timestamp() as i64,
                i32::MAX,
            )
            .await
            .context("Failed to load incomplete tasks from database")?;

        info!("Found {} incomplete tasks", tasks.len());

        let mut loaded_count = 0;
        for task in tasks {
            match task_sender.try_send(task) {
                Ok(()) => loaded_count += 1,
                Err(mpsc::error::TrySendError::Full(_)) => {
                    warn!("Task queue is full, stopping load");
                    break;
                }
                Err(mpsc::error::TrySendError::Closed(_)) => {
                    error!("Task queue is closed");
                    break;
                }
            }
        }
        info!("Loaded {loaded_count} tasks to memory queue");

        Ok(task_sender)
    }
}
