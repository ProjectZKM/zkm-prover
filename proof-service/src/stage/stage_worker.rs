use crate::database;
use crate::database::{Database, StageTask};
use crate::proto::includes::v1::Step;
use crate::proto::stage_service;
use crate::prover_client;
use crate::stage::{
    stage::get_timestamp,
    stage::Stage,
    tasks::{Task, TASK_ITYPE_FINAL, TASK_ITYPE_SPLIT, TASK_STATE_FAILED, TASK_STATE_SUCCESS},
    GenerateTask,
};
use crate::TlsConfig;
use anyhow::Context;
use common::file;
// use std::collections::HashMap;
use std::sync::Arc;
// use std::sync::Mutex;
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

#[instrument(level = "info", skip_all, fields(proof_id = %task.id))]
async fn run_stage_task(mut task: StageTask, tls_config: Option<TlsConfig>, db: Database) {
    info!("Running stage task");
    if let Some(context) = task.context {
        let task_decoded = serde_json::from_str::<GenerateTask>(&context);
        match task_decoded {
            Ok(generate_context) => {
                let mut check_at = get_timestamp();
                let mut stage = Stage::new(generate_context.clone());
                tracing::debug!(
                    "[single_node]: task_id: {:?}, status: {:?}, step: {:?}",
                    task.id,
                    task.status,
                    task.step
                );
                // single node handler.
                if generate_context.single_node {
                    if task.step != Step::Init as i32 {
                        tracing::debug!("single node task, but it has already been processed");
                        return;
                    }
                    stage.step = Step::Prove;
                    // update status in the db in order to help client get status response
                    db.update_stage_task_check_at(
                        &task.id,
                        task.check_at as u64,
                        check_at,
                        stage.step.into(),
                    )
                    .await
                    .unwrap();

                    // get single_node task
                    let single_node_task = stage.get_single_node_task();
                    let tls_config = tls_config.clone();
                    let response = prover_client::single_node(single_node_task, tls_config).await;
                    let mut result = vec![];
                    if let Some(single_node_task) = response {
                        // handle the response
                        stage.on_single_node_task(&single_node_task);
                        if stage.generate_task.target_step == Step::Snark {
                            result = single_node_task.output;
                        }
                    }
                    if stage.is_error() {
                        tracing::debug!("error in single node task");
                        let status = stage_service::v1::Status::InternalError;
                        db.update_stage_task(&task.id, status.into(), "")
                            .await
                            .unwrap();
                    } else {
                        tracing::debug!("success in single node task");
                        // update the step
                        db.update_stage_task_check_at(
                            &task.id,
                            task.check_at as u64,
                            check_at,
                            stage.step.into(),
                        )
                        .await
                        .unwrap();
                        // update task
                        db.update_stage_task(
                            &task.id,
                            stage_service::v1::Status::Success.into(),
                            &String::from_utf8(result).expect("Invalid UTF-8 bytes"),
                        )
                        .await
                        .unwrap();
                    }
                    return;
                }

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
                loop {
                    let current_step = stage.step;
                    match stage.step {
                        Step::Prove => {
                            let split_task = stage.get_split_task();
                            if let Some(split_task) = split_task {
                                let tx = tx.clone();
                                let tls_config = tls_config.clone();
                                let cur_count = cur_prover_num.clone();
                                tokio::spawn(async move {
                                    let response = prover_client::split(
                                        split_task,
                                        tls_config,
                                        cur_count,
                                        max_prover_num,
                                    )
                                    .await;
                                    if let Some(split_task) = response {
                                        let _ = tx.send(Task::Split(split_task)).await;
                                    }
                                });
                            }
                            // This is a temporary workaround.
                            if stage.count_processing_prove_tasks() < max_prover_num as usize {
                                if let Some(prove_task) = stage.get_prove_task() {
                                    let tx = tx.clone();
                                    let tls_config = tls_config.clone();
                                    let cur_count = cur_prover_num.clone();
                                    tokio::spawn(async move {
                                        let response = prover_client::prove(
                                            prove_task,
                                            tls_config,
                                            cur_count,
                                            max_prover_num,
                                        )
                                        .await;
                                        if let Some(prove_task) = response {
                                            let _ = tx.send(Task::Prove(prove_task)).await;
                                        }
                                    });
                                }
                            }

                            if stage.is_tasks_gen_done
                                && stage.count_unfinished_prove_tasks() < max_prover_num as usize
                            {
                                let agg_task = stage.get_agg_task();
                                tracing::debug!("get_agg_task: {:?}", agg_task.is_some());
                                if let Some(agg_task) = agg_task {
                                    let tx = tx.clone();
                                    let tls_config = tls_config.clone();
                                    let cur_count = cur_prover_num.clone();
                                    tokio::spawn(async move {
                                        let response = prover_client::aggregate(
                                            agg_task,
                                            tls_config,
                                            cur_count,
                                            max_prover_num,
                                        )
                                        .await;
                                        if let Some(agg_task) = response {
                                            let _ = tx.send(Task::Agg(agg_task)).await;
                                        }
                                    });
                                }
                            }
                        }
                        Step::Snark => {
                            let snark_task = stage.get_snark_task();
                            if let Some(snark_task) = snark_task {
                                let tx = tx.clone();
                                let tls_config = tls_config.clone();
                                let cur_count = cur_prover_num.clone();
                                tokio::spawn(async move {
                                    let response = prover_client::snark_proof(
                                        snark_task,
                                        tls_config,
                                        cur_count,
                                        max_prover_num,
                                    )
                                    .await;
                                    if let Some(snark_task) = response {
                                        let _ = tx.send(Task::Snark(snark_task)).await;
                                    }
                                });
                            }
                        }
                        _ => {}
                    }
                    tokio::select! {
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
                if stage.is_error() {
                    let get_status = || match stage.step {
                        Step::Split => stage_service::v1::Status::SplitError,
                        Step::Prove => stage_service::v1::Status::ProveError,
                        Step::Agg => stage_service::v1::Status::AggError,
                        Step::Snark => stage_service::v1::Status::SnarkError,
                        _ => stage_service::v1::Status::InternalError,
                    };
                    let status = get_status();
                    db.update_stage_task(&task.id, status.into(), "")
                        .await
                        .unwrap();
                } else {
                    // If generate compressed proof, do not store in database, use file instead.
                    let result = if generate_context.target_step == Step::Snark {
                        file::new(&generate_context.snark_path).read().unwrap()
                    } else {
                        vec![]
                    };
                    db.update_stage_task(
                        &task.id,
                        stage_service::v1::Status::Success.into(),
                        &String::from_utf8(result).expect("Invalid UTF-8 bytes"),
                    )
                    .await
                    .unwrap();
                    info!("[stage] finished {:?} ", stage);
                }
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
