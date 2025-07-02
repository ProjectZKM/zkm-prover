use crate::proto::prover_service::v1::{
    prover_service_client::ProverServiceClient, AggregateRequest, GetTaskResultRequest,
    GetTaskResultResponse, ProveRequest, ResultCode, SnarkProofRequest, SplitElfRequest,
    SingleNodeRequest,
};
use common::tls::Config as TlsConfig;
use std::sync::{Arc, Mutex};

use crate::stage::tasks::{AggTask, ProveTask, SingleNodeTask, SnarkTask, SplitTask, TASK_STATE_FAILED, TASK_STATE_PROCESSING, TASK_STATE_SUCCESS, TASK_STATE_UNPROCESSED, TASK_TIMEOUT};
use tonic::Request;

use crate::prover_node::{NodeStatus, ProverNode};
use crate::stage::stage::get_timestamp;
use rand::rngs::StdRng;
use rand::seq::SliceRandom;
use rand::SeedableRng;
use std::time::Duration;
use tonic::transport::Channel;

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
enum TaskType {
    Split,
    Prove,
    Agg,
    Snark,
    SingleNode,
}

fn get_nodes(task_type: TaskType) -> Vec<ProverNode> {
    let nodes_data = crate::prover_node::instance().lock().unwrap();

    match task_type {
        TaskType::Snark => nodes_data.get_snark_nodes(),
        TaskType::Prove => {
            let all_nodes = nodes_data.get_nodes();
            let nodes_num = std::env::var("PROVE_NODES_NUM")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(all_nodes.len());
            all_nodes.into_iter().take(nodes_num).collect()
        }
        _ => nodes_data.get_nodes(),
    }
}

async fn get_idle_client(
    tls_config: Option<TlsConfig>,
    task_type: TaskType,
) -> Option<(String, ProverServiceClient<Channel>, Arc<Mutex<NodeStatus>>)> {
    let mut nodes = get_nodes(task_type);
    let mut rng = StdRng::from_entropy();
    nodes.shuffle(&mut rng);

    for mut node in nodes {
        {
            let mut status = node.status.lock().unwrap();
            if *status == NodeStatus::Busy {
                continue;
            }
            if status.is_offline() {
                // If the node is offline for less than 180s, we skip it.
                if let Some(ts) = status.offline_since() {
                    if ts + 180 > get_timestamp() {
                        continue;
                    }
                }
                // unset the client if it was offline more than 180s, and will reconnect later
                *node.client.lock().unwrap() = None;
            }

            *status = NodeStatus::Busy;
        }

        if let Some(client) = node.is_active(tls_config.clone()).await {
            return Some((node.addr.clone(), client, node.status.clone()));
        } else {
            {
                let mut status = node.status.lock().unwrap();
                *status = NodeStatus::OffLine(get_timestamp());
            }

            tracing::warn!(
                "Node {} is unreachable, marked Offline to avoid reuse",
                node.addr
            );
        }
    }
    // tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
    None
}

pub fn result_code_to_state(code: i32) -> u32 {
    match ResultCode::from_i32(code) {
        Some(ResultCode::Unspecified) => TASK_STATE_PROCESSING,
        Some(ResultCode::Ok) => TASK_STATE_SUCCESS,
        Some(ResultCode::InternalError) => TASK_STATE_FAILED,
        Some(ResultCode::Busy) => TASK_STATE_UNPROCESSED,
        _ => TASK_STATE_FAILED,
    }
}

pub async fn split(
    mut split_task: SplitTask,
    tls_config: Option<TlsConfig>,
    cur_prover_num: Arc<tokio::sync::Mutex<u32>>,
    max_prover_num: u32,
) -> Option<SplitTask> {
    split_task.state = TASK_STATE_UNPROCESSED;
    // check if the number of current prover nodes is less than max_prover_num
    {
        let count = cur_prover_num.lock().await;
        if *count >= max_prover_num {
            return Some(split_task);
        }
    }
    let client = get_idle_client(tls_config, TaskType::Split).await;
    if let Some((addrs, mut client, node_status)) = client {
        {
            // after getting an idle client, we can check the current prover number again
            let mut count = cur_prover_num.lock().await;
            tracing::debug!(
                "[before]: current prover num: {}, max prover num: {}",
                *count,
                max_prover_num
            );
            if *count >= max_prover_num {
                // cannot run more than max_prover_num nodes at the same time.
                // set the node status to Idle, so it can be reused later
                let mut status = node_status.lock().unwrap();
                *status = NodeStatus::Idle;
                return Some(split_task);
            }
            *count += 1;
        }
        let request = SplitElfRequest {
            proof_id: split_task.proof_id.clone(),
            computed_request_id: split_task.task_id.clone(),
            elf_path: split_task.elf_path.clone(),
            base_dir: split_task.base_dir.clone(),
            seg_path: split_task.seg_path.clone(),
            public_input_path: split_task.public_input_path.clone(),
            private_input_path: split_task.private_input_path.clone(),
            output_path: split_task.output_path.clone(),
            args: split_task.args.clone(),
            block_no: split_task.block_no,
            seg_size: split_task.seg_size,
            receipt_inputs_path: split_task.recepit_inputs_path.clone(),
            program_id: split_task.program_id.clone(),
        };
        tracing::info!(
            "[split] rpc {} {}:{} start",
            addrs,
            request.proof_id,
            request.computed_request_id
        );
        let now = std::time::Instant::now();
        let mut grpc_request = Request::new(request);
        grpc_request.set_timeout(Duration::from_secs(TASK_TIMEOUT));
        let response = client.split_elf(grpc_request).await;
        {
            // Decrease the current prover number.
            let mut count = cur_prover_num.lock().await;
            tracing::debug!(
                "[after]: current prover num: {}, max prover num: {}",
                *count,
                max_prover_num
            );
            *count -= 1;
        }
        let mut status = node_status.lock().unwrap();
        if let Ok(response) = response {
            *status = NodeStatus::Idle;
            if let Some(response_result) = response.get_ref().result.as_ref() {
                split_task.state = result_code_to_state(response_result.code);
                // FIXME: node_info usage?
                split_task.trace.node_info = addrs.clone();
                split_task.total_steps = response.get_ref().total_steps;
                split_task.total_segments = response.get_ref().total_segments;
                tracing::info!(
                    "[split] rpc {} {}:{} code:{:?} message:{:?} end. Elapsed {:?}, {} cycles, {} segments",
                    addrs,
                    response.get_ref().proof_id,
                    response.get_ref().computed_request_id,
                    response_result.code,
                    response_result.message,
                    now.elapsed(),
                    split_task.total_steps,
                    split_task.total_segments,
                );
                return Some(split_task);
            }
        } else {
            *status = NodeStatus::OffLine(get_timestamp());
            tracing::warn!(
                "Node {} is unreachable, marked Offline to avoid reuse",
                addrs
            );
        }
    }
    tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
    Some(split_task)
}

pub async fn prove(
    mut prove_task: ProveTask,
    tls_config: Option<TlsConfig>,
    cur_prover_num: Arc<tokio::sync::Mutex<u32>>,
    max_prover_num: u32,
) -> Option<ProveTask> {
    prove_task.state = TASK_STATE_UNPROCESSED;
    // check if the number of current prover nodes is less than max_prover_num
    {
        let count = cur_prover_num.lock().await;
        if *count >= max_prover_num {
            return Some(prove_task);
        }
    }
    let client = get_idle_client(tls_config, TaskType::Prove).await;
    if let Some((addrs, mut client, node_status)) = client {
        {
            // after getting an idle client, we can check the current prover number again
            let mut count = cur_prover_num.lock().await;
            tracing::debug!(
                "[before]: current prover num: {}, max prover num: {}",
                *count,
                max_prover_num
            );
            if *count >= max_prover_num {
                // cannot run more than max_prover_num nodes at the same time.
                // set the node status to Idle, so it can be reused later
                let mut status = node_status.lock().unwrap();
                *status = NodeStatus::Idle;
                return Some(prove_task);
            }
            *count += 1;
        }
        if prove_task.trace.node_info == addrs {
            // If the task is already failed and the node is the same, skip it
            let mut status = node_status.lock().unwrap();
            *status = NodeStatus::Idle;
            return Some(prove_task);
        }
        let request = ProveRequest {
            proof_id: prove_task.program.proof_id.clone(),
            computed_request_id: prove_task.task_id.clone(),
            program_id: prove_task.program_id.clone(),
            segment: prove_task.segment.clone(),
            block_no: prove_task.program.block_no,
            seg_size: prove_task.program.seg_size,
            elf_path: prove_task.program.elf_path.clone(),
            receipts_input: prove_task.program.receipts.clone(),
            index: prove_task.file_no as u32,
        };
        tracing::info!(
            "[prove] rpc {} {}:{}:{} start",
            addrs,
            request.proof_id,
            request.computed_request_id,
            request.index
        );
        let now = std::time::Instant::now();
        let mut grpc_request = Request::new(request);
        grpc_request.set_timeout(Duration::from_secs(TASK_TIMEOUT));
        let response = client.prove(grpc_request).await;
        {
            // Decrease the current prover number.
            let mut count = cur_prover_num.lock().await;
            tracing::debug!(
                "[after]: current prover num: {}, max prover num: {}",
                *count,
                max_prover_num
            );
            *count -= 1;
        }
        let mut status = node_status.lock().unwrap();
        if let Ok(response) = response {
            *status = NodeStatus::Idle;
            if let Some(response_result) = response.get_ref().result.as_ref() {
                prove_task.state = result_code_to_state(response_result.code);
                prove_task.trace.node_info = addrs.clone();
                tracing::info!(
                    "[prove] rpc {} {}:{}:{} code:{:?} message:{:?} end, elapsed {:?}",
                    addrs,
                    response.get_ref().proof_id,
                    response.get_ref().computed_request_id,
                    prove_task.file_no,
                    response_result.code,
                    response_result.message,
                    now.elapsed(),
                );
                prove_task.output = response.get_ref().output_receipt.clone();
                return Some(prove_task);
            }
        } else {
            *status = NodeStatus::OffLine(get_timestamp());
            tracing::warn!(
                "Node {} is unreachable, marked Offline to avoid reuse",
                addrs
            );
        }
    }
    // tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
    Some(prove_task)
}

pub async fn aggregate(
    mut agg_task: AggTask,
    tls_config: Option<TlsConfig>,
    cur_prover_num: Arc<tokio::sync::Mutex<u32>>,
    max_prover_num: u32,
) -> Option<AggTask> {
    agg_task.state = TASK_STATE_UNPROCESSED;
    // check if the number of current prover nodes is less than max_prover_num
    {
        let count = cur_prover_num.lock().await;
        if *count >= max_prover_num {
            return Some(agg_task);
        }
    }
    let client = get_idle_client(tls_config, TaskType::Agg).await;
    if let Some((addrs, mut client, node_status)) = client {
        {
            // after getting an idle client, we can check the current prover number again
            let mut count = cur_prover_num.lock().await;
            tracing::debug!(
                "[before]: current prover num: {}, max prover num: {}",
                *count,
                max_prover_num
            );
            if *count >= max_prover_num {
                // cannot run more than max_prover_num nodes at the same time.
                // set the node status to Idle, so it can be reused later
                let mut status = node_status.lock().unwrap();
                *status = NodeStatus::Idle;
                return Some(agg_task);
            }
            *count += 1;
        }
        let request = AggregateRequest {
            proof_id: agg_task.proof_id.clone(),
            computed_request_id: agg_task.task_id.clone(),
            block_no: agg_task.block_no,
            seg_size: agg_task.seg_size,
            vk: agg_task.vk.clone(),
            inputs: agg_task.inputs.clone(),
            is_final: agg_task.is_final,
            is_first_shard: agg_task.is_first_shard,
            is_leaf_layer: agg_task.is_leaf_layer,
            is_deferred: agg_task.is_deferred,
        };
        tracing::info!(
            "[aggregate] rpc {} {}:{}:{} {} inputs start",
            addrs,
            request.proof_id,
            request.computed_request_id,
            agg_task.agg_index,
            request.inputs.len()
        );
        let now = std::time::Instant::now();
        let mut grpc_request = Request::new(request);
        grpc_request.set_timeout(Duration::from_secs(TASK_TIMEOUT));
        let response = client.aggregate(grpc_request).await;
        {
            // Decrease the current prover number.
            let mut count = cur_prover_num.lock().await;
            tracing::debug!(
                "[after]: current prover num: {}, max prover num: {}",
                *count,
                max_prover_num
            );
            *count -= 1;
        }
        let mut status = node_status.lock().unwrap();
        if let Ok(response) = response {
            *status = NodeStatus::Idle;
            if let Some(response_result) = response.get_ref().result.as_ref() {
                agg_task.state = result_code_to_state(response_result.code);
                agg_task.trace.node_info = addrs.clone();
                tracing::info!(
                    "[aggregate] rpc {} {}:{}:{} code:{:?} message:{:?} end, elapsed {:?}",
                    addrs,
                    response.get_ref().proof_id,
                    response.get_ref().computed_request_id,
                    agg_task.agg_index,
                    response_result.code,
                    response_result.message,
                    now.elapsed(),
                );
                agg_task.output = response.get_ref().agg_receipt.clone();
                return Some(agg_task);
            }
        } else {
            *status = NodeStatus::OffLine(get_timestamp());
            tracing::warn!(
                "Node {} is unreachable, marked Offline to avoid reuse",
                addrs
            );
        }
    }
    // tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
    Some(agg_task)
}
pub async fn snark_proof(
    mut snark_task: SnarkTask,
    tls_config: Option<TlsConfig>,
    cur_prover_num: Arc<tokio::sync::Mutex<u32>>,
    max_prover_num: u32,
) -> Option<SnarkTask> {
    // check if the number of current prover nodes is less than max_prover_num
    {
        let count = cur_prover_num.lock().await;
        if *count >= max_prover_num {
            return Some(snark_task);
        }
    }
    let client = get_idle_client(tls_config, TaskType::Snark).await;
    if let Some((addrs, mut client, node_status)) = client {
        {
            // after getting an idle client, we can check the current prover number again
            let mut count = cur_prover_num.lock().await;
            tracing::debug!(
                "[before]: current prover num: {}, max prover num: {}",
                *count,
                max_prover_num
            );
            if *count >= max_prover_num {
                // cannot run more than max_prover_num nodes at the same time.
                // set the node status to Idle, so it can be reused later
                let mut status = node_status.lock().unwrap();
                *status = NodeStatus::Idle;
                return Some(snark_task);
            }
            *count += 1;
        }
        let request = SnarkProofRequest {
            version: snark_task.version,
            proof_id: snark_task.proof_id.clone(),
            computed_request_id: snark_task.task_id.clone(),
            agg_receipt: snark_task.agg_receipt.clone(),
            from_input: snark_task.from_input,
        };
        tracing::info!(
            "[snark_proof] rpc {} {}:{} start",
            addrs,
            request.proof_id,
            request.computed_request_id,
        );
        let mut grpc_request = Request::new(request);
        grpc_request.set_timeout(Duration::from_secs(TASK_TIMEOUT));
        let response = client.snark_proof(grpc_request).await;
        {
            // Decrease the current prover number.
            let mut count = cur_prover_num.lock().await;
            tracing::debug!(
                "[after]: current prover num: {}, max prover num: {}",
                *count,
                max_prover_num
            );
            *count -= 1;
        }
        let mut status = node_status.lock().unwrap();
        if let Ok(response) = response {
            *status = NodeStatus::Idle;
            if let Some(response_result) = response.get_ref().result.as_ref() {
                if ResultCode::from_i32(response_result.code) == Some(ResultCode::Ok) {
                    tracing::info!(
                        "[snark_proof] rpc {} {}:{}  code:{:?} message:{:?}",
                        addrs,
                        response.get_ref().proof_id,
                        response.get_ref().computed_request_id,
                        response_result.code,
                        response_result.message,
                    );
                    snark_task.state = TASK_STATE_SUCCESS;
                    snark_task.trace.node_info = addrs;
                    snark_task.output = response.get_ref().snark_proof_with_public_inputs.clone();
                    return Some(snark_task);
                }
            }
        } else {
            *status = NodeStatus::OffLine(get_timestamp());
            tracing::warn!(
                "Node {} is unreachable, marked Offline to avoid reuse",
                addrs
            );
        }
        snark_task.state = TASK_STATE_FAILED;
    } else {
        snark_task.state = TASK_STATE_UNPROCESSED;
    }
    // tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
    Some(snark_task)
}

pub async fn single_node(mut single_node_task: SingleNodeTask, tls_config: Option<TlsConfig>) -> Option<SingleNodeTask> {
    single_node_task.state = TASK_STATE_UNPROCESSED;
    let client = get_idle_client(tls_config, TaskType::SingleNode).await;
    if let Some((addrs, mut client, node_status)) = client {
        let request = SingleNodeRequest {
            proof_id: single_node_task.proof_id.clone(),
            computed_request_id: single_node_task.task_id.clone(),
            elf_path: single_node_task.elf_path.clone(),
            base_dir: single_node_task.base_dir.clone(),
            public_input_path: single_node_task.public_input_path.clone(),
            private_input_path: single_node_task.private_input_path.clone(),
            args: single_node_task.args.clone(),
            block_no: single_node_task.block_no,
            receipt_inputs_path: single_node_task.receipt_inputs_path.clone(),
            program_id: single_node_task.program_id.clone(),
        };
        tracing::info!(
            "[single node] rpc {} {}:{} start",
            addrs,
            request.proof_id,
            request.computed_request_id
        );
        let now = std::time::Instant::now();
        let mut grpc_request = Request::new(request);
        grpc_request.set_timeout(Duration::from_secs(TASK_TIMEOUT));
        let response = client.single_node(grpc_request).await;
        let mut status = node_status.lock().unwrap();
        if let Ok(response) = response {
            *status = NodeStatus::Idle;
            if let Some(response_result) = response.get_ref().result.as_ref() {
                single_node_task.state = result_code_to_state(response_result.code);
                // FIXME: node_info usage?
                single_node_task.trace.node_info = addrs.clone();
                single_node_task.output = response.get_ref().agg_receipt.clone();
                
                tracing::info!(
                    "[single node] rpc {} {}:{} code:{:?} message:{:?} end. Elapsed {:?}",
                    addrs,
                    response.get_ref().proof_id,
                    response.get_ref().computed_request_id,
                    response_result.code,
                    response_result.message,
                    now.elapsed(),
                );
                return Some(single_node_task);
            }
        } else {
            *status = NodeStatus::OffLine(get_timestamp());
            tracing::warn!(
                "Node {} is unreachable, marked Offline to avoid reuse",
                addrs
            );
        }
    }
    tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
    Some(single_node_task)
    
}

#[allow(dead_code)]
pub async fn get_task_status(
    client: &mut ProverServiceClient<Channel>,
    proof_id: &str,
    task_id: &str,
) -> Option<ResultCode> {
    let request = GetTaskResultRequest {
        proof_id: proof_id.to_owned(),
        computed_request_id: task_id.to_owned(),
    };
    let mut grpc_request = Request::new(request);
    grpc_request.set_timeout(Duration::from_secs(TASK_TIMEOUT));
    let response = client.get_task_result(grpc_request).await;
    if let Ok(response) = response {
        if let Some(response_result) = response.get_ref().result.as_ref() {
            return ResultCode::from_i32(response_result.code);
        }
    }
    Some(ResultCode::Unspecified)
}

pub async fn get_task_result(
    client: &mut ProverServiceClient<Channel>,
    proof_id: &str,
    task_id: &str,
) -> Option<GetTaskResultResponse> {
    let request = GetTaskResultRequest {
        proof_id: proof_id.to_owned(),
        computed_request_id: task_id.to_owned(),
    };
    let mut grpc_request = Request::new(request);
    grpc_request.set_timeout(Duration::from_secs(30));
    let response = client.get_task_result(grpc_request).await;
    if let Ok(response) = response {
        return Some(response.into_inner());
    }
    None
}
