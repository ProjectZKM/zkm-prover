use std::sync::{Arc, Mutex};
use std::time::Instant;
use tonic::{Request, Response, Status};

use crate::proto::includes::v1::ProverVersion;
use crate::proto::prover_service::v1::{
    prover_service_server::ProverService, AggregateRequest, AggregateResponse, GetStatusRequest,
    GetStatusResponse, GetTaskResultRequest, GetTaskResultResponse, ProveRequest, ProveResponse,
    Result, ResultCode, SnarkProofRequest, SnarkProofResponse, SplitElfRequest, SplitElfResponse,
    get_status_response, SingleNodeRequest, SingleNodeResponse,
};
use crate::{config, metrics};
#[cfg(feature = "prover")]
use prover::{
    contexts::{AggContext, ProveContext, SnarkContext},
    executor::SplitContext,
    pipeline::Pipeline,
};
#[cfg(feature = "prover_v2")]
use prover_v2::{
    contexts::{AggContext, ProveContext, SnarkContext, SplitContext, SingleNodeContext},
    pipeline::Pipeline,
};

async fn run_back_task<
    T: Send + 'static,
    F: FnOnce() -> std::result::Result<T, String> + Send + 'static,
>(
    callable: F,
) -> std::result::Result<T, String> {
    let rt = tokio::runtime::Handle::current();
    let (tx, rx) = tokio::sync::oneshot::channel();
    let _ = rt
        .spawn_blocking(move || {
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(callable));
            let _ = tx.send(result);
        })
        .await;

    rx.await.unwrap().unwrap_or_else(|e| {
        let panic_message = if let Some(msg) = e.downcast_ref::<&str>() {
            msg.to_string()
        } else if let Some(msg) = e.downcast_ref::<String>() {
            msg.clone()
        } else {
            "Unknown panic".to_string()
        };

        tracing::error!("Task panicked: {}", panic_message);
        Err(panic_message) // Convert into a boxed error
    })
}

#[derive(Default)]
pub struct ProverServiceSVC {
    pub config: config::RuntimeConfig,
    pipeline: Arc<Pipeline>,
}
impl ProverServiceSVC {
    pub fn new(config: config::RuntimeConfig) -> Self {
        let version = if cfg!(feature = "prover") {
            ProverVersion::Zkm
        } else if cfg!(feature = "prover_v2") {
            ProverVersion::Zkm2
        } else {
            panic!("Not supported prover version");
        };
        let pipeline = Arc::new(Pipeline::new(
            &config.base_dir,
            &config.get_proving_key_path(version.into()),
        ));
        Self { config, pipeline }
    }
}

macro_rules! on_done {
    ($result:ident, $resp:ident) => {
        match $result {
            Ok((done, _data)) => {
                if done {
                    $resp.result = Some(Result {
                        code: (ResultCode::Ok.into()),
                        message: "SUCCESS".to_string(),
                    });
                } else {
                    $resp.result = Some(Result {
                        code: (ResultCode::Busy.into()),
                        message: ("BUSY".to_string()),
                    });
                }
            }
            Err(e) => {
                $resp.result = Some(Result {
                    code: (ResultCode::InternalError.into()),
                    message: (e.to_string()),
                });
            }
        }
    };
}

#[tonic::async_trait]
impl ProverService for ProverServiceSVC {
    async fn get_status(
        &self,
        _request: Request<GetStatusRequest>,
    ) -> tonic::Result<Response<GetStatusResponse>, Status> {
        metrics::record_metrics("prover::get_status", || async {
            // tracing::info!("{:#?}", request);
            let response = GetStatusResponse::default();
            Ok(Response::new(response))
        })
        .await
    }

    async fn get_task_result(
        &self,
        _request: Request<GetTaskResultRequest>,
    ) -> tonic::Result<Response<GetTaskResultResponse>, Status> {
        metrics::record_metrics("prover::get_task_result", || async {
            // tracing::info!("{:#?}", request);
            let response = GetTaskResultResponse::default();
            Ok(Response::new(response))
        })
        .await
    }

    async fn split_elf(
        &self,
        request: Request<SplitElfRequest>,
    ) -> tonic::Result<Response<SplitElfResponse>, Status> {
        metrics::record_metrics("prover::split_elf", || async {
            tracing::info!(
                "[split_elf] {}:{} start",
                request.get_ref().proof_id,
                request.get_ref().computed_request_id,
            );
            let start = Instant::now();
            let split_context = SplitContext::new(
                &request.get_ref().base_dir,
                &request.get_ref().program_id,
                &request.get_ref().elf_path,
                request.get_ref().block_no,
                request.get_ref().seg_size,
                &request.get_ref().seg_path,
                &request.get_ref().public_input_path,
                &request.get_ref().private_input_path,
                &request.get_ref().output_path,
                &request.get_ref().args,
                &request.get_ref().receipt_inputs_path,
            );

            let pipeline = self.pipeline.clone();
            let split_func = move || pipeline.split(&split_context);
            let result = run_back_task(split_func).await;

            let mut response = SplitElfResponse {
                proof_id: request.get_ref().proof_id.clone(),
                computed_request_id: request.get_ref().computed_request_id.clone(),
                total_steps: result.clone().unwrap_or_default().1,
                total_segments: result.clone().unwrap_or_default().2,
                ..Default::default()
            };
            // True if and only if no error occurs and ELF size > 0
            let result: std::result::Result<(bool, Vec<u8>), String> = match result {
                Ok(cycle) => Ok((cycle.1 > 0 && cycle.0, vec![])),
                Err(e) => Err(e),
            };
            on_done!(result, response);
            let end = Instant::now();
            let elapsed = end.duration_since(start);
            tracing::info!(
                "[split_elf] {}:{} code:{} elapsed:{} end. Total cycles {}, segments {}",
                request.get_ref().proof_id,
                request.get_ref().computed_request_id,
                response.result.as_ref().unwrap().code,
                elapsed.as_secs(),
                response.total_steps,
                response.total_segments
            );
            Ok(Response::new(response))
        })
        .await
    }

    async fn prove(
        &self,
        request: Request<ProveRequest>,
    ) -> tonic::Result<Response<ProveResponse>, Status> {
        metrics::record_metrics("prover::prove", || async {
            tracing::info!(
                "[prove] {}:{} start",
                request.get_ref().proof_id,
                request.get_ref().computed_request_id,
                //request.get_ref().seg_path,
            );
            let start = Instant::now();
            #[cfg(feature = "prover")]
            let prove_context = ProveContext::new(
                request.get_ref().block_no,
                request.get_ref().seg_size,
                &request.get_ref().segment,
                &request.get_ref().receipts_input,
            );
            #[cfg(feature = "prover_v2")]
            let prove_context = ProveContext {
                proof_id: request.get_ref().proof_id.clone(),
                program_id: request.get_ref().program_id.clone(),
                index: request.get_ref().index as usize,
                elf_path: request.get_ref().elf_path.clone(),
                segment: request.get_ref().segment.clone(),
                seg_size: request.get_ref().seg_size,
            };

            let pipeline = self.pipeline.clone();
            let prove_func = move || pipeline.prove_root(&prove_context);
            let result = run_back_task(prove_func).await;

            let mut response = ProveResponse {
                proof_id: request.get_ref().proof_id.clone(),
                computed_request_id: request.get_ref().computed_request_id.clone(),
                output_receipt: match &result {
                    Ok((_, x)) => x.clone(),
                    _ => vec![],
                },
                ..Default::default()
            };
            on_done!(result, response);
            let end = Instant::now();
            let elapsed = end.duration_since(start);
            tracing::info!(
                "[prove] {}:{} code:{} elapsed:{} end",
                request.get_ref().proof_id,
                request.get_ref().computed_request_id,
                response.result.as_ref().unwrap().code,
                elapsed.as_secs()
            );
            Ok(Response::new(response))
        })
        .await
    }

    async fn aggregate(
        &self,
        request: Request<AggregateRequest>,
    ) -> tonic::Result<Response<AggregateResponse>, Status> {
        metrics::record_metrics("prover::aggregate", || async {
            tracing::info!(
                "[aggregate] {}:{} {} inputs start",
                request.get_ref().proof_id,
                request.get_ref().computed_request_id,
                request.get_ref().inputs.len()
            );
            let start = Instant::now();
            #[cfg(feature = "prover")]
            let agg_context = {
                let inputs = request.get_ref().inputs.clone();
                AggContext::new(
                    request.get_ref().seg_size,
                    &inputs[0].receipt_input,
                    &inputs[1].receipt_input,
                    inputs[0].is_agg,
                    inputs[1].is_agg,
                    request.get_ref().is_final,
                )
            };
            #[cfg(feature = "prover_v2")]
            let agg_context = AggContext {
                vk: request.get_ref().vk.clone(),
                proofs: request
                    .get_ref()
                    .inputs
                    .iter()
                    .map(|input| input.receipt_input.clone())
                    .collect(),
                is_complete: request.get_ref().is_final,
                is_first_shard: request.get_ref().is_first_shard,
                is_leaf_layer: request.get_ref().is_leaf_layer,
                is_deferred: request.get_ref().is_deferred,
            };

            let pipeline = self.pipeline.clone();
            let agg_func = move || pipeline.prove_aggregate(&agg_context);
            let result = run_back_task(agg_func).await;

            let mut response = AggregateResponse {
                proof_id: request.get_ref().proof_id.clone(),
                computed_request_id: request.get_ref().computed_request_id.clone(),
                agg_receipt: match &result {
                    Ok((_, x)) => x.clone(),
                    _ => vec![],
                },
                ..Default::default()
            };
            on_done!(result, response);
            let end = Instant::now();
            let elapsed = end.duration_since(start);
            tracing::info!(
                "[aggregate] {}:{} code:{} elapsed:{} end",
                request.get_ref().proof_id,
                request.get_ref().computed_request_id,
                response.result.as_ref().unwrap().code,
                elapsed.as_secs()
            );
            Ok(Response::new(response))
        })
        .await
    }

    async fn snark_proof(
        &self,
        request: Request<SnarkProofRequest>,
    ) -> tonic::Result<Response<SnarkProofResponse>, Status> {
        metrics::record_metrics("prover::snark_proof", || async {
            tracing::info!(
                "[snark_proof] {}:{} start",
                request.get_ref().proof_id,
                request.get_ref().computed_request_id,
            );
            let start = Instant::now();

            let snark_context = SnarkContext {
                version: request.get_ref().version,
                proof_id: request.get_ref().proof_id.clone(),
                // proving_key_path: self.config.get_proving_key_path(request.get_ref().version),
                agg_receipt: request.get_ref().agg_receipt.clone(),
                from_input: request.get_ref().from_input,
            };

            let pipeline = self.pipeline.clone();
            let snark_func = move || pipeline.prove_snark(&snark_context);
            let result = run_back_task(snark_func).await;

            let mut response = SnarkProofResponse {
                proof_id: request.get_ref().proof_id.clone(),
                computed_request_id: request.get_ref().computed_request_id.clone(),
                snark_proof_with_public_inputs: match &result {
                    Ok((_, x)) => x.clone(),
                    _ => vec![],
                },
                ..Default::default()
            };
            on_done!(result, response);
            let end = Instant::now();
            let elapsed = end.duration_since(start);
            tracing::info!(
                "[snark_proof] {}:{} code:{} elapsed:{} end",
                request.get_ref().proof_id,
                request.get_ref().computed_request_id,
                response.result.as_ref().unwrap().code,
                elapsed.as_secs()
            );
            Ok(Response::new(response))
        })
        .await
    }

    async fn single_node(
        &self,
        request: Request<SingleNodeRequest>,
    ) -> tonic::Result<Response<SingleNodeResponse>, Status> {
        tracing::info!("Single node start");
        metrics::record_metrics("prover::single_node", || async {
            tracing::info!(
                "[single_node] {}:{} start",
                request.get_ref().proof_id,
                request.get_ref().computed_request_id,
            );
            let start = Instant::now();
            let single_node_context = SingleNodeContext {
                program_id: request.get_ref().program_id.to_string(),
                elf_path: request.get_ref().elf_path.to_string(),
                private_input_path: request.get_ref().private_input_path.to_string(),
                receipt_inputs_path: request.get_ref().receipt_inputs_path.to_string(),
            };

            let pipeline = self.pipeline.clone();
            let single_node_func = move || pipeline.prove_single_node(&single_node_context);
            let result = run_back_task(single_node_func).await;

            let mut response = SingleNodeResponse {
                proof_id: request.get_ref().proof_id.clone(),
                computed_request_id: request.get_ref().computed_request_id.clone(),
                agg_receipt: match &result {
                    Ok((_, x)) => x.clone(),
                    _ => vec![],
                },
                ..Default::default()
            };
            on_done!(result, response);
            let end = Instant::now();
            let elapsed = end.duration_since(start);
            tracing::info!(
                "[single node] {}:{} code:{} elapsed:{} end",
                request.get_ref().proof_id,
                request.get_ref().computed_request_id,
                response.result.as_ref().unwrap().code,
                elapsed.as_secs()
            );
            Ok(Response::new(response))
        })
        .await
    }
}
