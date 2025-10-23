use std::collections::HashMap;
use std::io::Write as _;
use std::pin::Pin;
use std::result::Result as StdResult;
use std::sync::Arc;
use std::time::Instant;

use once_cell::sync::Lazy;
use parking_lot::Mutex as ParkingMutex;
use tempfile::NamedTempFile;
use tokio::sync::broadcast;
use tokio_stream::{wrappers::BroadcastStream, Stream as TokioStream, StreamExt};
use tonic::{Request, Response, Status};

use crate::proto::includes::v1::ProverVersion;
use crate::proto::prover_service::v1::prover_service_client::ProverServiceClient;
use crate::proto::prover_service::v1::{
    prover_service_server::ProverService, AggregateRequest, AggregateResponse, FetchSegmentRequest,
    FetchSegmentResponse, GetStatusRequest, GetStatusResponse, GetTaskResultRequest,
    GetTaskResultResponse, ProveRequest, ProveResponse, ReleaseSegmentRequest,
    ReleaseSegmentResponse, Result, ResultCode, SegmentHandle, SingleNodeRequest,
    SingleNodeResponse, SnarkProofRequest, SnarkProofResponse, SplitElfRequest, SplitElfResponse,
    StreamSegmentsRequest,
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
    contexts::{AggContext, ProveContext, SingleNodeContext, SnarkContext, SplitContext},
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn segment_manager_store_fetch_release() {
        let manager = SegmentManager::default();
        let key = SegmentKey::new("proof", "job");

        // Simulate stream subscription preceding job registration.
        let _ = manager.subscribe(&key);
        manager.register_job(key.clone());

        let mut handle = SegmentHandle::default();
        handle.proof_id = "proof".into();
        handle.provider_addr = "addr".into();
        handle.token = "token".into();
        handle.index = 1;
        handle.total_segments_partial = 1;

        let bytes = Arc::new(vec![1u8, 2, 3]);
        manager.publish(&key, handle.clone(), Arc::clone(&bytes));

        let stored = manager
            .segment(&key, &handle.token)
            .expect("segment stored");
        assert_eq!(*stored, vec![1, 2, 3]);

        manager.release(&key, &handle.token);
        assert!(manager.segment(&key, &handle.token).is_none());

        manager.mark_finished(&key);
        // After cleanup, a fresh subscription should be possible without stale data.
        let _ = manager.subscribe(&key);
    }
}

#[derive(Clone, Hash, PartialEq, Eq)]
struct SegmentKey {
    proof_id: String,
    computed_request_id: String,
}

impl SegmentKey {
    fn new(proof_id: &str, computed_request_id: &str) -> Self {
        SegmentKey {
            proof_id: proof_id.to_string(),
            computed_request_id: computed_request_id.to_string(),
        }
    }
}

struct SegmentEntry {
    sender: broadcast::Sender<SegmentHandle>,
    segments: HashMap<String, Arc<Vec<u8>>>,
    finished: bool,
}

impl SegmentEntry {
    fn new(sender: broadcast::Sender<SegmentHandle>) -> Self {
        Self {
            sender,
            segments: HashMap::new(),
            finished: false,
        }
    }
}

#[derive(Default)]
struct SegmentManager {
    inner: ParkingMutex<HashMap<SegmentKey, SegmentEntry>>,
}

static SEGMENT_MANAGER: Lazy<SegmentManager> = Lazy::new(SegmentManager::default);

impl SegmentManager {
    fn subscribe(&self, key: &SegmentKey) -> broadcast::Receiver<SegmentHandle> {
        let mut guard = self.inner.lock();
        guard
            .entry(key.clone())
            .or_insert_with(|| {
                let (sender, _) = broadcast::channel(512);
                SegmentEntry::new(sender)
            })
            .sender
            .subscribe()
    }

    fn register_job(&self, key: SegmentKey) -> broadcast::Sender<SegmentHandle> {
        let mut guard = self.inner.lock();
        let entry = guard.entry(key).or_insert_with(|| {
            let (sender, _) = broadcast::channel(512);
            SegmentEntry::new(sender)
        });
        entry.segments.clear();
        entry.finished = false;
        entry.sender.clone()
    }

    fn publish(&self, key: &SegmentKey, handle: SegmentHandle, bytes: Arc<Vec<u8>>) {
        let sender_opt = {
            let mut guard = self.inner.lock();
            if let Some(entry) = guard.get_mut(key) {
                entry
                    .segments
                    .insert(handle.token.clone(), Arc::clone(&bytes));
                Some(entry.sender.clone())
            } else {
                None
            }
        };

        if let Some(sender) = sender_opt {
            if let Err(err) = sender.send(handle) {
                tracing::warn!("broadcast segment handle failed: {}", err);
            }
        }
    }

    fn release(&self, key: &SegmentKey, token: &str) {
        let mut guard = self.inner.lock();
        if let Some(entry) = guard.get_mut(key) {
            entry.segments.remove(token);
            if entry.finished && entry.segments.is_empty() {
                guard.remove(key);
            }
        }
    }

    fn mark_finished(&self, key: &SegmentKey) {
        let mut guard = self.inner.lock();
        if let Some(entry) = guard.get_mut(key) {
            entry.finished = true;
            if entry.segments.is_empty() {
                guard.remove(key);
            }
        }
    }

    fn segment(&self, key: &SegmentKey, token: &str) -> Option<Arc<Vec<u8>>> {
        self.inner
            .lock()
            .get(key)
            .and_then(|entry| entry.segments.get(token).cloned())
    }
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

    fn read_local_segment(&self, key: &SegmentKey, token: &str) -> StdResult<Vec<u8>, Status> {
        SEGMENT_MANAGER
            .segment(key, token)
            .map(|bytes| (*bytes).clone())
            .ok_or_else(|| Status::not_found("segment not found"))
    }

    async fn fetch_segment_bytes(&self, request: &ProveRequest) -> StdResult<Vec<u8>, Status> {
        #[allow(deprecated)]
        if request.segment_token.is_empty() {
            return std::fs::read(&request.segment_path)
                .map_err(|e| Status::internal(format!("read segment failed: {}", e)));
        }

        let key = SegmentKey::new(&request.proof_id, &request.segment_job_id);
        if request.segment_provider_addr == self.config.addr {
            return self.read_local_segment(&key, &request.segment_token);
        }

        let fetch_request = FetchSegmentRequest {
            proof_id: request.proof_id.clone(),
            token: request.segment_token.clone(),
            index: request.index,
            computed_request_id: request.segment_job_id.clone(),
        };
        let endpoint = format!("http://{}", request.segment_provider_addr);
        let mut client = ProverServiceClient::connect(endpoint)
            .await
            .map_err(|e| Status::unavailable(format!("connect provider failed: {}", e)))?;
        let response = client
            .fetch_segment(Request::new(fetch_request))
            .await
            .map_err(|e| Status::internal(format!("fetch segment rpc failed: {}", e)))?;
        Ok(response.into_inner().segment)
    }

    async fn release_segment_token(&self, request: &ProveRequest) {
        if request.segment_token.is_empty() {
            return;
        }
        let release_request = ReleaseSegmentRequest {
            proof_id: request.proof_id.clone(),
            token: request.segment_token.clone(),
            index: request.index,
            computed_request_id: request.segment_job_id.clone(),
        };
        if request.segment_provider_addr == self.config.addr {
            if let Err(err) =
                ProverServiceSVC::release_segment(self, Request::new(release_request)).await
            {
                tracing::warn!("local release segment failed: {}", err);
            }
        } else {
            let endpoint = format!("http://{}", request.segment_provider_addr);
            match ProverServiceClient::connect(endpoint).await {
                Ok(mut client) => {
                    if let Err(err) = client.release_segment(Request::new(release_request)).await {
                        tracing::warn!("remote release segment failed: {}", err);
                    }
                }
                Err(err) => {
                    tracing::warn!("connect provider for release failed: {}", err);
                }
            }
        }
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
    type StreamSegmentsStream =
        Pin<Box<dyn TokioStream<Item = StdResult<SegmentHandle, Status>> + Send + 'static>>;

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

    async fn stream_segments(
        &self,
        request: Request<StreamSegmentsRequest>,
    ) -> tonic::Result<Response<Self::StreamSegmentsStream>, Status> {
        metrics::record_metrics("prover::stream_segments", || async {
            let key = SegmentKey::new(
                &request.get_ref().proof_id,
                &request.get_ref().computed_request_id,
            );
            let receiver = SEGMENT_MANAGER.subscribe(&key);
            let stream = BroadcastStream::new(receiver).filter_map(|item| match item {
                Ok(handle) => Some(StdResult::Ok(handle)),
                Err(err) => {
                    tracing::warn!("segment stream error: {}", err);
                    None
                }
            });
            Ok(Response::new(Box::pin(stream) as Self::StreamSegmentsStream))
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
            let proof_id = request.get_ref().proof_id.clone();
            let computed_request_id = request.get_ref().computed_request_id.clone();
            let key = SegmentKey::new(&proof_id, &computed_request_id);
            let key_arc = Arc::new(key.clone());
            let provider_addr = self.config.addr.clone();
            SEGMENT_MANAGER.register_job(key.clone());

            let mut split_context = SplitContext::new(
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
                &request.get_ref().computed_request_id,
            );

            let callback_key = Arc::clone(&key_arc);
            let callback_proof_id = proof_id.clone();
            let callback_addr = provider_addr.clone();
            split_context.segment_callback = Some(Arc::new(move |report| {
                let mut handle = SegmentHandle::default();
                handle.proof_id = callback_proof_id.clone();
                handle.provider_addr = callback_addr.clone();
                handle.token = report.token.clone();
                handle.index = report.index as u32;
                handle.total_segments_partial = report.generated as u32;
                SEGMENT_MANAGER.publish(callback_key.as_ref(), handle, Arc::clone(&report.bytes));
            }));

            let pipeline = self.pipeline.clone();
            let split_func = move || pipeline.split(&split_context);
            let result = run_back_task(split_func).await;

            let mut response = SplitElfResponse {
                proof_id: request.get_ref().proof_id.clone(),
                computed_request_id: request.get_ref().computed_request_id.clone(),
                total_steps: result.clone().unwrap_or_default().1.total_steps,
                total_segments: result.clone().unwrap_or_default().1.total_segments,
                public_values: result.clone().unwrap_or_default().1.public_values,
                deferred_inputs: result.clone().unwrap_or_default().1.deferred_inputs,
                ..Default::default()
            };
            // True if and only if no error occurs and ELF size > 0
            let result: std::result::Result<(bool, Vec<u8>), String> = match result {
                Ok(cycle) => Ok((cycle.1.total_steps > 0 && cycle.0, vec![])),
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
            SEGMENT_MANAGER.mark_finished(&key);
            Ok(Response::new(response))
        })
        .await
    }

    async fn fetch_segment(
        &self,
        request: Request<FetchSegmentRequest>,
    ) -> tonic::Result<Response<FetchSegmentResponse>, Status> {
        metrics::record_metrics("prover::fetch_segment", || async {
            let key = SegmentKey::new(
                &request.get_ref().proof_id,
                &request.get_ref().computed_request_id,
            );
            let data = SEGMENT_MANAGER
                .segment(&key, &request.get_ref().token)
                .ok_or_else(|| Status::not_found("segment not found"))?;
            Ok(Response::new(FetchSegmentResponse {
                segment: (*data).clone(),
            }))
        })
        .await
    }

    async fn release_segment(
        &self,
        request: Request<ReleaseSegmentRequest>,
    ) -> tonic::Result<Response<ReleaseSegmentResponse>, Status> {
        metrics::record_metrics("prover::release_segment", || async {
            let key = SegmentKey::new(
                &request.get_ref().proof_id,
                &request.get_ref().computed_request_id,
            );
            SEGMENT_MANAGER.release(&key, &request.get_ref().token);
            Ok(Response::new(ReleaseSegmentResponse {}))
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
            let (prove_context, _temp_segment_file) = {
                let bytes = self.fetch_segment_bytes(request.get_ref()).await?;
                let mut temp_file = NamedTempFile::new()
                    .map_err(|e| Status::internal(format!("create temp segment failed: {}", e)))?;
                temp_file
                    .write_all(&bytes)
                    .map_err(|e| Status::internal(format!("write temp segment failed: {}", e)))?;
                let segment_path = temp_file.path().to_string_lossy().into_owned();
                (
                    ProveContext {
                        proof_id: request.get_ref().proof_id.clone(),
                        program_id: request.get_ref().program_id.clone(),
                        index: request.get_ref().index as usize,
                        elf_path: request.get_ref().elf_path.clone(),
                        segment: segment_path,
                        seg_size: request.get_ref().seg_size,
                    },
                    Some(temp_file),
                )
            };

            let pipeline = self.pipeline.clone();
            let prove_func = move || pipeline.prove_root(&prove_context);
            let result = run_back_task(prove_func).await;
            let is_success = result.as_ref().is_ok();

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
            #[cfg(feature = "prover_v2")]
            if is_success {
                self.release_segment_token(request.get_ref()).await;
            }
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

    #[cfg(feature = "prover_v2")]
    async fn single_node(
        &self,
        request: Request<SingleNodeRequest>,
    ) -> tonic::Result<Response<SingleNodeResponse>, Status> {
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
                base_dir: request.get_ref().base_dir.to_string(),
                private_input_path: request.get_ref().private_input_path.to_string(),
                receipt_inputs_path: request.get_ref().receipt_inputs_path.to_string(),
                target_step: request.get_ref().target_step,
                seg_size: request.get_ref().seg_size,
            };

            let pipeline = self.pipeline.clone();
            let single_node_func = move || pipeline.prove_single_node(&single_node_context);
            let result = run_back_task(single_node_func).await;

            let mut response = SingleNodeResponse {
                proof_id: request.get_ref().proof_id.clone(),
                computed_request_id: request.get_ref().computed_request_id.clone(),
                total_steps: result.clone().unwrap_or_default().1,
                output: match &result {
                    Ok((_, _, x, _)) => x.clone(),
                    _ => vec![],
                },
                public_values: match &result {
                    Ok((_, _, _, x)) => x.clone(),
                    _ => vec![],
                },
                ..Default::default()
            };

            // True if and only if no error occurs and cycles > 0
            let result: std::result::Result<(bool, Vec<u8>), String> = match result {
                Ok(cycle) => Ok((cycle.1 > 0 && cycle.0, vec![])),
                Err(e) => Err(e),
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

    #[cfg(feature = "prover")]
    async fn single_node(
        &self,
        _request: Request<SingleNodeRequest>,
    ) -> tonic::Result<Response<SingleNodeResponse>, Status> {
        Err(Status::unimplemented(
            "single_node is not supported in zkm feature",
        ))
    }
}
