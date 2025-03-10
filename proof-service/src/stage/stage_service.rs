use crate::proto::stage_service::v1::{
    stage_service_server::StageService,
    GenerateProofRequest, GenerateProofResponse, GetStatusRequest, GetStatusResponse,
    Status::{Computing, InvalidParameter},
};
use anyhow::Error;
use common::tls::Config as TlsConfig;
use std::sync::Mutex;

use crate::stage::{stage_worker, tasks, GenerateTask};

use tonic::{Request, Response, Status};

use crate::config;
use common::file;

use prover::provers;

use std::io::Write;

use ethers::types::Signature;
use std::str::FromStr;

use crate::database;
use crate::metrics;

use lazy_static::lazy_static;
use std::collections::HashMap;

lazy_static! {
    static ref GLOBAL_TASKMAP: Mutex<HashMap<String, i32>> = Mutex::new(HashMap::new());
}

pub struct StageServiceSVC {
    db: database::Database,
    config: config::RuntimeConfig,
}

impl StageServiceSVC {
    pub async fn new(config: config::RuntimeConfig) -> anyhow::Result<Self> {
        let tls_config = if config.ca_cert_path.is_some() {
            Some(
                TlsConfig::new(
                    config.ca_cert_path.as_ref().unwrap(),
                    config.cert_path.as_ref().unwrap(),
                    config.key_path.as_ref().unwrap(),
                )
                .await?,
            )
        } else {
            None
        };
        let database_url = config.database_url.as_str();
        let db = database::Database::new(database_url);
        sqlx::migrate!("./migrations").run(&db.db_pool).await?;
        let _ = stage_worker::start(tls_config.clone(), db.clone()).await;
        Ok(StageServiceSVC { db, config })
    }

    pub fn verify_signature(&self, request: &GenerateProofRequest) -> Result<String, Error> {
        let sign_data = match request.block_no {
            Some(block_no) => {
                format!("{}&{}&{}", request.proof_id, block_no, request.seg_size)
            }
            None => {
                format!("{}&{}", request.proof_id, request.seg_size)
            }
        };
        let signature = Signature::from_str(&request.signature)?;
        let recovered = signature.recover(sign_data)?;
        Ok(format!("{:?}", recovered))
    }
}

#[tonic::async_trait]
impl StageService for StageServiceSVC {
    async fn get_status(
        &self,
        request: Request<GetStatusRequest>,
    ) -> tonic::Result<Response<GetStatusResponse>, Status> {
        metrics::record_metrics("stage::get_status", || async {
            let task = self.db.get_stage_task(&request.get_ref().proof_id).await;
            let mut response = GetStatusResponse {
                proof_id: request.get_ref().proof_id.clone(),
                ..Default::default()
            };
            if let Ok(task) = task {
                response.status = task.status;
                response.step = task.step;
                let execute_info: Vec<tasks::SplitTask> = self
                    .db
                    .get_prove_task_infos(&request.get_ref().proof_id, tasks::TASK_ITYPE_SPLIT)
                    .await
                    .unwrap_or_default();
                if !execute_info.is_empty() {
                    response.total_steps = execute_info[0].total_steps;
                }

                let (execute_only, composite_proof) = if let Some(context) = task.context {
                    match serde_json::from_str::<GenerateTask>(&context) {
                        Ok(context) => {
                            if task.status
                                == crate::proto::stage_service::v1::Status::Success as i32
                                && !context.output_stream_path.is_empty()
                            {
                                let output_data =
                                    file::new(&context.output_stream_path).read().unwrap();
                                response.output_stream.clone_from(&output_data);
                                if context.composite_proof {
                                    let receipts_path = format!("{}/receipt/0", context.prove_path);
                                    let receipts_data = file::new(&receipts_path).read().unwrap();
                                    response.receipt = receipts_data;
                                }
                            }
                            (context.execute_only, context.composite_proof)
                        }
                        Err(_) => (false, false),
                    }
                } else {
                    (false, false)
                };
                if !execute_only && !composite_proof {
                    if let Some(result) = task.result {
                        response.proof_with_public_inputs = result.into_bytes();
                    }
                    //if let Some(fileserver_url) = &self.fileserver_url {
                    //    response.proof_url = format!(
                    //        "{}/{}/snark/proof_with_public_inputs.json",
                    //        fileserver_url,
                    //        request.get_ref().proof_id
                    //    );
                    //    response.stark_proof_url = format!(
                    //        "{}/{}/aggregate/proof_with_public_inputs.json",
                    //        fileserver_url,
                    //        request.get_ref().proof_id
                    //    );
                    //    response.public_values_url = format!(
                    //        "{}/{}/aggregate/public_values.json",
                    //        fileserver_url,
                    //        request.get_ref().proof_id
                    //    );
                    //}
                    //if let Some(verifier_url) = &self.verifier_url {
                    //    response.solidity_verifier_url.clone_from(verifier_url);
                    //}
                }
            }
            Ok(Response::new(response))
        })
        .await
    }

    async fn generate_proof(
        &self,
        request: Request<GenerateProofRequest>,
    ) -> tonic::Result<Response<GenerateProofResponse>, Status> {
        metrics::record_metrics("stage::generate_proof", || async {
            log::info!("[generate_proof] {} start", request.get_ref().proof_id);

            // check seg_size
            if !request.get_ref().composite_proof
                && !provers::valid_seg_size(request.get_ref().seg_size as usize)
            {
                let response = GenerateProofResponse {
                    proof_id: request.get_ref().proof_id.clone(),
                    status: InvalidParameter.into(),
                    error_message: format!(
                        "invalid seg_size support [{}-{}]",
                        provers::MIN_SEG_SIZE,
                        provers::MAX_SEG_SIZE
                    ),
                    ..Default::default()
                };
                log::warn!(
                    "[generate_proof] {} invalid seg_size support [{}-{}] {}",
                    request.get_ref().proof_id,
                    request.get_ref().seg_size,
                    provers::MIN_SEG_SIZE,
                    provers::MAX_SEG_SIZE
                );
                return Ok(Response::new(response));
            }
            // check signature
            let user_address: String;
            match self.verify_signature(request.get_ref()) {
                Ok(address) => {
                    // check white list
                    let users = self.db.get_user(&address).await.unwrap();
                    log::info!(
                        "[generate_proof] proof_id:{} address:{:?} exists:{:?}",
                        request.get_ref().proof_id,
                        address,
                        !users.is_empty(),
                    );
                    if users.is_empty() {
                        let response = GenerateProofResponse {
                            proof_id: request.get_ref().proof_id.clone(),
                            status: crate::proto::stage_service::v1::Status::InvalidParameter
                                .into(),
                            error_message: "permission denied".to_string(),
                            ..Default::default()
                        };
                        log::warn!(
                            "[generate_proof] {} permission denied",
                            request.get_ref().proof_id,
                        );
                        return Ok(Response::new(response));
                    }
                    user_address = users[0].address.clone();
                }
                Err(e) => {
                    let response = GenerateProofResponse {
                        proof_id: request.get_ref().proof_id.clone(),
                        status: InvalidParameter.into(),
                        error_message: "invalid signature".to_string(),
                        ..Default::default()
                    };
                    log::warn!(
                        "[generate_proof] {} invalid signature {:?}",
                        request.get_ref().proof_id,
                        e,
                    );
                    return Ok(Response::new(response));
                }
            }

            let base_dir = self.config.base_dir.clone();
            let dir_path = format!("{}/proof/{}", base_dir, request.get_ref().proof_id);
            file::new(&dir_path)
                .create_dir_all()
                .map_err(|e| Status::internal(e.to_string()))?;

            let elf_path = format!("{}/elf", dir_path);
            file::new(&elf_path)
                .write(&request.get_ref().elf_data)
                .map_err(|e| Status::internal(e.to_string()))?;

            let block_no = request.get_ref().block_no.unwrap_or(0u64);
            let block_dir = format!("{}/0_{}", dir_path, block_no);
            file::new(&block_dir)
                .create_dir_all()
                .map_err(|e| Status::internal(e.to_string()))?;

            for file_block_item in &request.get_ref().block_data {
                let block_path = format!("{}/{}", block_dir, file_block_item.file_name);
                file::new(&block_path)
                    .write(&file_block_item.file_content)
                    .map_err(|e| Status::internal(e.to_string()))?;
            }

            let input_stream_dir = format!("{}/input_stream", dir_path);
            file::new(&input_stream_dir)
                .create_dir_all()
                .map_err(|e| Status::internal(e.to_string()))?;
            let public_input_stream_path = if request.get_ref().public_input_stream.is_empty() {
                "".to_string()
            } else {
                let public_input_stream_path = format!("{}/{}", input_stream_dir, "public_input");
                file::new(&public_input_stream_path)
                    .write(&request.get_ref().public_input_stream)
                    .map_err(|e| Status::internal(e.to_string()))?;
                public_input_stream_path
            };

            let private_input_stream_path = if request.get_ref().private_input_stream.is_empty() {
                "".to_string()
            } else {
                let private_input_stream_path = format!("{}/{}", input_stream_dir, "private_input");
                file::new(&private_input_stream_path)
                    .write(&request.get_ref().private_input_stream)
                    .map_err(|e| Status::internal(e.to_string()))?;
                private_input_stream_path
            };

            let receipt_inputs_path = if request.get_ref().receipt_inputs.is_empty() {
                "".to_string()
            } else {
                let receipt_inputs_path = format!("{}/{}", input_stream_dir, "receipt_inputs");
                let mut buf = Vec::new();
                bincode::serialize_into(&mut buf, &request.get_ref().receipt_inputs)
                    .expect("serialization failed");
                file::new(&receipt_inputs_path)
                    .write(&buf)
                    .map_err(|e| Status::internal(e.to_string()))?;
                receipt_inputs_path
            };

            let receipts_path = if request.get_ref().receipts.is_empty() {
                "".to_string()
            } else {
                let receipts_path = format!("{}/{}", input_stream_dir, "receipts");
                let mut buf = Vec::new();
                bincode::serialize_into(&mut buf, &request.get_ref().receipts)
                    .expect("serialization failed");
                file::new(&receipts_path)
                    .write(&buf)
                    .map_err(|e| Status::internal(e.to_string()))?;
                receipts_path
            };

            let output_stream_dir = format!("{}/output_stream", dir_path);
            file::new(&output_stream_dir)
                .create_dir_all()
                .map_err(|e| Status::internal(e.to_string()))?;

            let output_stream_path = format!("{}/{}", output_stream_dir, "output_stream");

            let seg_path = format!("{}/segment", dir_path);
            file::new(&seg_path)
                .create_dir_all()
                .map_err(|e| Status::internal(e.to_string()))?;

            let prove_path = format!("{}/prove", dir_path);
            file::new(&prove_path)
                .create_dir_all()
                .map_err(|e| Status::internal(e.to_string()))?;

            let prove_receipt_path = format!("{}/receipt", prove_path);
            file::new(&prove_receipt_path)
                .create_dir_all()
                .map_err(|e| Status::internal(e.to_string()))?;

            let agg_path = format!("{}/aggregate", dir_path);
            file::new(&agg_path)
                .create_dir_all()
                .map_err(|e| Status::internal(e.to_string()))?;

            let snark_dir = format!("{}/snark", dir_path);
            file::new(&snark_dir)
                .create_dir_all()
                .map_err(|e| Status::internal(e.to_string()))?;
            let snark_path = format!("{}/proof_with_public_inputs.json", snark_dir);

            let generate_task = GenerateTask::new(
                &request.get_ref().proof_id,
                &dir_path,
                &elf_path,
                &seg_path,
                &prove_path,
                &agg_path,
                &snark_path,
                &public_input_stream_path,
                &private_input_stream_path,
                &output_stream_path,
                Some(block_no),
                request.get_ref().seg_size,
                request.get_ref().execute_only,
                request.get_ref().composite_proof,
                &receipt_inputs_path,
                &receipts_path,
            );

            let _ = self
                .db
                .insert_stage_task(
                    &request.get_ref().proof_id,
                    &user_address,
                    Computing.into(),
                    &serde_json::to_string(&generate_task).unwrap(),
                )
                .await;
            // TODO: we use the stage server as the file server, any better way?
            let mut snark_proof_url = match &self.config.fileserver_url {
                Some(fileserver_url) => format!(
                    "{}/{}/snark/proof_with_public_inputs.json",
                    fileserver_url,
                    request.get_ref().proof_id
                ),
                None => "".to_string(),
            };
            let mut stark_proof_url = match &self.config.fileserver_url {
                Some(fileserver_url) => format!(
                    "{}/{}/aggregate/proof_with_public_inputs.json",
                    fileserver_url,
                    request.get_ref().proof_id
                ),
                None => "".to_string(),
            };
            let mut public_values_url = match &self.config.fileserver_url {
                Some(fileserver_url) => format!(
                    "{}/{}/aggregate/public_values.json",
                    fileserver_url,
                    request.get_ref().proof_id
                ),
                None => "".to_string(),
            };
            if request.get_ref().execute_only {
                snark_proof_url = "".to_string();
                stark_proof_url = "".to_string();
                public_values_url = "".to_string();
            }
            let response = GenerateProofResponse {
                proof_id: request.get_ref().proof_id.clone(),
                status: Computing.into(),
                snark_proof_url,
                stark_proof_url,
                public_values_url,
                ..Default::default()
            };
            log::info!("[generate_proof] {} end", request.get_ref().proof_id);
            Ok(Response::new(response))
        })
        .await
    }
}
