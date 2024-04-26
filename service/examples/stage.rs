use common::file;
use common::tls::Config;
use stage_service::stage_service_client::StageServiceClient;
use stage_service::{BlockFileItem, GenerateProofRequest, GetStatusRequest};
use std::env;
use std::path::Path;
use std::time::Instant;
use tokio::time;
use tonic::transport::ClientTlsConfig;
use tonic::transport::Endpoint;
pub mod stage_service {
    tonic::include_proto!("stage.v1");
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::try_init().unwrap_or_default();
    let elf_path = env::var("ELF_PATH").unwrap_or("/tmp/zkm/test/hello_world".to_string());
    let output_dir = env::var("OUTPUT_DIR").unwrap_or("/tmp/zkm/test".to_string());
    let block_path = env::var("BLOCK_PATH").unwrap_or("".to_string());
    let block_no = env::var("BLOCK_NO").unwrap_or("0".to_string());
    let block_no = block_no.parse::<_>().unwrap_or(0);
    let seg_size = env::var("SEG_SIZE").unwrap_or("262144".to_string());
    let seg_size = seg_size.parse::<_>().unwrap_or(262144);
    let endpoint = env::var("ENDPOINT").unwrap_or("http://127.0.0.1:50000".to_string());
    let ca_cert_path = env::var("CA_CERT_PATH").unwrap_or("".to_string());
    let cert_path = env::var("CERT_PATH").unwrap_or("".to_string());
    let key_path = env::var("KEY_PATH").unwrap_or("".to_string());
    let ssl_config = if ca_cert_path.is_empty() {
        None
    } else {
        Some(Config::new(ca_cert_path, cert_path, key_path).await?)
    };

    let elf_data = file::new(&elf_path).read().unwrap();
    let mut block_data = Vec::new();

    if block_no > 0 {
        let files = file::new(&block_path).read_dir().unwrap();
        for file_name in files {
            let file_path = format!("{}/{}", block_path, file_name);
            let block_file_item = BlockFileItem {
                file_name: file_name.to_string(),
                file_content: file::new(&file_path).read().unwrap(),
            };
            block_data.push(block_file_item);
        }
    }

    let proof_id = uuid::Uuid::new_v4().to_string();
    let request = GenerateProofRequest {
        proof_id: proof_id.clone(),
        elf_data,
        block_data,
        block_no,
        seg_size,
        ..Default::default()
    };
    log::info!("request: {:?}", proof_id);
    let start = Instant::now();
    let endpoint = match ssl_config {
        Some(config) => {
            let tls_config = ClientTlsConfig::new()
                .ca_certificate(config.ca_cert)
                .identity(config.identity);
            Endpoint::new(endpoint)?.tls_config(tls_config)?
        }
        None => Endpoint::new(endpoint)?,
    };
    let mut stage_client = StageServiceClient::connect(endpoint).await?;
    let response = stage_client.generate_proof(request).await?.into_inner();
    log::info!("generate_proof response: {:?}", response);
    if response.status == crate::stage_service::Status::Computing as u32 {
        loop {
            let get_status_request = GetStatusRequest {
                proof_id: proof_id.clone(),
            };
            let get_status_response = stage_client
                .get_status(get_status_request)
                .await?
                .into_inner();
            if get_status_response.status != crate::stage_service::Status::Computing as u32 {
                if let Some(status) =
                    crate::stage_service::Status::from_i32(get_status_response.status as i32)
                {
                    match status {
                        crate::stage_service::Status::Success => {
                            log::info!(
                                "generate_proof success proof_size: {} public_inputs_size: {} circuit_data_size: {}",
                                get_status_response.result.len(),
                                get_status_response.proof_with_public_inputs.len(),
                                get_status_response.verifier_only_circuit_data.len(),
                            );
                            let output_dir = Path::new(&output_dir);
                            let proof_path = output_dir.join("proof");
                            let public_inputs_path = output_dir.join("proof_with_public_inputs");
                            let circuit_data_path = output_dir.join("verifier_only_circuit_data");
                            let _ = file::new(&proof_path.to_string_lossy())
                                .write(get_status_response.result.as_slice());
                            let _ = file::new(&public_inputs_path.to_string_lossy())
                                .write(get_status_response.proof_with_public_inputs.as_slice());
                            let _ = file::new(&circuit_data_path.to_string_lossy())
                                .write(get_status_response.verifier_only_circuit_data.as_slice());
                        }
                        _ => {
                            log::info!(
                                "generate_proof failed status: {}",
                                get_status_response.status
                            );
                        }
                    }
                }
                break;
            }
            time::sleep(time::Duration::from_secs(1)).await;
        }
    }
    let end = Instant::now();
    let elapsed = end.duration_since(start);
    log::info!("Elapsed time: {:?} secs", elapsed.as_secs());
    Ok(())
}
