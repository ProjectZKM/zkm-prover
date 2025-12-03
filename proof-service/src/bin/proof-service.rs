use clap::Parser;
use common::tls::Config as TlsConfig;
use tonic::codec::CompressionEncoding;
use tonic::transport::Server;
use tonic::transport::ServerTlsConfig;

use hyper::service::{make_service_fn, service_fn};
use hyper::{Body, Request, Response};
use prometheus::{Encoder, TextEncoder};
use proof_service::{
    config, metrics,
    proto::{
        prover_service::v1::prover_service_server::ProverServiceServer,
        stage_service::v1::stage_service_server::StageServiceServer,
    },
    prover_node::{self, ProverNode},
    prover_service::ProverServiceSVC,
    stage::stage_service::StageServiceSVC,
};

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Path to the config file
    #[arg(short = 'c', long = "config", default_value_t = String::from("./proof-service/config/config.toml"))]
    config: String,
    /// Run in stage mode
    #[arg(short = 's', long = "stage", default_value_t = false)]
    stage: bool,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    config::setup_logger();
    let args = Args::parse();
    println!("Args: {:?}", args);
    let runtime_config = config::RuntimeConfig::from_toml(&args.config).expect("Config is missing");
    let addr = runtime_config.addr.as_str().parse()?;
    let nodes_lock = crate::prover_node::instance();
    {
        let mut nodes_data = nodes_lock.lock().unwrap();
        for node in &runtime_config.prover_addrs {
            nodes_data.add_node(ProverNode::new(node));
        }
    }
    let mut server = Server::builder();
    if runtime_config.key_path.is_some() {
        tracing::info!("Starting gRPC server with TLS");
        let tls_config = TlsConfig::new(
            &runtime_config
                .ca_cert_path
                .clone()
                .expect("valid ca cert path"),
            &runtime_config.cert_path.clone().unwrap(),
            &runtime_config.key_path.clone().unwrap(),
        )
        .await?;
        let mut server_tls_config = ServerTlsConfig::new();
        if let Some(ca_cert) = tls_config.ca_cert {
            server_tls_config = server_tls_config.client_ca_root(ca_cert);
        }
        if let Some(identity) = tls_config.identity {
            server_tls_config = server_tls_config.identity(identity);
        }
        server = server.tls_config(server_tls_config)?;
    }
    let grpc_server = if args.stage {
        let stage = StageServiceSVC::new(runtime_config.clone()).await?;
        server
            .add_service(
                StageServiceServer::new(stage)
                    .send_compressed(CompressionEncoding::Gzip)
                    .accept_compressed(CompressionEncoding::Gzip),
            )
            .serve(addr)
    } else {
        let prover = ProverServiceSVC::new(runtime_config.clone());
        server
            .add_service(
                ProverServiceServer::new(prover)
                    .send_compressed(CompressionEncoding::Gzip)
                    .accept_compressed(CompressionEncoding::Gzip),
            )
            .serve(addr)
    };

    let metrics_addr = runtime_config.metrics_addr.as_str().parse()?;
    let make_svc = make_service_fn(move |_| {
        let registry = metrics::REGISTRY_INSTANCE.clone();
        async move {
            Ok::<_, hyper::Error>(service_fn(move |_: Request<Body>| {
                let registry = registry.clone();
                async move {
                    let encoder = TextEncoder::new();
                    let metric_families = registry.gather();
                    let mut buffer = Vec::new();
                    encoder.encode(&metric_families, &mut buffer).unwrap();
                    Ok::<_, hyper::Error>(Response::new(Body::from(buffer)))
                }
            }))
        }
    });
    metrics::init_registry();
    let metrics_server = hyper::Server::bind(&metrics_addr).serve(make_svc);

    tokio::pin!(grpc_server);
    tokio::pin!(metrics_server);

    tracing::info!(
        "Starting stage/prover:{} on {}",
        args.stage,
        runtime_config.addr
    );

    tokio::select! {
        res = grpc_server => res?,
        res = metrics_server => res?,
    }

    Ok(())
}
