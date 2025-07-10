use clap::Parser;
use common::tls::Config as TlsConfig;
use std::net::SocketAddr;
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
    #[arg(short = 'c', long = "config", default_value_t = String::from("./config/config.toml"))]
    config: String,
    #[arg(short = 's', long = "stage", default_value_t = false)]
    stage: bool,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    config::setup_logger();
    let args = Args::parse();
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
        let tls_config = TlsConfig::new(
            &runtime_config
                .ca_cert_path
                .clone()
                .unwrap_or("".to_string()),
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
        #[cfg(all(feature = "prover", feature = "gpu"))]
        {
            plonky2::create_ctx(13, 13);
            plonky2::init_globalmem(134217728);
            prover::init_stark_op_stream_simple();
        }
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

    // let file_server = tokio::spawn(async move {
    //     if let Err(e) = start_file_server(&runtime_config.fileserver_addr).await {
    //         eprintln!("Error running HTTP server: {}", e);
    //     }
    // });

    tokio::pin!(grpc_server);
    tokio::pin!(metrics_server);
    // tokio::pin!(file_server);

    tracing::info!(
        "Starting stage/prover:{} on {}",
        args.stage,
        runtime_config.addr
    );

    tokio::select! {
        res = grpc_server => res?,
        res = metrics_server => res?,
        // res = file_server => res?,
    }

    #[cfg(all(feature = "prover", feature = "gpu"))]
    if !args.stage {
        plonky2::destroy_ctx();
    }

    Ok(())
}

pub async fn start_file_server(host: &str) -> Result<(), Box<dyn std::error::Error>> {
    let file_server = warp::fs::dir("public");
    warp::serve(file_server)
        .run(host.parse::<SocketAddr>().expect("host is invalid"))
        .await;
    Ok(())
}
