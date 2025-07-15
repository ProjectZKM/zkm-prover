use crate::proto::includes::v1::ProverVersion;
use common::file;
use serde_derive::Deserialize;
use tracing_forest::ForestLayer;
use tracing_subscriber::{
    fmt::format::FmtSpan, layer::SubscriberExt, util::SubscriberInitExt, EnvFilter, Registry,
};

#[derive(Debug, Deserialize, Clone, Default)]
pub struct RuntimeConfig {
    pub addr: String,
    pub metrics_addr: String,
    pub database_url: String,
    pub prover_addrs: Vec<String>,

    pub base_dir: String,
    pub max_concurrent_tasks: Option<usize>,

    pub fileserver_url: Option<String>,
    // pub fileserver_addr: String,
    pub proving_key_paths: Vec<String>,

    pub ca_cert_path: Option<String>,
    pub cert_path: Option<String>,
    pub key_path: Option<String>,
}

impl RuntimeConfig {
    pub fn new() -> Self {
        RuntimeConfig {
            addr: "0.0.0.0:50000".to_string(),
            metrics_addr: "0.0.0.0:50010".to_string(),
            database_url: "mysql://user:password@localhost:3306/dbname".to_string(),
            prover_addrs: ["0.0.0.0:50000".to_string()].to_vec(),
            base_dir: "/tmp".to_string(),
            max_concurrent_tasks: Some(1),
            fileserver_url: None,
            // fileserver_addr: "0.0.0.0:40000".to_string(),
            proving_key_paths: vec![],
            ca_cert_path: None,
            cert_path: None,
            key_path: None,
        }
    }

    pub fn from_toml(path: &str) -> anyhow::Result<Self> {
        let contents = file::new(path).read_to_string()?;
        Ok(toml::from_str(&contents)?)
    }

    pub fn get_proving_key_path(&self, version: i32) -> String {
        match ProverVersion::from_i32(version) {
            Some(ProverVersion::Zkm) => self.proving_key_paths[0].clone(),
            Some(ProverVersion::Zkm2) => self.proving_key_paths[1].clone(),
            None => unimplemented!("Invalid prover version found: {}", version),
        }
    }
}

/// A simple logger.
///
/// Set the `RUST_LOG` environment variable to be set to `info` or `debug`.
pub fn setup_logger() {
    let env_filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new("off"))
        .add_directive("hyper=off".parse().unwrap())
        .add_directive("p3_keccak_air=off".parse().unwrap())
        .add_directive("p3_fri=off".parse().unwrap())
        .add_directive("p3_dft=off".parse().unwrap())
        .add_directive("p3_challenger=off".parse().unwrap());

    // if the RUST_LOGGER environment variable is set, use it to determine which logger to
    // configure (tracing_forest or tracing_subscriber)
    // otherwise, default to 'forest'
    let logger_type = std::env::var("RUST_LOGGER").unwrap_or_else(|_| "flat".to_string());
    match logger_type.as_str() {
        "forest" => {
            Registry::default()
                .with(env_filter)
                .with(ForestLayer::default())
                .init();
        }
        "flat" => {
            tracing_subscriber::fmt::Subscriber::builder()
                .compact()
                .with_file(false)
                .with_target(false)
                .with_thread_names(false)
                .with_env_filter(env_filter)
                .with_span_events(FmtSpan::CLOSE)
                .finish()
                .init();
        }
        _ => {
            panic!("Invalid logger type: {}", logger_type);
        }
    }
}
