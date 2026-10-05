use std::path::Path;
use tonic::transport::{Certificate, Identity};

#[derive(Clone)]
pub struct Config {
    pub ca_cert: Option<Certificate>,
    pub identity: Option<Identity>,
}

impl Config {
    pub async fn new(ca_cert_path: &str, cert_path: &str, key_path: &str) -> anyhow::Result<Self> {
        let (ca_cert, identity) = get_cert_and_identity(ca_cert_path, cert_path, key_path).await?;
        Ok(Config { ca_cert, identity })
    }
}

// FIXME: remember to align with the project-template
async fn get_cert_and_identity(
    ca_cert_path: &str,
    cert_path: &str,
    key_path: &str,
) -> anyhow::Result<(Option<Certificate>, Option<Identity>)> {
    let ca_cert_path = Path::new(ca_cert_path);
    let cert_path = Path::new(cert_path);
    let key_path = Path::new(key_path);
    // if !ca_cert_path.is_file() || !cert_path.is_file() || !key_path.is_file() {
    //     bail!("both ca_cert_path, cert_path and key_path should be valid file")
    // }
    let mut ca: Option<Certificate> = None;
    let mut identity: Option<Identity> = None;
    if ca_cert_path.is_file() {
        println!("Loading CA cert from {:?}", ca_cert_path);
        let ca_cert = tokio::fs::read(ca_cert_path)
            .await
            .unwrap_or_else(|err| panic!("Failed to read {:?}, err: {:?}", ca_cert_path, err));
        ca = Some(Certificate::from_pem(ca_cert));
    }

    if cert_path.is_file() && key_path.is_file() {
        println!(
            "Loading server identity cert and key from {:?} and {:?}",
            cert_path, key_path
        );
        let cert = tokio::fs::read(cert_path)
            .await
            .unwrap_or_else(|err| panic!("Failed to read {:?}, err: {:?}", cert_path, err));
        let key = tokio::fs::read(key_path)
            .await
            .unwrap_or_else(|err| panic!("Failed to read {:?}, err: {:?}", key_path, err));
        identity = Some(Identity::from_pem(cert, key));
    }
    Ok((ca, identity))
}
