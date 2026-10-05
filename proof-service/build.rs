fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("cargo:rerun-if-changed=../proto/src/proto/prover/v1/prover.proto");
    println!("cargo:rerun-if-changed=../proto/src/proto/stage/v1/stage.proto");
    println!("cargo:rerun-if-changed=../proto/src/proto/include/v1/includes.proto");
    tonic_build::configure()
        .protoc_arg("--experimental_allow_proto3_optional")
        .type_attribute(
            ".",
            "#[derive(serde_derive::Serialize, serde_derive::Deserialize)]",
        )
        .compile(
            &[
                "../proto/src/proto/prover/v1/prover.proto",
                "../proto/src/proto/stage/v1/stage.proto",
                "../proto/src/proto/include/v1/includes.proto",
            ],
            &["../proto/src/proto"],
        )?;
    Ok(())
}
