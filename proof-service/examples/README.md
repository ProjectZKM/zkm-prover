# Examples

## Hello world

* Compile the Go code to MIPS

Write your own hello.go, and compile

```
$ GOOS=linux GOARCH=mips GOMIPS=softfloat go build hello.go -o /tmp/zkm/test/hello_world
```

If you build your own server, you can use Docker Compose (The image is built based on AMD64)

```
$ docker-compose up -d
```

* Adjust parameter request stage service

- `ELF_PATH`: The go program path compiled in the above steps
- `ENDPOINT`: The access address of stage service
- `RUST_LOG`: Log level
- `OUTPUT_DIR`: Store results folder path
- `SEG_SIZE`: SEG_SIZE default 131072

The smaller the SEG_SIZE, the longer the cost will be

```
$ RUST_LOG=info ELF_PATH=/tmp/zkm/test/hello_world OUTPUT_DIR=/tmp/zkm/test ENDPOINT=http://127.0.0.1:50000 cargo run --release --example stage
```

* If SEG_SIZE=262144, Wait for about 20 minutes. If you see "success", a proof will be generated. You can see the
  corresponding file in OUTPUT_DIR

## [Minigeth](https://github.com/ProjectZKM/cannon-mips)

* Compile the minigeth_mips

```
$ git clone https://github.com/ProjectZKM/cannon-mips
$ cd cannon-mips && make minigeth_mips
$ cp mipsevm/minigeth /tmp/zkm/test/
```

* Download the block and place it in the corresponding directory

```
$ mkdir -p /tmp/cannon
$ export BASEDIR=/tmp/cannon; minigeth/go-ethereum 13284491
$ mkdir -p /tmp/zkm/test/0_13284491
$ cp -R /tmp/cannon/0_13284491 /tmp/zkm/test
```

* Adjust parameter request stage service

```
$ export RUST_LOG=info
$ ELF_PATH=/tmp/zkm/test/minigeth BLOCK_NO=13284491 BLOCK_PATH=/tmp/zkm/test/0_13284491 SEG_SIZE=262144 cargo run --release --example stage
```

## [Revme](https://github.com/ProjectZKM/zkm/tree/main/prover/examples/revme)

* Generate suite_json

```
$ git clone https://github.com/ProjectZKM/revme
$ RPC_URL=http://localhost:8545 CHAIN_ID=1337 BLOCK_NO=3 RUST_LOG=debug SUITE_JSON_PATH=./test-vectors/suite3.json cargo run --example process
```

* Compile the remve_mips

```
$ git clone https://github.com/ProjectZKM/zkm
$ cd zkm/prover/examples/revme
$ cargo build --release  --target=mips-unknown-linux-musl
```

* Adjust parameter request stage service

- `ENDPOINT`: zkm-prover service endpoint
- `CA_CERT_PATH`: zkm-prover service CA CERT
- `PRIVATE_KEY`: wallet private key, used for message signing only. DON'T hold any asset in this address.
- `ELF_PATH`: the file compiled in the previous step
- `PUBLIC_INPUT_PATH`: Output file for the Generate Suite_json step

When you apply the access of the proof network, you need to submit the address with checksum.

```
$ export RUST_LOG=info
$ ENDPOINT=... CA_CERT_PATH=... PRIVATE_KEY=... ELF_PATH=...revm SEG_SIZE=262144 PUBLIC_INPUT_PATH=... cargo run --release --example stage
```

# Deployment

* Generate config toml

```
$ cd ../config
$ bash gen_config.sh
```

And you can view more detail in [gen_config](../config/README.md).

* Use S3 to store your data

We provide the support of s3, and you can enable s3 support by setting base_dir to a s3 path such as
`s3://{bucket}/{object}`.

Besides, you may need to configure some s3 configurations in your environment variables as below or read more details
in [s3-configuration](https://docs.aws.amazon.com/cli/latest/userguide/cli-chap-configure.html).

```
$ export AWS_ACCESS_KEY_ID="test"
$ export AWS_SECRET_ACCESS_KEY="test"
$ export AWS_DEFAULT_REGION="us-east-1"
$ export AWS_ENDPOINT_URL="{{ENDPOINT_URL}}"
```

* Compile zkm-prover

```
cargo build --release
```

* Start prover_server.

```
# use prover1_tls.toml and prover2_tls.toml instead if tls is enabled
$ RUST_LOG=info ./target/release/proof-service --config ./service/config/prover1.toml
$ RUST_LOG=info ./target/release/proof-service --config ./service/config/prover2.toml
```

* Start stage_server.

```
# use stage_tls.toml instead if tls is enabled
RUST_LOG=info ./target/release/proof-service --config ./service/config/stage.toml --stage
```

* Start example stage

```
# set CA_CERT_PATH, CERT_PATH and KEY_PATH if tls is enabled
RUST_LOG=info cargo run --release --example stage
```
