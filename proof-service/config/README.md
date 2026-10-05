# README

## Description

The script file `gen_config.sh` allow you generate multi prover toml in a easy way.

First, you should set these variables according to your environment.

- provers
- stage
- proving_key_paths = ["/mnt/data/zkm/proving.key", "/mnt/data/zkm2/proving.key"]
- tls
- metrics_addr = "0.0.0.0:50011"
- base_dir

Notice that the proving_key_paths should be aligned with [`ProverVersion`](../../proto/src/include/v1/include.proto), each prover version is used to index its proving key download URL.

Then you can run this script in below way.

```bash
bash gen_config.sh
```

### Generate cirtificates

* Stage

```
bash -x certgen.sh --cn stage --ssl-dns localhost --ssl-ip 127.0.0.1,0.0.0.0
```

* Prover

```
bash -x certgen.sh --cn prover1 --ssl-dns localhost --ssl-ip 127.0.0.1,0.0.0.0
```

* Client

```
bash -x certgen.sh --cn client --ssl-dns localhost --ssl-ip 127.0.0.1,0.0.0.0
```