# zkm-prover

A parallel proving service for [ZKM](https://github.com/ProjectZKM/zkm).

## Stage Workflow

```mermaid
graph TD
    Init --> Split;
    Split --> Prove;
    Prove --prove_tasks--> Agg;
    Prove --composite_proof?--> End;
    Agg --> Snark;
    Snark --> End;
```

| Stage | Input        | Action              | In Disk/Memory |
|-------|--------------|---------------------|----------------|
| Init  | GenerateTask | gen_split_task      | Memory         |
| Split | SplitTask    | gen_prove_task      | Disk           |
| Prove | ProveTask    | gen_agg_task or END | Memory         |
| Agg   | AggTask      | gen_snark_task      | Memory         |
| Snark | SnarkTask    | END                 | Memory         |

This repository consists of a stage service and multiple prover nodes. Each node can run a proving task.

```mermaid
graph TD
    User --> Stage;
    Stage <-- read,write,update --> Database;
    Stage -- record metrics --> Metrics;
    Stage <-- grpc --> Executor;
    Stage <-- grpc --> ProveNodes; 
```

For the Stage, it provides the functions as below.

| Method         | In Disk/Database | Functionality                     |
|----------------|------------------|-----------------------------------|
| generate_proof | Disk, Database   | Submit a proof generation request |  
| get_status     | Database         | Query the task status             | 

For each ProverNodes, it begins to serve after registering to the Stage, and provides the functions as below.

| Method          | Hardware Dependency | Functionality                                                            |
|-----------------|---------------------|--------------------------------------------------------------------------|
| split_elf       | Disk, IO            | Split the ELF program into multiple segments, dump the segment into disk |  
| prove           | Memory, GPU         | Prove the batches                                                        |
| aggregate       | Memory, GPU         | Aggregate the two batch proofs                                           |
| snark_proof     | Memory, CPU or GPU  | Generate the SNARK proof of the stark verifier on large field            |
| get_status      | Memory, CPU         | Query the prover's status, Idle or Computing                             | 
| get_task_result | Memory, CPU         | Query the task status, returning 200 or else.                            | 

A ProverNode can be an instance to run `prove`, `aggregate`, or `snark_proof`. Consider that, the `snark_proof` can not
utilize the GPU accelerator,
it's necessary to schedule different instance onto different machine by its resource requirement to realize hardware
affinity for better machine utilization.

Especially, `split_elf` reads the ELF from the disk, which is written by the `Stage`'s `GenerateTask`, this means its
corresponding `ProverNode` should be able to access the `Stage`'s disk. Currently, the shared filesystems, like AWS S3
or NFS, are employed to make it possible.
This additional dependency of the `proof-service` can be practical in short-term, but it's best to transit the data by
`GRPC` directly in the long-term[TODO].

### Dataflow

```mermaid
sequenceDiagram
    User ->> Stage Service: Submit GenerateTask by Stage Client(GRPC)
    Stage Service ->> Stage: GenerateTask and generate all the computing graph
    Stage ->> Prover Client: Generate Tasks, SplitELF, Prove, Agg, Snark, and puts them in the Cache
    Prover Client ->> Prover Service: Submit tasks to remote ProveNode by GRPC
    Prover Service ->> Provers: Call the specific provers to finish the tasks.
    Provers ->> Prover Service: Response of each tasks
    Prover Service ->> Prover Client: Response of each tasks by GRPC
    Prover Client ->> Stage: Update the task's output and status (including the cahce), update the database
    User ->> Stage Service: Get task status by Stage Client(GRPC)
```

## Local Deployment

### MySQL

Install Docker for your platform, and run the MySQL container.

```aiignore
docker pull mysql:latest
docker run --name db-proof-service -e MYSQL_ROOT_PASSWORD=123456 -v ./initdb.d:/docker-entrypoint-initdb.d/initdb.sql -p 3306:3306 -d mysql:latest
# Create database zkm

```

For Ziren:

1. Launch the Mysql service.
```
docker run --name zkm-mysql -e MYSQL_ROOT_PASSWORD=123456 -e MYSQL_DATABASE=zkm2 -e MYSQL_USER=stage -e MYSQL_PASSWORD=123456 -p 3306:3306 -v /var/mysql-data:/var/lib/mysql  -d mysql:latest
```

You can use `docker exec -it zkm-mysql  mysql -u stage -p` to login the database and check out the schemes.

2. Migrate the tables

set your `DATABASE_URL`, like `DATABASE_URL=mysql://stage:${password}@localhost/zkm2`.

```
cargo install sqlx-cli
sqlx migrate run
```

### Prover

Create the prover nodes `config.toml` by [gen_config.sh](./proof-service/config/gen_config.sh).

Start

```
export RUST_LOG=info; nohup ./target/release/proof-service --config ./proof-service/config/config.toml > prover.out &
```

### Stage

Create the stage server `config.toml` by [gen_config.sh](./proof-service/config/gen_config.sh), and set up the `prover_addrs`.

Start

```
export RUST_LOG=info; nohup ./target/release/proof-service --stage --config ./proof-service/config/stage.toml > stage.out &
```

### File Server

Use [Static Web Server](https://static-web-server.net/getting-started/) as the file server.

```
cargo install static-web-server
static-web-server --port 40000 --root /tmp/zkm/
```

### Run Reth

1. Add your address to whilitest

```
INSERT INTO user (address) VALUES ('$your address without 0x prefix');
```

2. Generate your certificate as per to [config](./proof-service/config/README.md)


3. Prove your program 

A simple example would be like Fibonacci.

```
cd examples/host
# configure your network prover
cargo run -r
```

For Reth:
```
git clone https://github.com/ProjectZKM/reth-processor -b stateless

cargo run -r -- --block-number 23794449  --rpc-url ${your rpc} --debug-rpc-url ${your debug rpc} --chain-id 1 --prove

```