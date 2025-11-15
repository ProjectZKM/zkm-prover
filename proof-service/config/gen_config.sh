#!/bin/bash

# You should provide some variable to use this config bash
#provers=("localhost:50001" "localhost:50002")
provers=("localhost:50001")
stage="localhost:50000"
snarks=("localhost:50051")
tls=false
base_dir="/tmp/zkm/test/test_proof"

# Generate tls certs
if [ "$tls" = true ]; then
    IFS=':' read -r host port <<< "$stage"
    cd ./../../tools/certs
    bash certgen.sh --cn stage --ssl-dns $host
    rm -rf stage.csr
    id=1
    for prover in "${provers[@]}"; do
        prover_name="prover${id}"
        IFS=':' read -r host port <<< "$prover"
        bash certgen.sh --cn $prover_name --ssl-dns ${host}
        rm -rf ${prover_name}.csr
        ((id++))
    done
    bash certgen.sh --cn client --ssl-dns localhost
    rm -rf client.csr
    rm -rf ca.srl
    rm -rf openssl.cnf
    cd -
fi

# Generate stage toml
# Read templeta content first
if [ "$tls" = true ]; then
    stage_template_content=$(cat stage_tls.toml.template)
else
    stage_template_content=$(cat stage.toml.template)
fi
stage_config="$stage_template_content"
IFS=':' read -r host port <<< "$stage"
stage_config="${stage_config//\{\{addr\}\}/0.0.0.0:${port}}"
# generate prover addrs
prover_addrs=""
for prover in "${provers[@]}"; do
    if [ -z "$prover_addrs" ]; then
        prover_addrs="$prover"
    else
        prover_addrs="$prover_addrs\", \"$prover"
    fi
done
stage_config="${stage_config//\{\{prover_addrs\}\}/\"${prover_addrs}\"}"
stage_config="${stage_config//\{\{base_dir\}\}/${base_dir}}"
if [ "$tls" = true ]; then
    echo "$stage_config" > stage_tls.toml 
else
    echo "$stage_config" > stage.toml 
fi

# Generate provers toml
# Read templeta content first
if [ "$tls" = true ]; then
    prover_template_content=$(cat prover_tls.toml.template)
else
    prover_template_content=$(cat prover.toml.template)
fi

id=1
for prover in "${provers[@]}"; do
    if [ "$tls" = true ]; then
        prover_path="prover${id}_tls.toml"
    else
        prover_path="prover${id}.toml"
    fi
    IFS=':' read -r host port <<< "$prover"
    prover_config="$prover_template_content"
    addr="0.0.0.0:${port}"
    prover_config="${prover_config//\{\{addr\}\}/${addr}}"
    prover_config="${prover_config//\{\{prover_addrs\}\}/\"${addr}\"}"
    prover_config="${prover_config//\{\{base_dir\}\}/${base_dir}}"
    prover_config="${prover_config//\{\{prover_name\}\}/prover${id}}"
    if [ "$tls" = true ]; then
        echo "$prover_config" > "prover${id}_tls.toml"
    else
        echo "$prover_config" > "prover${id}.toml"
    fi
    ((id++))
done
