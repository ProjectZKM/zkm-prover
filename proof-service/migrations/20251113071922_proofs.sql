-- Add migration script here
CREATE TABLE IF NOT EXISTS proofs
(
    id                  serial primary key,
    proof_id            text      not null,
    computed_request_id text      not null,
    proof               blob      not null,
    created_at          timestamp not null default now(),
    INDEX proof_id_req_id(proof_id(255), computed_request_id(255))
);