-- Add migration script here
CREATE TABLE IF NOT EXISTS prover_job_queue
(
    id                  serial primary key,
    job_status          int       not null,
    job_priority        int       not null,
    job_type            text      not null,

    created_at          timestamp not null default now(),
    updated_by          text      not null,
    updated_at          timestamp not null default now(),

    proof_id            text      not null,
    computed_request_id text      not null,
    job_data            json      not null,
    INDEX proof_id_req_id(proof_id(255), computed_request_id(255)),
    INDEX job_status_updated_at(job_status, updated_at),
    INDEX job_type(job_type(255))
);