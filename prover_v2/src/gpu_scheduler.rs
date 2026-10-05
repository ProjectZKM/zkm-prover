#![cfg(feature = "gpu")]

use std::sync::{mpsc, Arc};
use std::thread::{self, JoinHandle};

use anyhow::{anyhow, Context};
use crossbeam_channel::{unbounded, Receiver, Sender, TryRecvError};
use zkm_gpu_core::cuda_runtime;

use crate::agg_prover::AggProver;
use crate::contexts::{AggContext, ProveContext};
use crate::root_prover::RootProver;
use zkm_gpu_prover::{GpuProverHandle, MultiGpuProver};

/// A clonable dispatcher for submitting GPU jobs.
#[derive(Clone)]
pub struct GpuJobDispatcher {
    inner: Arc<GpuJobInner>,
}

struct GpuJobInner {
    root_tx: Sender<JobMessage>,
    agg_tx: Sender<JobMessage>,
}

enum JobMessage {
    Root {
        ctx: ProveContext,
        result_tx: mpsc::Sender<anyhow::Result<(usize, Vec<u8>)>>,
    },
    Agg {
        job_id: u64,
        ctx: AggContext,
        result_tx: mpsc::Sender<(u64, anyhow::Result<Vec<u8>>)>,
    },
    Shutdown,
}

impl GpuJobDispatcher {
    pub fn submit_root(
        &self,
        ctx: ProveContext,
        result_tx: mpsc::Sender<anyhow::Result<(usize, Vec<u8>)>>,
    ) -> anyhow::Result<()> {
        self.inner
            .root_tx
            .send(JobMessage::Root { ctx, result_tx })
            .map_err(|e| anyhow!("failed to dispatch root job: {e}"))
    }

    pub fn submit_agg(
        &self,
        job_id: u64,
        ctx: AggContext,
        result_tx: mpsc::Sender<(u64, anyhow::Result<Vec<u8>>)>,
    ) -> anyhow::Result<()> {
        self.inner
            .agg_tx
            .send(JobMessage::Agg {
                job_id,
                ctx,
                result_tx,
            })
            .map_err(|e| anyhow!("failed to dispatch aggregation job: {e}"))
    }
}

pub struct GpuJobPool {
    dispatcher: Option<GpuJobDispatcher>,
    workers: Vec<JoinHandle<()>>,
}

impl GpuJobPool {
    pub fn new(pool: Arc<MultiGpuProver>, worker_count: usize) -> anyhow::Result<Self> {
        let available = pool.len();
        if available == 0 {
            return Err(anyhow!("no GPU provers available"));
        }
        let worker_count = worker_count.max(1).min(available);

        let (root_tx, root_rx) = unbounded();
        let (agg_tx, agg_rx) = unbounded();
        let dispatcher = GpuJobDispatcher {
            inner: Arc::new(GpuJobInner { root_tx, agg_tx }),
        };

        let mut workers = Vec::with_capacity(worker_count);
        let root_prover = Arc::new(RootProver::default());
        let agg_prover = Arc::new(AggProver::default());

        for i in 0..worker_count {
            let handle = pool
                .get(i)
                .with_context(|| format!("missing GPU handle at index {i}"))?;
            let worker_root_rx = root_rx.clone();
            let worker_agg_rx = agg_rx.clone();
            let root_prover = Arc::clone(&root_prover);
            let agg_prover = Arc::clone(&agg_prover);

            workers.push(thread::spawn(move || {
                worker_loop(
                    i,
                    handle,
                    worker_root_rx,
                    worker_agg_rx,
                    root_prover,
                    agg_prover,
                )
            }));
        }

        Ok(Self {
            dispatcher: Some(dispatcher),
            workers,
        })
    }

    pub fn dispatcher(&self) -> GpuJobDispatcher {
        self.dispatcher.as_ref().unwrap().clone()
    }
}

impl Drop for GpuJobPool {
    fn drop(&mut self) {
        if let Some(dispatcher) = self.dispatcher.take() {
            // Send shutdown signals equal to worker count.
            for _ in 0..self.workers.len() {
                let _ = dispatcher.inner.root_tx.send(JobMessage::Shutdown);
            }
            for _ in 0..self.workers.len() {
                let _ = dispatcher.inner.agg_tx.send(JobMessage::Shutdown);
            }
            drop(dispatcher);
        }
        for handle in self.workers.drain(..) {
            let _ = handle.join();
        }
    }
}

fn worker_loop(
    idx: usize,
    handle: Arc<GpuProverHandle>,
    root_rx: Receiver<JobMessage>,
    agg_rx: Receiver<JobMessage>,
    root_prover: Arc<RootProver>,
    agg_prover: Arc<AggProver>,
) {
    loop {
        let job = match root_rx.try_recv() {
            Ok(job) => Some(job),
            Err(TryRecvError::Empty) => match crossbeam_channel::select! {
                recv(root_rx) -> msg => msg.ok(),
                recv(agg_rx) -> msg => msg.ok(),
            } {
                Some(job) => Some(job),
                None => return,
            },
            Err(TryRecvError::Disconnected) => match agg_rx.recv() {
                Ok(job) => Some(job),
                Err(_) => None,
            },
        };

        let Some(job) = job else { return };

        match job {
            JobMessage::Root { ctx, result_tx } => {
                tracing::info!("GPU {idx} processing root job");
                let res = root_prover
                    .prove_with_gpu_handle(idx, &handle, &ctx)
                    .map(|proof| (ctx.index, proof));
                let _ = result_tx.send(res);
            }
            JobMessage::Agg {
                job_id,
                ctx,
                result_tx,
            } => {
                tracing::info!("GPU {idx} processing agg job");
                let res = agg_prover.prove_with_gpu_handle(idx, &handle, &ctx);
                let _ = result_tx.send((job_id, res));
            }
            JobMessage::Shutdown => return,
        }
    }
}
