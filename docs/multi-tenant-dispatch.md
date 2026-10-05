# Cross-machine scheduling of several proof streams

## Principle

The GPU server already does everything inside a box: it owns the cards it is
given, runs one persistent core worker per card, overlaps the reduce tree with
the core shards, farms the root's grinds over every card and drains the leaf
backlog with several host threads. A proof does not need more than one box
(a mainnet block proves in ~20 s on two cards, ~10 s on eight; a GOAT
state-chain step is of the same size). So the prover service stops scheduling
GPUs. It schedules **machines**: which box proves which task of which tenant,
and when, plus the one stage that is not GPU work, the Groth16 wrap.

What goes: the in-process GPU path of `prover_v2` (`GpuJobPool`,
`MultiGpuProver::autodetect`, `GPU_POOL_THREADS`, the `gpu` feature) and the
notion that a task takes "all the cards of the node". What stays: the stage
(request intake, database, queue, status), the split / prove / aggregate /
SNARK path for programs too large for one box, and the SNARK wrapper.

## 1. The tenants and their tasks

Two tenants exist today and they are not alike.

**EthProofs (Ethereum mainnet).** One task per block, every 12 s, 150-400 M
cycles, independent of every other block; the result is the compressed proof
(~280 KB), no wrap. What matters is the latency of each block.

**GOAT (the BitVM proof builder).** Five guest programs, submitted through
the stage API exactly as today (`GenerateProofRequest` with `elf_id`, the ELF
sent once, target step SNARK, polled with `GetStatus`); every one of them ends
in a Groth16 proof:

| program | trigger | one task is | in-guest work | observed cycles |
|---|---|---|---|---|
| header chain | every `batch_size` Bitcoin blocks past the confirmation depth (10 in the configuration, ~100 min of chain) | the previous proof + the new headers | verify the previous Groth16 proof, extend the header chain | 16.6-16.9 M per step |
| commit chain | a sequencer-set commitment on Bitcoin (manual, rare) | the previous proof + one commitment | verify the previous proof, check the commitment | one step per commitment |
| state chain | every `batch_size` GOAT blocks (40 in the configuration, 120 s of chain at one block per 3 s) | the previous proof + the blocks of the window | verify the previous proof; per block execute the EVM block, check the withdrawals, verify the Cosmos light block | 46.8-50.9 M per 4-block step in the builder's own log, so a 40-block step is on the order of a mainnet block |
| watchtower | a signed API request during a challenge | the three chain proofs + the challenge transaction | verify three Groth16 proofs, SPV of the challenge | one task per request |
| operator | a signed API request during a challenge | the three chain proofs + every watchtower proof + the withdrawal state | verify three or more Groth16 proofs, check each watchtower proof and the Gateway state | one task per request |

Four properties of these tasks drive the design more than their size.

1. **The chain programs are serial by construction.** Step *n* verifies the
   Groth16 proof of step *n − 1* inside the guest, so step *n* cannot start
   before step *n − 1* has been proved **and wrapped**. Nothing in the
   scheduler can run two steps of one chain concurrently; the only
   concurrency GOAT offers is across its three chains and its on-demand
   proofs. The throughput of a chain is set by its batch size, and the
   builder already batches: a state-chain step covers 120 s of chain and
   costs a mainnet block's worth of proving, so one two-card node keeps the
   chain real time with a lag of one window plus one step. There is no
   per-block proving problem to solve for GOAT; the per-block arrival rate
   (one block per 3 s) is absorbed by the batch.
2. **Every GOAT proof ends in a Groth16 wrap**, and every step pays a fixed
   in-guest cost for verifying the previous wrap (the whole of a header-chain
   step is that verification plus the window's headers). The wrap is a CPU
   stage with a large host-memory footprint, not GPU work, and one wrap at a
   time per box; it is the second resource the service schedules.
3. **The guest pins a proof-system version.** The previous proof is verified
   against the key of the version recorded next to it, and the builder's
   circuits are built against one Ziren release, while EthProofs runs the
   current main. A node runs one version (one GPU server binary and one set
   of wrap keys); a task names the version it needs; the two never share a
   node.
4. **The on-demand proofs have deadlines.** A watchtower or operator proof is
   requested during a Bitcoin challenge window and the builder has a timeout
   endpoint that marks the task failed. These are the latency tasks of GOAT;
   the chains are throughput tasks.

## 2. Nodes

A node is one GPU server endpoint: a box, or a disjoint set of cards on a box
when a box is split between tenants (two servers, two card lists; the control
plane does not know or care which). Each node is registered with:

| field | meaning |
|---|---|
| `endpoint` | the server's address |
| `version` | the proof-system version the server and its wrap keys implement |
| `cards` | how many cards it owns, for capacity estimates |
| `programs` | the programs (`elf_id`) whose keys it holds hot, with the last time each was used |
| `tenants` | the tenants allowed on it, and whether it is reserved for one |
| `wrap` | whether the box can run a Groth16 wrap, and whether one is running |
| `health` | last `Ready` probe, in-flight task, last failure |

A box that alternates programs pays ~1.7 s per switch per card (host key
~93 MB, device key staging ~1.4 s), so a program should stay where it runs.
Nodes are configured statically first (a list per deployment); discovery
comes later.

## 3. Tasks

`GenerateProofRequest` already carries `elf_id`, the inputs and the target
step; the stage derives the rest at intake rather than asking the builder to
change:

| field | from |
|---|---|
| `tenant` | the request's signer, or the `elf_id` allow-list |
| `version` | the tenant's configuration (the builder's circuits are pinned to one release) |
| `class` | `latency` for operator and watchtower proofs and for EthProofs blocks, `batch` for the chain steps |
| `stream` | for a chain program, the chain it belongs to; a stream has at most one task in flight and its tasks run in submission order |
| `wrap` | whether the target step is SNARK |
| `deadline` | optional; set for the on-demand proofs from the challenge window |
| `dedupe_key` | `elf_id` and the hash of the input stream; a resubmission returns the existing task |

A task is proved stateless on one node of the right version and, when it
needs a wrap, wrapped on a box of that version, which may be the same box or
a wrap-only box. Each tenant has its own queue with `max_in_flight` and a
depth cap; a full queue answers `RESOURCE_EXHAUSTED` and the submitter
retries. The split / prove / aggregate stages are a different task kind for
programs that exceed one box, not the path of a block or a chain step.

## 4. Placement

For a ready task the scheduler picks a node by:

1. **Eligibility**: the node's version is the task's; the tenant is allowed
   on the node; the node is healthy; a stream task is ready only when its
   predecessor has finished, wrap included.
2. **Reservation**: a tenant's reserved nodes come first. A latency task may
   take a batch tenant's idle node (an idle node is one with an empty queue
   and no in-flight task); a batch task never takes a latency tenant's node,
   reserved or not.
3. **Affinity**: among eligible nodes, prefer one that holds the program hot;
   a cold node costs the switch.
4. **Earliest finish**: `now + backlog of the node + estimated prove time`,
   the estimate from the task's cycle count and the node's card count
   (learned per program from past tasks), plus the wrap queue of the box
   when the task needs one.

Inside a tenant, `latency` before `batch`, then deadline, then FIFO; a
stream's own order is never changed. There is no preemption: a node finishes
the task it is on. The wrap stage has its own queue per box with the same
order, and one wrap runs at a time on a box.

## 5. Streams faster than the floor

A GOAT block arrives every 3 s and the smallest proof costs 3-5 s whatever
the card count (one or two shards; the time is the pipeline floor: core
shard, leaf, compose, root with the compress-schedule grinds). The builder
does not prove blocks: it proves windows, and a window is what the service
should prefer for any stream whose consumer does not need one proof per
block. The floor and the wrap are then paid once per window, and so is
anything the guest does per run rather than per block.

Two shapes of stream exist and they get different treatment:

- **Chained** (the GOAT chains): each step verifies the previous one, so the
  stream is serial and its throughput is `window / (prove + wrap)`. The
  service keeps one task in flight per stream and the lag is one window plus
  one step. To raise throughput the tenant raises the window; to lower the
  lag it lowers it, down to the point where `prove + wrap` of one step
  exceeds the window. If a chain ever needs more than that, the fix is in
  the circuit, not the scheduler: prove windows independently as compressed
  proofs and have the chain step verify several of them at once, which
  turns the serial chain into a tree whose leaves can run on several nodes.
- **Independent per block** (EthProofs): blocks do not depend on one
  another, so a box can be split into one node per card and several blocks
  kept in flight; proofs are delivered in block order by the stage. The
  stream advances at one block per `floor / nodes`.

## 6. Failure and retry

- `Ready` probes per node; a node that fails a probe takes no new task and
  its in-flight task is retried elsewhere after its timeout.
- A proof request that fails (a refused node, a timeout, a transport error)
  is retried once on another node of the same version; the `dedupe_key`
  makes the retry idempotent. A second failure fails the task with the node's
  error text. A failed stream task blocks its stream until it is retried or
  the builder resubmits the step; the stream never skips a step.
- A node drains on request: no new tasks, in-flight finishes, then it is
  removed from the registry. Per-tenant drain the same way.

## 7. Keys

Leaf keys depend on the shard's shape, compose and root keys on nothing of
the guest, so within one version a single allowed-key map serves every tenant
and every node; a second version brings its own map and its own wrap keys. A
new program (`elf_id`) is gated once with key verification on before it is
admitted; a shape outside the map regenerates the map, no ceremony. Guest
verifying keys are an allow-list per tenant on intake, and the builder's
program upgrades (a new `elf_id` for the same chain) are admitted the same
way, since the chain program accepts a predecessor with a different program
id and records the upgrade in its history.

## 8. Phases

1. **Routing only.** Nodes in configuration with their version, tenant to
   node list, queue per tenant, one task in flight per stream, stateless
   prove over the existing GPU server API, wrap on the proving box. GOAT's
   builder works unchanged on a node of its release; EthProofs on a node of
   main.
2. **Placement.** Reservations, latency-only borrowing, affinity, the
   finish-time estimate with the wrap queue, health and retry, deadlines for
   the on-demand proofs.
3. **Simplification.** Remove the in-process GPU path from `prover_v2`; the
   remaining split / aggregate / SNARK code runs through the same nodes and
   the same wrap queue.

## 9. Operations

Per tenant and per node: queue depth, wait, prove time, wrap time, program
switches, borrowed node-seconds, failures by reason. Per stream: the lag
between the chain's head and the last proved window, and the time of each
step split into fetch, prove and wrap. Proof retention and the `dedupe_key`
index per tenant. A per-tenant kill switch that drains that tenant's queue
and nothing else.

## Open questions

- Fairness between two latency tenants: weighted shares of the borrowable
  nodes rather than strict priority.
- Whether a box that both proves and wraps should accept a new prove while
  it wraps (the wrap is CPU and memory; the prove is GPU and some CPU), or
  whether wrapping moves to CPU-only boxes.
- The tree shape for a chain that outgrows one serial step: how many window
  proofs one chain step should verify, and whether the window proofs are
  compressed or wrapped.
- Node discovery (nodes registering themselves) versus static configuration.
