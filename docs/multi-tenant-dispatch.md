# Cross-machine scheduling of several block streams

## Principle

The GPU server already does everything inside a box: it owns the cards it is
given, runs one persistent core worker per card, overlaps the reduce tree with
the core shards, farms the root's grinds over every card and drains the leaf
backlog with several host threads. A block does not need more than one box
(a mainnet block proves in ~20 s on two cards, ~10 s on eight; a GOAT block
in 3-5 s on one). So the prover service stops scheduling GPUs. It schedules
**machines**: which box proves which block of which tenant, and when.

What goes: the in-process GPU path of `prover_v2` (`GpuJobPool`,
`MultiGpuProver::autodetect`, `GPU_POOL_THREADS`, the `gpu` feature) and the
notion that a task takes "all the cards of the node". What stays: the stage
(request intake, database, queue, status), the split / prove / aggregate /
SNARK path for programs too large for one box, and the SNARK wrapper.

## The streams

| tenant | block | cycles per block | prove time (RTX 5090) | arrival | what matters |
|---|---|---|---|---|---|
| Ethereum mainnet (EthProofs) | 10-50 M gas | 150-400 M | ~20 s on 2 cards, ~10 s on 8 | one block every 12 s | latency of each block |
| GOAT testnet | 0-300 k gas, 92 % empty | 3-6 M | 3.3-5 s on 1-4 cards (pipeline floor) | bursty, mostly idle | throughput and cost |

Two facts drive the design. A small tenant's block on a box the large tenant
needs delays the large tenant's next block by the whole small block. And a
box that alternates programs pays ~1.7 s per switch per card (host key ~93 MB,
device key staging ~1.4 s), so a program should stay where it runs.

## 1. Nodes

A node is one GPU server endpoint: a box, or a disjoint set of cards on a box
when a box is split between tenants (two servers, two card lists; the control
plane does not know or care which). Each node is registered with:

| field | meaning |
|---|---|
| `endpoint` | the server's address |
| `cards` | how many cards it owns, for capacity estimates |
| `programs` | the programs whose keys it holds hot, with the last time each was used |
| `tenants` | the tenants allowed on it, and whether it is reserved for one |
| `health` | last `Ready` probe, in-flight block, last failure |

Nodes are configured statically first (a list per deployment); discovery
comes later.

## 2. Tasks

`GenerateProofRequest` gains `tenant`, `program_id` (the guest vk hash;
`elf_id` today), `class` (`latency` or `batch`), an optional `deadline` and a
`dedupe_key` (`chain id, block number`). A task is a whole block: the program
and its serialized input (7-13 MB for a mainnet block), proved stateless on
one node, returning the compressed proof (~280 KB). The split / prove /
aggregate stages are a different task kind for programs that exceed one box,
not the path of a block.

Each tenant has its own queue with `max_in_flight` and a depth cap; a full
queue answers `RESOURCE_EXHAUSTED` and the tenant's poller retries at its next
block. A resubmitted `dedupe_key` returns the existing task.

## 3. Placement

For a ready task the scheduler picks a node by:

1. **Eligibility**: the tenant is allowed on the node; the node is healthy.
2. **Reservation**: a tenant's reserved nodes come first. The latency tenant
   may also take a batch tenant's idle node (an idle node is one with an
   empty queue and no in-flight block); a batch tenant never takes a latency
   tenant's node, reserved or not.
3. **Affinity**: among eligible nodes, prefer one that holds the program hot;
   a cold node costs the switch.
4. **Earliest finish**: `now + backlog of the node + estimated prove time`,
   the estimate from the block's gas or cycle count and the node's card count
   (learned per program from past blocks).

Inside a tenant, `latency` before `batch`, then deadline, then FIFO. There is
no preemption: a node finishes the block it is on.

## 4. Throughput tenants: blocks faster than the floor

GOAT produces a block every 3 s, and one proof costs 3.3-5 s whatever the
card count, because a GOAT block is one or two shards and the time is the
pipeline floor (core shard, leaf, compose, root with the compress-schedule
grinds). No single node proves such a stream block by block in real time;
the stream has to be served by throughput, in two ways that compose.

**Concurrent blocks, one node per card.** A block that small does not use a
second card, so a box serving a throughput tenant is split into one node
per card (one GPU server per card, from the control plane's point of view
just more nodes), and the scheduler keeps several consecutive blocks in
flight at once. Each block still takes ~5 s on its card, but the stream
advances at one block per 5 s / nodes: two cards sustain one block per
2.5 s (enough for a 3 s chain, with a lag of one or two blocks), four cards
one per 1.25 s. The dedupe key keeps a retried block from being proved
twice, and proofs are delivered in block order by the stage, not by the
nodes.

**Range tasks.** Where the consumer does not need one proof per block, the
stage groups consecutive blocks into one task: a window of `k` blocks or
`t` seconds, whichever closes first, proved by a guest that executes the
blocks of the range in order, chaining each header to the previous one, and
commits the first and last block hash. The floor is then paid once per
range, and so is anything the guest does per run rather than per block (for
the GOAT guest, parsing the chain's genesis is ~2.6 M of its ~3.3-5 M cycles
per block). Ten GOAT blocks are 15-25 M cycles, one or two shards, 4-6 s on
one node: under a second per block, with a lag of one window. The range
task is the batch tenant's default; the per-block task stays for the
latency tenant.

**A cheaper schedule.** A range proof that only feeds an aggregator (not a
chain verifier) can skip the compress schedule's grinds and keep the larger
proof; that takes roughly a second off the floor. This is a per-tenant
option on the task, honoured by the node.

Together: two cards split into two nodes prove a 3 s chain block by block
with a two-block lag, and the same two cards prove it as ten-block ranges
with four times the headroom.

## 5. Failure and retry

- `Ready` probes per node; a node that fails a probe takes no new task and its
  in-flight task is retried elsewhere after its timeout.
- A proof request that fails (a refused node, a timeout, a transport error)
  is retried once on another node; the `dedupe_key` makes the retry
  idempotent. A second failure fails the task with the node's error text.
- A node drains on request: no new tasks, in-flight finishes, then it is
  removed from the registry. Per-tenant drain the same way.

## 6. Keys

Leaf keys depend on the shard's shape, compose and root keys on nothing of
the guest, so one allowed-key map serves every tenant and every node. A new
program is gated once with key verification on before it is admitted; a
shape outside the map regenerates the map, no ceremony. Guest verifying keys
are an allow-list per tenant on intake.

## 7. Phases

1. **Routing only.** Nodes in configuration, tenant to node list, queue per
   tenant, stateless prove over the existing GPU server API. On one box this
   is one server per card set; a throughput tenant gets one node per card
   and several blocks in flight.
2. **Placement.** Reservations, latency-only borrowing, affinity, the
   finish-time estimate, health and retry.
3. **Simplification.** Remove the in-process GPU path from `prover_v2`; the
   remaining split / aggregate / SNARK code runs through the same nodes.

## 8. Operations

Per tenant and per node: queue depth, wait, prove time, program switches,
borrowed node-seconds, failures by reason. Proof retention and the
`dedupe_key` index per tenant. A per-tenant kill switch that drains that
tenant's queue and nothing else.

## Open questions

- Fairness between two latency tenants: weighted shares of the borrowable
  nodes rather than strict priority.
- The range guest: a loop over the stateless executor with the header chain
  checked between blocks, or one stateless input carrying several blocks.
- Node discovery (nodes registering themselves) versus static configuration.
