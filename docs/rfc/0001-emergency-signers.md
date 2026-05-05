# RFC-0001: Emergency Signer Recovery via Threshold Signatures

| Field      | Value                                            |
|------------|--------------------------------------------------|
| RFC Number | 0001                                             |
| Title      | Emergency Signer Recovery via Threshold Signatures |
| Status     | Draft                                            |
| Type       | Standards Track (consensus change)               |
| Created    | 2026-05-05                                       |
| Authors    | ALFIS Project                                    |

## Abstract

ALFIS uses a Limited Confidence Proof-of-Activity scheme in which every
domain-bearing block ("full block") must be locked by at least four
signing blocks produced by a quorum of seven historically eligible
signer keys. The set of eligible signers is drawn from past block
authors and is therefore bounded by the early history of the chain.
Today this set is concentrated in roughly sixteen keys held by five to
six individuals. The chain is at risk of permanent stall if a critical
fraction of these key holders becomes unavailable simultaneously.

This RFC defines an emergency recovery mechanism that allows the
community to unfreeze a stalled chain and replace the eligible signer
set with a new, deliberately distributed list of live keys. The
mechanism uses an Ed25519 threshold signature (FROST, RFC 9591) held by
a `M`-of-`N` quorum of community members. The emergency private key
never exists in full on any single machine at any point in time; it is
constructed as a set of FROST shares from inception. Recovery requires
out-of-band social coordination plus a single in-protocol round of
gossip-mediated message exchange.

The mechanism is designed to never trigger under normal operation or
during short-term network splits, and to require explicit human action
even when its time-based precondition is met.

## 1. Motivation

### 1.1 The current signer model

Beginning at block index `BLOCK_SIGNERS_START` (currently 35), every
full block must be followed by at least `BLOCK_SIGNERS_MIN` (currently 4)
signing blocks before the next full block is permitted. The set of
seven eligible signers for a given full block is selected
pseudorandomly from past block authors, filtered by a minimum block
count of `block.index / 100`. See `src/blockchain/chain.rs` function
`get_block_signers()` for the reference implementation.

This filter ensures that a freshly minted attacker key cannot become a
signer cheaply, but it has a side effect: the higher the chain grows,
the harder it is for any new key to ever qualify. At the time of
writing the chain is at index ~21,735, requiring ~217 blocks per key
to qualify. The eligible signer set is therefore effectively frozen
to a small group of long-time participants.

### 1.2 The bus factor

Independent surveys of the eligible signer set indicate that
approximately 16 keys held by 5-6 individuals dominate signer
selection. If a sufficient fraction of these holders becomes
simultaneously unavailable - through death, loss of interest, hardware
failure, prolonged absence, or coercion - no random selection of seven
signers will yield the four signatures required to advance the chain.
The chain stops permanently.

A direct measurement of the chain at height 21,755 (2026-05-05)
confirms this concentration empirically:

* Of 695 distinct keys that have ever produced a block, only **16**
  meet the current `min_block_count = height / 100 = 217` threshold
  and are eligible to be selected as signers.
* The top 9 of these 16 keys produce **88-92%** of all signing
  blocks across every measured window (entire chain, last 10000,
  last 1000, last 100). Concentration is mildly increasing over
  time, not decreasing.
* Of the top 5 most-active keys, **four belong to a single
  individual**. A unilateral departure of that individual would
  remove approximately half of all current signing capacity in a
  single event.

This last observation is decisive: the bus-factor risk is not a
distant theoretical concern, it is a live operational reality.

### 1.3 The CAP positioning

ALFIS today is operationally a CP system: in the presence of a
network partition, both partitions correctly refuse to produce
divergent state. This RFC preserves CP behaviour in all realistic
short- and medium-term partition scenarios. It introduces a narrow,
human-gated path to availability that activates only after a duration
greatly exceeding plausible partitions, and even then only with
explicit cryptographic action by `M` independent parties.

### 1.4 Goals

1. Permit unfreezing the chain when a critical fraction of historical
   signers is permanently lost.
2. Replace the eligible signer set with a new, geographically and
   socially diverse list of live keys, capped per individual.
3. Require explicit social coordination - the mechanism cannot be
   triggered by an automated timer alone.
4. Ensure the emergency private key never exists in reconstructable
   form on any single machine.
5. Preserve all existing rules about domain ownership and identity:
   the emergency mechanism unfreezes the chain but does not grant any
   ability to seize existing domains.
6. Add the smallest possible surface area to consensus: one new block
   class, one new signature verification path, one new block-author
   exception for the emergency public key.

### 1.5 Non-goals

1. This RFC does not address short-term censorship resistance. A
   hostile partition lasting under one week is still expected to
   freeze the chain.
2. This RFC does not introduce a general-purpose governance system.
   The emergency public key has exactly one power: replacing the
   eligible signer list when the chain is stalled.

## 2. Terminology

| Term | Definition |
|------|------------|
| `EMERGENCY_PUBKEY` | A 32-byte Ed25519 public key compiled into ALFIS. The corresponding private key exists only as FROST shares. |
| Share holder | One of the `N` individuals holding a FROST share of `EMERGENCY_PUBKEY`. |
| Auth key | A separate Ed25519 keypair owned by a share holder, used to authenticate gossip messages during a recovery session. Not the FROST share. |
| Auth pubkey list | The list of auth public keys for the current set of share holders, configured as hex strings in node configuration. |
| Recovery session | A single attempt to produce one emergency block, identified by the hash of the most recent full block being unfrozen. |
| Emergency block | A block of class `CLASS_SIGNERS_UPDATE` whose author public key is `EMERGENCY_PUBKEY`. Contains the new eligible signer list. |

## 3. Specification

### 3.1 Activation

This RFC activates at chain height `EMERGENCY_ACTIVATION_HEIGHT`
(value to be set during the release that ships this RFC, chosen to
provide adequate upgrade time for nodes). Below this height the rules
in this RFC have no effect.

A node that has not been upgraded to support this RFC will reject
emergency blocks as malformed. Operators are required to upgrade
before `EMERGENCY_ACTIVATION_HEIGHT`.

### 3.2 The emergency public key

A single 32-byte Ed25519 public key is compiled into the binary as
the constant `EMERGENCY_PUBKEY`. The corresponding private key is
generated through a Distributed Key Generation ceremony (RFC 9591
section 3) among the initial `N` share holders, or alternatively
through a Shamir-style split immediately followed by destruction of
the original key. See section 7 for the long-term ceremony
considerations.

The chosen scheme is `M`-of-`N` = 5-of-9.

### 3.3 New block class

A new transaction class is introduced:

```
CLASS_SIGNERS_UPDATE = "signers_update"
```

A block of this class:

1. MUST have `pub_key` equal to `EMERGENCY_PUBKEY`.
2. MUST have a valid Ed25519 signature over the canonical block bytes,
   verifiable against `EMERGENCY_PUBKEY`. The signature is produced
   through FROST aggregation; from the verifier's perspective it is
   indistinguishable from a regular Ed25519 signature.
3. MUST have a transaction whose `data` field carries a list of
   between 7 and 15 inclusive 32-byte Ed25519 public keys, in strict
   ascending lexicographic order, with no duplicates. These are the
   replacement signer keys.
4. MUST have `difficulty` equal to `SIGNER_DIFFICULTY` (16). The
   computational barrier exists only to anchor the block in the chain
   and prevent trivial block-spam; its security weight is provided by
   the threshold signature, not by PoW.

The serialization format of the signer list within `data` is the
concatenation of the 32-byte public keys in order, optionally framed
by a length-prefix consistent with existing transaction encoding (the
exact framing is delegated to the reference implementation, with the
constraint that it MUST be canonical: there is exactly one valid
encoding for any given list).

### 3.4 Activation precondition for emergency blocks

An emergency block is only valid if the chain is in a stalled state
at the time it is being added. Specifically, let `last_full` be the
most recent full block (any block whose `transaction` field is
non-empty, including a previous emergency block). An emergency block
`B` is valid only if:

```
B.timestamp - last_full.timestamp >= EMERGENCY_TIMEOUT_SECONDS
```

with `EMERGENCY_TIMEOUT_SECONDS = 7 * 86400 = 604800`.

Rationale: signing blocks normally arrive within minutes of their
full block. A gap of one week between full blocks indicates either
that the signer quorum has failed to assemble, or that the chain has
been intentionally idle with no new domain activity. In the latter
case there is no operational reason to issue an emergency block at
all, so a benign emergency block is equivalent to a no-op signer
update.

The condition is checked against `last_full.timestamp` regardless of
whether intermediate signing blocks were produced. A full block
locked by two signatures and stalled for a week qualifies for
emergency unfreezing in exactly the same way as a full block with
zero signatures.

### 3.5 Locking rule for emergency blocks

After an emergency block at height `H_e`, the next full block
(domain-bearing) is permitted only after `BLOCK_SIGNERS_MIN`
signing blocks produced by signers from the new list defined in
`H_e`. The signing blocks themselves follow standard rules; they are
NOT signed by `EMERGENCY_PUBKEY` and are NOT eligible for any
relaxed validation. The emergency mechanism produces exactly one
block per recovery session.

The `EMERGENCY_PUBKEY` MUST NOT appear as the author of any
non-emergency block. A signing block authored by `EMERGENCY_PUBKEY`
is invalid. A regular full block authored by `EMERGENCY_PUBKEY` is
invalid. The emergency public key has exactly one role: signing
emergency blocks of class `CLASS_SIGNERS_UPDATE`.

### 3.6 Replacement of the signer pool

After the most recent emergency block at height `H_e`, the function
`get_block_signers(full_block)` for any `full_block` with
`full_block.index > H_e` returns its result by selecting from the
list of public keys in the emergency block at `H_e`, NOT from
historical block authors. The selection mechanism preserves the
existing seed derivation (`block.signature.get_tail_u64()`) but
removes the `min_block_count` filter, since fresh keys have not yet
mined any blocks.

The emergency list always contains `K` keys with 7 ≤ K ≤ 15
(enforced at block validation time, see section 3.3). The quorum
parameters remain unchanged from normal operation:
`BLOCK_SIGNERS_ALL = 7` candidates, `BLOCK_SIGNERS_MIN = 4`
required. Selection of the 7 candidates from the K-element list
uses the existing seed mechanism
(`tail.wrapping_mul(count) % window`) applied to the emergency
list as the candidate array, with the `min_block_count` filter
removed (fresh keys have not yet mined any blocks).

For the canonical case K = 7, all keys from the emergency list are
selected as signers, preserving the historical 4-of-7 quorum. For
K > 7, the deterministic seed picks 7 distinct keys.

A signer list with K < 7 is invalid and the emergency block
carrying it MUST be rejected. Refer also to section 3.3, which
treats this as a block-level invariant, and section 3.7.3, which
treats it as a session-level abort condition.

A subsequent emergency block at a later height fully replaces the
list of the previous one. Emergency blocks are not cumulative.

### 3.7 Recovery session protocol

A recovery session produces exactly one emergency block. The protocol
is structured around the fact that `block.signature` covers the
entire block including the mined `nonce` and `random` fields (see
`src/blockchain/hash_utils.rs::check_block_signature`). Therefore the
final FROST signature must be computed only after a valid PoW nonce
has been found, and all share holders must agree on a single
candidate block before producing partial signatures - FROST round-1
nonces are one-time and cannot be reused across multiple candidates.

The protocol proceeds in four phases.

#### 3.7.1 Out-of-band coordination (Phase 0)

Share holders coordinate via an external channel (Mimir, DeltaChat,
Matrix, Signal, mailing list, etc.) to:

1. Confirm that at least `M = 5` share holders are present and able
   to participate. More than 5 MAY participate; any number `s` with
   `5 ≤ s ≤ 9` is valid. Larger `s` increases robustness against
   any one participant subsequently failing to deliver their
   partial signature in Phase 3, since the protocol does not
   tolerate partial-signature dropout once Phase 1 closes (see
   3.7.4).
2. Agree on the new signer list. Each participating share holder
   will contribute between 0 and 3 of their own keys (i.e. keys for
   which they personally hold the corresponding private key, or
   delegated keys belonging to community members they vouch for).
3. Confirm the hash of the full block to be unfrozen
   (`last_full.hash`), which serves as the recovery session
   identifier.

This phase is entirely social and produces no on-protocol artifacts.

#### 3.7.2 Commitment broadcast (Phase 1)

Each participating share holder, using their node, broadcasts a
single `EmergencyCommitment` gossip message:

| Field | Type | Description |
|-------|------|-------------|
| `session_id` | 32 bytes | Hash of the full block being unfrozen. |
| `auth_pubkey` | 32 bytes | Holder's auth public key (must be in the configured auth pubkey list). |
| `keys` | list of 32-byte pubkeys, length 0..3 | Keys this holder contributes to the new signer list. |
| `frost_commitment` | bytes | FROST round-1 hiding+binding commitment per RFC 9591 section 5.1. |
| `auth_signature` | 64 bytes | Ed25519 signature by `auth_pubkey` over a canonical encoding of all preceding fields. |

This message contains NO partial signature: at this stage the block
to be signed does not yet exist, and FROST partial signatures are a
function of the message being signed, the signer's share, the
signer's nonce, and the aggregate of all participants' commitments.
None of these inputs is fully determined yet.

Receiving nodes:

1. Verify `auth_pubkey` is in the configured auth pubkey list. If
   not, drop.
2. Verify `auth_signature` against `auth_pubkey`. If invalid, drop.
3. Verify `keys` contains at most 3 entries with no duplicates. If
   not, drop.
4. Verify `session_id` matches the hash of the current
   `last_full_block`. If not, ignore.
5. Verify the holder has not previously committed in this session
   (one commitment per holder per session). If a duplicate is seen,
   retain the first and drop subsequent ones.
6. Forward via standard gossip to peers.
7. Cache the commitment in memory until the session ends.

Replay protection: every message embeds `session_id =
last_full.hash`. As soon as one emergency block is added, the chain
advances and the hash of the latest full block changes. Messages
from prior sessions become unusable in subsequent sessions.

#### 3.7.3 Candidate construction and mining (Phase 2)

After receiving the first `EmergencyCommitment` for a new
`session_id`, every node opens a **commitment window** of
`T_window = 300 seconds`. During the window, additional commitments
from distinct auth pubkeys are accepted and gossiped. When the
window closes, the set of participants `P` is fixed:

* `P` = the set of distinct auth pubkeys that submitted valid
  `EmergencyCommitment` messages for this `session_id` before the
  window closed.
* The session is viable iff `|P| ≥ M` (i.e. at least 5 share
  holders committed). If `|P| < M`, the session is aborted; share
  holders may begin a fresh session with a new round of
  out-of-band coordination.
* If `|P| > M`, all `s = |P|` participants are bound to this
  session. FROST aggregation in Phase 4 requires the partial
  signatures of all `s` (not just any `M` of them); the threshold
  controls only the minimum entry into Phase 1, not the size of
  the participating set thereafter.

After the window closes, every node can compute deterministically:

* The complete final signer list, by taking the union of all `keys`
  fields from messages in `P`, deduplicating, and sorting
  lexicographically. This list is identical for every node observing
  the same set of commitments.
* The set of FROST commitments needed for partial-signature
  computation in the next phase.

If the resulting key list contains fewer than 7 distinct keys, the
session is malformed and MUST be aborted; share holders are
responsible for ensuring adequate distribution of contributions
during Phase 0. With `s` contributors and a per-contributor cap of
3 keys, the achievable range is `1..3s`; only the 7..15 window is
protocol-valid.

A designated **coordinator** then constructs a candidate block and
mines it. The coordinator is chosen deterministically as the share
holder whose `auth_pubkey` is lexicographically smallest among
those in `P`.

The coordinator constructs:

* `pub_key = EMERGENCY_PUBKEY`
* `prev_block_hash = last_block.hash`
* `index = last_block.index + 1`
* `timestamp` = current wall-clock time
* `difficulty = SIGNER_DIFFICULTY`
* `transaction.class = CLASS_SIGNERS_UPDATE`
* `transaction.data` = canonical encoding of the sorted, deduplicated
  signer key list
* `transaction.identity`, `transaction.confirmation`,
  `transaction.signing`, `transaction.encryption` = empty
* `signature` = empty (placeholder; to be filled in Phase 4)

The coordinator then mines: searches for `nonce` and `random` such
that `hash_difficulty(block.hash) >= SIGNER_DIFFICULTY`, where the
block hash is computed with `signature` zeroed (consistent with
`check_block_hash`). Once found, the coordinator broadcasts the
candidate via a new gossip message:

| Field | Type | Description |
|-------|------|-------------|
| `session_id` | 32 bytes | Same as Phase 1. |
| `auth_pubkey` | 32 bytes | Coordinator's auth pubkey. |
| `candidate_block` | bytes | Fully-mined block with `signature` field zeroed. |
| `auth_signature` | 64 bytes | Ed25519 signature by coordinator's auth pubkey over the canonical encoding of preceding fields. |

Receiving nodes verify:

1. `auth_pubkey` matches the lex-smallest commitment-submitting auth
   pubkey for this session. If not, drop (a non-coordinator is
   attempting to drive the session).
2. `auth_signature` is valid.
3. `candidate_block`'s signer list (decoded from `transaction.data`)
   exactly equals the deterministic union from Phase 1 commitments.
4. `candidate_block` has correct `pub_key` (`EMERGENCY_PUBKEY`),
   `prev_block_hash` (matches current `last_block.hash`), `index`,
   `difficulty`, and a hash that meets `SIGNER_DIFFICULTY`.
5. The block's `timestamp - last_full.timestamp >= 604800` (the
   week-long emergency precondition; see section 3.4).

If all checks pass, gossip the message and proceed to Phase 3.

**Coordinator failover.** If no `EmergencyCandidate` is observed
within `T_coordinator = 600 seconds` after Phase 1 completes, the
role passes to the share holder with the next-smallest auth_pubkey.
Each subsequent coordinator gets the same 600-second window.
A failing coordinator may have crashed, may have been censored, or
may simply lack the hardware to mine `SIGNER_DIFFICULTY = 16` in
reasonable time (in practice, seconds on a modern CPU; ten minutes
is a generous margin).

#### 3.7.4 Partial signing (Phase 3)

Each share holder in `P`, upon receiving and validating an
`EmergencyCandidate`, computes their FROST round-2 partial signature
over the canonical bytes of `candidate_block` (with `signature`
field zeroed - the same bytes covered by `check_block_signature`).
Inputs to the partial signature:

* The signer's share of the FROST private key.
* The signer's round-1 nonce, retained locally from Phase 1.
* The aggregate of round-1 commitments from all `s` participants
  in `P` (visible via gossip).
* The message bytes (zeroed-signature canonical block bytes).

The share holder broadcasts an `EmergencyPartialSignature` message:

| Field | Type | Description |
|-------|------|-------------|
| `session_id` | 32 bytes |  |
| `candidate_hash` | 32 bytes | `block.hash` of the candidate being signed. |
| `auth_pubkey` | 32 bytes |  |
| `frost_partial_signature` | bytes | FROST round-2 output. |
| `auth_signature` | 64 bytes | Ed25519 over preceding fields. |

A share holder MUST sign at most one candidate per session (the
round-1 nonce can only be used once). If two distinct candidates are
observed, share holders sign whichever they validated first and
ignore the second. In practice the deterministic-coordinator rule
ensures only one candidate exists per session under honest
operation; the per-session limit is a defensive backstop.

**Order independence.** Partial signatures may be produced,
broadcast, and aggregated in any order. FROST aggregation is
mathematically commutative: the final signature is the sum of all
participants' partial signatures (with Lagrange coefficients
already baked into each `z_i` by its producer, computed from the
fixed set `P`). Any permutation of partial signatures yields the
same aggregate. Concretely:

* Share holders may compute and broadcast their partial signature
  as soon as they have validated the candidate in their UI; there
  is no need to wait for others to go first.
* Aggregators may collect partial signatures into any data
  structure; sorting before summation is unnecessary.
* Re-delivery of an already-seen partial signature via gossip is
  harmless and is simply deduplicated by `(session_id, auth_pubkey)`.

The only ordering requirement in the entire protocol is the
**phase boundary**: every participant must agree on the set `P`
(determined by the close of the Phase-2 commitment window) and on
the candidate bytes (determined by Phase 2) **before** producing
any partial signature in Phase 3. Once those two facts are fixed,
Phase 3 message arrival order is irrelevant.

Receiving nodes verify the auth signature, verify that
`auth_pubkey` is in `P` (i.e. among the Phase-1 committers for this
session), verify that `candidate_hash` matches the active
candidate, and gossip the message.

#### 3.7.5 Aggregation and propagation (Phase 4)

Any node observing exactly `s` valid `EmergencyPartialSignature`
messages - one from each participant in `P` - for a single
candidate aggregates them per RFC 9591 section 5.3 into a complete
Ed25519 signature, places it in `candidate_block.signature`, and
broadcasts the resulting block through the standard
block-propagation path.

If fewer than `s` partial signatures arrive within a reasonable
window (e.g. 5 minutes after the candidate is broadcast), the
session is dead: FROST aggregation requires partial signatures from
**all** Phase-1 committers, not any subset of size `M`. The
threshold `M` governs only the minimum size of `P` at the close of
Phase 1; once `P` is fixed, every member of `P` must follow through
in Phase 3, otherwise the session is unrecoverable and a fresh
session must be started (with a new round of Phase 0 coordination
and new round-1 commitments).

The block is then validated by all nodes (including non-share-holder
nodes) using ordinary `check_block_signature` against
`EMERGENCY_PUBKEY`. The threshold-signature origin of the signature
is invisible to the validator: it is, by construction, an ordinary
Ed25519 signature.

### 3.8 Configuration: the auth pubkey list

Each node operator configures, in `alfis.toml`:

```toml
[emergency]
auth_pubkeys = [
    "<hex-encoded 32-byte Ed25519 pubkey of share holder 1>",
    "<hex-encoded 32-byte Ed25519 pubkey of share holder 2>",
    # ... up to share holder N
]
```

The list contains all `N = 9` current share holders' auth public
keys. This list is updated in coordination with resharing ceremonies
(section 7).

`EMERGENCY_PUBKEY` itself remains a compile-time constant. Only the
auth keys, used to filter gossip contributions, are configurable.

### 3.9 Share holder node software

A share holder additionally:

1. Loads their FROST share from a file `emergency-key.part` placed
   alongside their regular `.key` file. The format is delegated to
   the reference implementation; conceptually it carries a single
   FROST share plus the group public key for sanity checking.
2. Runs an additional UI screen (web GUI feature) labeled
   "Emergency coordination" exposing controls to:
   * Load or unload the share file at runtime.
   * View pending recovery session state (Phase 1 commitments seen,
     Phase 2 candidate seen, Phase 3 partial signatures seen).
   * Enter the proposed list of keys (up to 3) this holder wishes to
     contribute, and trigger broadcast of `EmergencyCommitment`
     (Phase 1).
   * If this holder is the deterministic coordinator for the
     session: trigger candidate construction and mining, then
     broadcast `EmergencyCandidate` (Phase 2).
   * Upon observing a valid candidate: trigger generation and
     broadcast of this holder's `EmergencyPartialSignature`
     (Phase 3).
3. Does NOT automatically participate. Every protocol message
   requires explicit operator action via the UI. The share holder
   MUST consciously approve the session, the proposed signer list,
   and the candidate block before any partial signature is produced.

A non-share-holder node has no special UI and no extra files; it
simply gossips emergency messages and validates blocks like any
other node.

## 4. Rationale

### 4.1 Why FROST and not Shamir reconstruction

A naive design would ship Shamir shares of `EMERGENCY_PUBKEY`'s
private key, have `M` holders send their shares to one designated
node, reconstruct the key in memory, sign, and discard. This design
fails in three ways:

1. The reconstructing node briefly holds the full private key. From
   that point onward, it cannot be cryptographically distinguished
   from a node that retained a copy. The emergency power becomes
   single-party at the discretion of whoever was chosen to
   reconstruct.
2. Memory disclosure attacks (RAM dumps, swap, hypervisor
   introspection, malware) on the reconstructing node compromise the
   key permanently.
3. Subsequent emergencies become indistinguishable from unilateral
   action by the prior reconstructor.

FROST avoids all three. The private key never exists as a
recoverable object. Each share holder produces a partial signature
that mathematically commits them to that specific message; partial
signatures cannot be combined into a private key, only into a
signature for the agreed-upon message. The next emergency requires
the same cooperation.

### 4.2 Why one-week timeout

Signing blocks normally arrive within minutes. A delay of hours is
already abnormal but plausible (network split, brief outage). A
delay of one week is implausible in any realistic operational
scenario except quorum failure. Choosing one week balances:

* Domain holders with imminent expiration (within
  `DOMAIN_RENEW_TIME` = 30 days) still have meaningful time to renew
  after recovery.
* Short-term partitions (hours, days) cannot accidentally trigger
  divergent emergency blocks on each side, because no side has been
  stalled long enough.
* Recovery is fast enough to be operationally meaningful, not a
  multi-month process.

### 4.3 Why the auth-key list lives in node configuration, not consensus

If the auth keys were part of consensus, every share holder
turnover would require a hard fork or a special transaction class.
Keeping them in node configuration shifts the responsibility to node
operators: the auth keys are a filter on gossip, not on block
validity. A misconfigured node will simply fail to propagate
contributions but will still validate the resulting emergency block
correctly (since the block's signature is verified directly against
`EMERGENCY_PUBKEY`).

### 4.4 Why max 3 keys per holder

If a single share holder contributes more than 3 keys, they
substantially shape the resulting signer pool, partially defeating
the goal of distribution. Three is a compromise: enough that a
holder can vouch for two community members plus themselves, few
enough that no holder dominates. The cap is enforced socially by
gossip-level validation: each contribution carries the holder's auth
signature over the keys field, so a malicious holder cannot frame
another. A holder exceeding the cap is dropped at the gossip layer
by all honest peers.

### 4.5 Why difficulty 16 (SIGNER_DIFFICULTY)

Higher PoW (24 or 28) was considered but offers no security
benefit: an attacker who has compromised five FROST shares is not
deterred by a few extra seconds of hashing. The threshold signature
itself is the security barrier. Lower PoW would be acceptable but
the existing `SIGNER_DIFFICULTY` constant is already calibrated for
quick block production by ordinary nodes and reuses existing
mining-loop behaviour.

### 4.6 Why `M` is a minimum, not a fixed number of participants

`M = 5` is the FROST threshold: the minimum number of share
holders required to produce any signature at all. It is not the
required size of the participant set in any given session. Any
number `s` with `5 ≤ s ≤ 9` is a valid session size, and FROST
aggregation correctly produces a single Ed25519 signature for any
such `s`.

In practice, share holders should agree on a participant set in
Phase 0 that they collectively trust to follow through, and stick
to that set. The flexibility to choose `s > 5` is offered so that
emergencies can scale to whatever subset of share holders happens
to be reachable, without requiring exactly 5 to be present.

## 5. Security considerations

### 5.1 Compromise of the auth pubkey list

If an attacker can substitute the configured auth pubkey list on a
victim's node, that node will accept malicious contributions and
reject honest ones. However, the resulting emergency block must
still carry a valid FROST aggregate signature, which requires
cooperation of `M` real share holders. The attacker therefore gains
the ability to censor recovery on isolated nodes but cannot forge a
recovery. Operators MUST treat `auth_pubkeys` configuration with
the same care as origin or DNS upstream settings.

### 5.2 Compromise of `M` FROST shares

If an attacker obtains 5 of the 9 FROST shares simultaneously,
they can produce a valid emergency block at any time the timeout
condition is met. They CANNOT use it to seize existing domains
(section 3.5 - all standard identity-availability rules continue to
apply). They CAN replace the eligible signer list with a list under
their control. From that point forward, normal block production
continues under the attacker's signers, who can mine new
(non-conflicting) domains at standard rates and sign each other's
blocks.

Mitigations:
* Geographic, jurisdictional, and social diversity in share holder
  selection.
* Periodic resharing (section 7) to invalidate any quietly leaked
  shares.

### 5.3 Replay across sessions

Contributions are bound to `session_id = last_full.hash`. After
any successful emergency block, the chain advances and the latest
full block hash changes (to the emergency block itself). Old
contributions become inert. There is no risk of an attacker
replaying contributions from a prior session into a new one.

### 5.4 Denial of recovery via flooded gossip

An attacker without legitimate auth keys might attempt to flood the
gossip layer with fake contributions to obscure real ones. The
auth-key filter at section 3.7.2 step 1 drops these immediately at
each node, so the cost is bounded by ordinary gossip rate-limiting
mechanisms. No additional countermeasure is required.

### 5.5 Partition-time accidental recovery

A network partition of less than one week cannot trigger recovery on
either side, because the timeout in section 3.4 is not satisfied. A
partition longer than one week is treated as equivalent to quorum
failure and recovery is permitted. If the partition heals after
recovery, standard chain-selection rules apply: the side that
produced the emergency block has advanced further and wins. The
partition becomes a hard fork in the operational sense; this is the
deliberate cost of choosing availability over consistency in the
extreme tail.

This RFC takes the position that a partition lasting more than one
week is operationally indistinguishable from quorum death and must
be treated the same way.

### 5.6 Loss of more than `N - M` shares

If 5 or more of the 9 share holders permanently lose their shares
without ever participating in a resharing, no emergency block can
ever be produced. This degrades to the pre-RFC failure mode and
requires a hard fork to recover from. Section 7 describes the
operational discipline intended to prevent this.

## 6. Backwards compatibility

This RFC introduces a new transaction class and a new block
validation path. Nodes that have not been upgraded will reject
emergency blocks as malformed and stop accepting subsequent blocks
that build on them. All operators MUST upgrade before
`EMERGENCY_ACTIVATION_HEIGHT`.

The emergency mechanism does not affect any pre-activation block.
Historical chain validation is unchanged.

A node that upgrades but receives no emergency block experiences no
behavioural change. The new code paths are dormant unless an
emergency block is observed.

## 7. Long-term key management

The FROST share set and the auth pubkey list are expected to evolve
over the lifetime of the project. This RFC does not normatively
specify the resharing protocol; that is deferred to a follow-up
RFC. The intended operational pattern is sketched here:

* **Cadence**: at least once per calendar year, ideally more often
  in the first years of deployment.
* **Participants**: at minimum `M = 5` current share holders, plus
  any incoming or outgoing holders.
* **Procedure**: FROST proactive resharing per RFC 9591 section
  6, producing new shares for the same `EMERGENCY_PUBKEY`. After
  the ceremony, all old shares become useless. New auth pubkeys are
  published; node operators update `alfis.toml`.
* **Public signal**: each resharing is announced publicly with the
  identity of new share holders (not the shares themselves).
* **Escalation**: if no resharing has occurred in two years, the
  community is expected to treat this as a soft alarm and
  prioritize organizing one. If five or more shares are believed
  lost or compromised before a resharing can be organized, the
  community SHOULD treat this as a hard fork situation and prepare
  a new RFC.

## 8. Reference implementation

To be provided in a subsequent commit. The implementation is
expected to:

1. Add `frost-ed25519` (RFC 9591 implementation by the Zcash
   Foundation) as a dependency.
2. Introduce `CLASS_SIGNERS_UPDATE` constant in
   `src/commons/constants.rs`.
3. Extend `Transaction` and `Block` validation in
   `src/blockchain/chain.rs` to recognize the new class and the
   activation precondition.
4. Modify `get_block_signers` in `src/blockchain/chain.rs` to
   consult the most recent emergency block before falling back to
   historical author selection.
5. Add three new gossip message types in `src/p2p/message.rs`:
   `EmergencyCommitment` (Phase 1), `EmergencyCandidate` (Phase 2),
   `EmergencyPartialSignature` (Phase 3), with corresponding
   propagation, deduplication, and session-state logic in
   `src/p2p/network.rs`.
6. Add `[emergency]` section to settings parsing in
   `src/settings.rs`.
7. Add an "Emergency coordination" panel to the web UI
   (`src/webview/`) under the existing GUI feature flag.
8. Add `emergency-key.part` loader analogous to keystore loading.

## 9. Open questions

1. Exact value of `EMERGENCY_ACTIVATION_HEIGHT`. To be set at
   release time based on the chain height observed plus an upgrade
   buffer (e.g. height + 2000).
2. Canonical encoding of the signer list within
   `transaction.data`. Length-prefix vs fixed-stride concatenation.
   Trivially decidable in implementation.
3. Whether to surface emergency-session state in the standard UI,
   or only in the share-holder-only UI panel.
   Argument for surfacing: any node operator can monitor recovery
   progress. Argument against: needless surface area.

## Appendix A. Worked numerical example

Suppose:

* Chain height at activation: 21,735.
* `EMERGENCY_ACTIVATION_HEIGHT = 23,735` (height + 2000).
* All 9 initial share holders complete DKG before activation.

After activation, suppose the chain reaches block 25,000 (a full
block, last full at 25,000) and stalls. Two signing blocks arrive
at 25,001 and 25,002, then no further blocks for one week.

At `block 25000.timestamp + 604800`, five share holders -
Alice, Bob, Carol, Dave, and Eve - coordinate via Mimir.
The remaining four share holders are unreachable (one travelling,
one with hardware down, two simply offline). Five is exactly the
threshold; the participating set is `s = 5`. They agree on the
following contributions:

* Alice: 3 keys (her own + 2 community members she vouches for).
* Bob: 3 keys.
* Carol: 2 keys.
* Dave: 2 keys.
* Eve: 1 key.

Total: 11 keys, all distinct.

(In a more comfortable scenario, six or seven share holders would
participate; the protocol works identically with `s ∈ {5..9}`. The
benefit of `s > 5` is purely social - room to over-recruit known
reliable participants - since FROST aggregation requires partial
signatures from **all** `s` participants, not any subset.)

**Phase 1 (commitments).** Each of the five holders broadcasts an
`EmergencyCommitment` carrying their `keys` field and their FROST
round-1 commitment. Each commitment is signed by the holder's auth
key and propagates through gossip. After 30 seconds, all share
holder nodes (and all listening nodes) have observed all five
commitments and can compute the deterministic union of keys
(11 keys, sorted lexicographically).

**Phase 2 (candidate construction and mining).** Suppose Alice's
auth pubkey is lex-smallest among the five. Alice is therefore the
deterministic coordinator. Her node constructs the candidate block
(class `CLASS_SIGNERS_UPDATE`, `pub_key = EMERGENCY_PUBKEY`,
`prev_block_hash = block_25002.hash`, `index = 25003`,
`transaction.data` = canonical encoding of the 11-key list,
`signature` = empty placeholder). Alice mines: at
`SIGNER_DIFFICULTY = 16`, this typically takes well under a minute
on a modern CPU. Alice broadcasts the resulting `EmergencyCandidate`
message. All other share holders' nodes receive and validate the
candidate.

**Phase 3 (partial signatures).** Each of Bob, Carol, Dave, and Eve
(and Alice herself) approves the candidate via the UI and triggers
generation of their FROST round-2 partial signature, computed over
the candidate's canonical bytes (with `signature` field zeroed) and
the aggregate of all five round-1 commitments. Each broadcasts an
`EmergencyPartialSignature`.

**Phase 4 (aggregation).** The first node to observe all five
partial signatures aggregates them into a single Ed25519 signature,
inserts it into the candidate's `signature` field, and broadcasts
the resulting block via the standard block-propagation path. From
this point the block is just a regular signed block; ordinary
validation and propagation apply.

Block 25,003 is accepted by all upgraded nodes. Block 25,004 onward
returns to standard production: the next domain miner produces a
full block at 25,004; signers from the new 11-key list (selected to
7 by the deterministic seed mechanism, with no `min_block_count`
filter) produce signing blocks 25,005-25,008; the chain resumes.

The emergency mechanism remains dormant until and unless another
week-long stall occurs.
