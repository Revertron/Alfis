# RFC-0002: Chain Self-Healing via Standby Signature Pool

| Field      | Value                                            |
|------------|--------------------------------------------------|
| RFC Number | 0002                                             |
| Title      | Chain Self-Healing via Standby Signature Pool    |
| Status     | Draft                                            |
| Type       | Standards Track (consensus change)               |
| Created    | 2026-07-11                                       |
| Authors    | ALFIS Project                                    |
| Relates to | RFC-0001 (Emergency Signer Recovery)             |

## Abstract

Every ALFIS full block must be locked by at least `BLOCK_SIGNERS_MIN = 4`
signing blocks from a set of 7 signer keys drawn pseudorandomly and fixed
forever by the full block's own signature. When fewer than four of the
drawn keys are operational, the chain stalls permanently: there is no
timeout, no re-draw, and no alternative signing path.

This RFC introduces **healing signatures**: after a full block has
remained unlocked for `HEALING_TIMEOUT` (five days), the missing
signatures — up to the same total of four — may be contributed by a
deterministic **standby pool** of at most twelve keys derived from chain
history: the seven most productive keys of all time (the *anchor pool*)
plus the five most active keys of the recent window that are not already
anchors (the *recent pool*). If healing signatures participate in a lock,
at least one of the counted signatures must come from an anchor key.

Healing signatures are ordinary empty signing blocks. The mechanism adds
no new message types, no new transaction classes, no configuration, and
no cryptographic machinery; the consensus change is confined to the
signature-validity and lock-completeness rules. Unlike RFC-0001, it
requires no key ceremony and activates automatically, while remaining
deliberately conservative: it completes the existing 4-signature lock
rather than replacing it with a different quorum.

This RFC additionally makes normative three hardening fixes to the
existing lock machinery that the healing rule depends on (section 3.7).

## 1. Motivation

### 1.1 The stall failure mode

The seven eligible signers for a full block `F` are selected by a
pseudorandom walk seeded with the tail of `F.signature` over the set of
historical block authors that pass the `min_block_count = height / 100`
filter (see `get_block_signers` in `src/blockchain/chain.rs`). Two
properties combine into a permanent-stall risk:

1. The signer set for `F` is fixed the moment `F` is mined. If fewer
   than four of the drawn keys ever produce a signing block, `F` stays
   unlocked forever and no further full block is permitted.
2. The eligibility filter is a ratchet: at the current height a key
   must have authored ~225 blocks to qualify, which excludes newcomers
   in practice and freezes the pool at a small set of veterans.

Measured on the chain snapshot at height 22,524 (2026-07-05):

* 715 distinct keys have ever authored a block; only **16** meet the
  eligibility threshold.
* The top 7 keys by total blocks have authored between 1,411 and 2,329
  blocks each, overwhelmingly signing blocks; all 16 eligible keys are
  still active within the last 5,000 blocks, but roughly **half of the
  most productive keys are controlled by a single operator** (the
  project maintainer, who runs a distributed fleet of nodes; the other
  eligible keys are typically single home machines).
* In the same snapshot, the most recent full block (index 22,521,
  2026-07-05 03:58:50 UTC) is followed by exactly **three** signing
  blocks, one short of the lock, with no further block in the snapshot
  — an illustration of a draw whose fourth signature may simply never
  arrive.

The bus-factor consequence is analyzed at length in RFC-0001 section 1.2
and is not repeated here.

### 1.2 Why not RFC-0001's threshold-signature mechanism

RFC-0001 solves the catastrophic variant of this problem (the whole
signer population lost) with a FROST 5-of-9 emergency key held by
configured share holders. Its costs are significant: a distributed key
generation ceremony, share-holder tooling and UI, three new gossip
message types with session state, periodic resharing discipline, and a
configured list of humans that must be maintained out-of-band.

For the *common* variant — some drawn signers gone, most of the
productive keys still alive — a far smaller mechanism suffices, one that
reuses the existing signing-block machinery end to end. RFC-0001 remains
the backstop for the case this RFC cannot cover (loss of substantially
the entire standby pool at once, see section 7).

### 1.3 Design constraints adopted from prior analysis

The design space was narrowed by the following deliberate decisions:

1. **No time-based relaxation of the quorum itself** (e.g. widening the
   drawn set or lowering the threshold over time). Such decay activates
   symmetrically on both sides of a network partition and lets both
   sides advance, producing long irreconcilable forks. Fork *formation*
   must remain the thing the protocol prevents.
2. **No moving-window eligibility for the drawn signers.** A
   recency-based signer pool can be entered by an attacker who grinds
   blocks for a period and then disappears or turns hostile
   (aggravated by the fact that domain *renewals* are exempt from the
   24-hour cooldown and receive a difficulty discount, making activity
   cheaper to fake than it appears).
3. **The healing set must be derived from chain data, not
   configuration.** A configured list guarantees one-key-per-person but
   requires the ceremony and maintenance burden of RFC-0001; a
   chain-derived set is person-blind but self-maintaining and free.
   This RFC accepts person-blindness and mitigates its risks with the
   anchor rule (section 3.5) and the timeout, and documents the
   residual concentration honestly (section 7).
4. **Healing completes the existing 4-signature lock** rather than
   forming a separate majority quorum. The healing pool is capacity of
   last resort, not a parallel government.

## 2. Terminology

| Term | Definition |
|------|------------|
| Full block | Block with a non-empty transaction (a domain registration or renewal). |
| Lock window | The span of empty blocks between a full block `F` and the next full block. |
| Drawn signers | The 7 keys selected for `F` by `get_block_signers(F)`. |
| Anchor pool `A(F)` | The 7 keys with the most authored blocks in `(1, F.index]`. |
| Recent pool `R(F)` | The 5 most active keys of the last `HEALING_WINDOW` blocks before `F`, excluding members of `A(F)`. |
| Standby pool `P(F)` | `A(F) ∪ R(F)`, at most 12 keys. |
| Healing signature | An empty block in `F`'s lock window authored by a member of `P(F)` under the timeout condition of section 3.4. |
| Anchor signature | Any counted signature block (drawn or healing) whose author is in `A(F)`. |
| Healed window | A lock window containing at least one healing signature. Detected structurally: an empty block whose author is not among the drawn signers of its window's full block. |

## 3. Specification

### 3.1 Constants

```
HEALING_ACTIVATION_HEIGHT  = <set at release; for a stalled chain: the stuck full block itself, see 6.1>
HEALING_TIMEOUT            = 5 * 86400 seconds   (432,000)
HEALING_TIMEOUT_FAST       = 3 * 86400 seconds   (259,200)
HEALING_LOOKBACK           = 10 blocks
HEALING_POOL_ANCHORS       = 7
HEALING_POOL_RECENT        = 5
HEALING_WINDOW             = 5,000 blocks
HEALING_ANCHORS_MIN        = 1
```

All rules in this RFC apply only to blocks with
`index > HEALING_ACTIVATION_HEIGHT`. Historical validation is unchanged.

### 3.2 Standby pool derivation

For a full block `F`, every node computes deterministically:

* **`A(F)`** — rank all keys by the number of blocks they authored with
  `1 < index ≤ F.index`; take the top `HEALING_POOL_ANCHORS`. Ties are
  broken by ascending lexicographic order of the public key bytes.
* **`R(F)`** — rank all keys **not in `A(F)`** by the number of blocks
  they authored with `max(1, F.index − HEALING_WINDOW) < index ≤
  F.index`; take the top `HEALING_POOL_RECENT`, same tie-break. If
  fewer distinct non-anchor keys were active in the window, `R(F)` is
  simply smaller.
* **`P(F) = A(F) ∪ R(F)`**.

The ranking counts blocks of **all** classes (full and signing). Both
rankings are functions of the chain up to and including `F.index`, so
every node computes the same pool regardless of its own tip, and the
pool for a given lock window is immutable once `F` exists. The result
SHOULD be cached per `F.index` analogously to the existing
`SignersCache`.

### 3.3 Healing signature validity

An empty block `E` in the lock window of full block `F` is a valid
signature block if **either**:

* `E.pub_key` is among the drawn signers of `F` (existing rule,
  unchanged), **or**
* `E.pub_key ∈ P(F)` **and** the timeout condition of section 3.4
  holds for `E`.

All other empty-block rules apply unchanged in both cases: proof-of-work
of at least `SIGNER_DIFFICULTY`; correct hash and Ed25519 signature;
timestamp not earlier than the predecessor block and not more than 60
seconds in the future at the time of receipt; **one block per key per
lock window** (the existing walk in `is_good_signer_for_block`); the
author of `F` itself may not sign. Additionally, from
`HEALING_ACTIVATION_HEIGHT` the author key of an empty block must meet
`KEYSTORE_DIFFICULTY`, closing a gap where key strength was checked for
full blocks only.

A key that is both a drawn signer and a pool member is simply a drawn
signer; the healing path is relevant to it only in that it changes
nothing (one signature either way).

### 3.4 Timeout condition

The timeout applicable to full block `F` is adaptive:

```
T(F) = HEALING_TIMEOUT_FAST   if any of the HEALING_LOOKBACK blocks
                              preceding F (indices F.index-10 .. F.index-1)
                              is a healing signature
       HEALING_TIMEOUT        otherwise
```

Whether a past block is a healing signature is decided by a purely
structural test — an empty block whose author is not among the drawn
signers of its window's full block (no other block can validly have
that shape, so no marker field is needed). The per-window result
SHOULD be cached.

A healing signature `E` for full block `F` is then valid only if:

```
E.timestamp - F.timestamp >= T(F)
```

The reference point is the **full block's own timestamp**, not the tip's,
so that (a) the condition is a pure function of block data and can be
re-validated offline byte-for-byte, and (b) each accepted healing block
does not restart the clock for the next one — once the window is stale
by `T(F)`, all pool members qualify concurrently.

The condition cannot be satisfied early by forging: block timestamps are
rejected when more than 60 seconds ahead of the receiving node's clock,
and must be monotonically non-decreasing along the chain. The only way
to obtain a valid healing timestamp is for five days genuinely to pass
on a publicly observable, stalled chain.

### 3.5 Lock completeness (the anchor rule)

Let `S` be the set of valid signature blocks in `F`'s lock window
(each block individually valid per section 3.3, all authors distinct).
`F` is **locked** if and only if:

```
|S| >= BLOCK_SIGNERS_MIN (4)
AND ( S contains at least BLOCK_SIGNERS_MIN drawn signatures
      OR at least HEALING_ANCHORS_MIN block(s) in S is authored
         by a member of A(F) )
```

In words: four drawn signatures always lock, exactly as today — a
stray healing signature in the window cannot raise the bar for a
drawn lock (otherwise a single standby key could *poison* a slow but
recoverable window by dropping one healing signature into it and
demanding an anchor that a drawn lock never needs). A lock that
relies on healing signatures to reach four must include at least one
signature — drawn *or* healing — from an all-time top-7 key. Note
that this may require a fifth signature block in rare compositions
(e.g. three drawn non-anchor signatures plus one recent-pool healing
signature do not lock; the window remains open until an anchor signs
or a fourth drawn signature arrives).

The lock predicate replaces the current height-difference arithmetic
(`sign_count = height - full.index`) in `is_waiting_signers`,
`next_allowed_full_block`, `get_sign_block` and full-block validation.
The walk is over at most `BLOCK_SIGNERS_ALL` blocks and is cheap.

### 3.6 Mining behaviour

A node holding a key in `P(F)` treats a healing opportunity exactly like
a signing opportunity: `get_sign_block` additionally offers a healing
job when the local wall clock indicates the timeout has passed, the
chain is not syncing, the lock is incomplete, and the key has not yet
signed this window. The existing randomized start delay
(`BLOCK_SIGNERS_START_RANDOM`, up to 90 s) applies, and SHOULD be
enlarged for healing jobs (suggested: up to 15 minutes) since healing is
never latency-critical and larger jitter reduces wasted concurrent
mining across up to twelve participants.

A node only offers signatures that can advance the lock: when four
signatures already exist but the window is still unlocked
(section 3.5), healing jobs are taken by anchor keys only — one more
non-anchor healing signature cannot advance anything, whereas drawn
signatures always can (they count toward a purely drawn lock).

Participation is automatic. No operator action, UI, or configuration is
required. Nodes without pool keys behave exactly as today.

### 3.7 Hardening fixes (normative)

The healing rule is meaningful only if the lock is actually enforced.
Three defects in the current implementation are corrected from
`HEALING_ACTIVATION_HEIGHT`:

1. **Enforce the lock on received full blocks.** `is_good_sign_block`
   currently returns `true` for any full block before reaching the
   check that rejects a full block over an unlocked predecessor (dead
   code since 2021, commit `f8d47df`). From activation, a full block
   whose preceding full block is not locked (per section 3.5) is
   invalid.
2. **Close the post-7 lapse.** An empty block over a full block that is
   already **locked** and has `BLOCK_SIGNERS_ALL` (7) signature blocks
   is invalid. (Currently, once seven signing blocks exist, arbitrarily
   many further empty blocks from any key are accepted.) Empty blocks
   numbers 5–7 over a locked window remain valid, as today, to tolerate
   signing races. An *unlocked* window, however, accepts every valid
   signature block regardless of count. This qualification is essential:
   an unconditional cap at seven could deadlock the chain permanently —
   three drawn non-anchor signatures plus four recent-pool healing
   signatures fill seven slots without satisfying the anchor rule, and
   the anchor signature that would complete the lock must remain
   admissible. The window stays bounded anyway, at one block per drawn
   or standby key.
3. **Key strength for empty blocks** as stated in section 3.3.

Additionally (non-consensus but required behaviour): a node that
detects a same-origin peer serving a chain irreconcilable with its own
(a fork beyond `LIMITED_CONFIDENCE_DEPTH`) MUST surface this loudly — a
dedicated log line at `error` level and a UI event — instead of the
current silent ban. Partition reunification failures must be visible to
humans.

## 4. Rationale

### 4.1 Why completion-of-4 rather than a majority of the pool

A majority threshold over the standby pool (e.g. 7-of-12) would be
partition-exclusive by pigeonhole — at most one side of a split could
assemble it — but only if pool keys corresponded to distinct people.
They do not: the chain sees keys, not people, and today roughly half of
the anchor pool is one operator. A key-majority rule would therefore
buy the *appearance* of decentralized exclusivity without the
substance, while making recovery harder in every honest scenario. This
RFC instead keeps the familiar 4-signature lock and derives its
partition story from topology and the anchor rule (section 4.4).

### 4.2 Why anchors are ranked all-time

An all-time ranking cannot be entered quickly: overtaking keys with
1,400–2,300 authored blocks requires out-producing five years of
continuous operation. This is the grind-resistance the recent pool
lacks. The anchor set drifts — slowly, over years — as living keys
accumulate blocks, so it is not permanently frozen the way the
`height/100` eligibility ratchet is, but it cannot be captured within
any single window of attack effort.

### 4.3 Why the recent pool exists at all

Anchors alone reproduce the mortality problem one level up: the day the
anchor holders are gone, healing dies with them. The recent slots are
the entry path: any key that becomes genuinely active — including pure
domain-mining keys that can never pass the signer-eligibility ratchet —
enters `R(F)` within one window and adds healing capacity. Measured at
the current tip, `R(F)` would consist of two veteran signer keys just
below the anchor cut (1,326 and 1,213 total blocks) and three
moderately active keys (229–436 total blocks), one of which is almost
exclusively a domain-mining key — evidence that the entry path admits
participants the drawn-signer system structurally cannot.

### 4.4 Why the anchor rule

The recent pool is grindable (section 1.3, item 2), and a key — unlike
an honest human — can sign on *both* sides of a partition if its owner
deliberately straddles it. Without the anchor rule, an attacker who
buys four recent slots during a genuine stall could heal both sides of
a split they themselves engineer at the network layer, manufacturing
the exact durable fork this design exists to prevent. With
`HEALING_ANCHORS_MIN = 1`, no combination of recent-pool signatures
can lock a block anywhere without at least one of seven slow-moving,
un-grindable keys co-signing on that side. Healing on both sides of a
partition therefore requires anchor participation on both sides —
either two honest anchor holders genuinely split apart, or a
compromised anchor key.

Raising the parameter to 2 would harden this further at the cost of
recovery fragility: with today's concentration, requiring two anchors
after the majority operator's departure could mean requiring *both*
remaining independent anchor keys. One anchor is the deliberate
balance; the parameter exists so a future release can adjust it as the
anchor set decentralizes.

### 4.5 Why five days — and three in a degraded regime

The baseline timeout serves three purposes: it keeps the healing path
strictly subordinate to normal signing (a healthy quorum locks in
minutes); it gives humans time to notice a stall through ordinary
channels before the protocol acts; and it is the principal defence
against the residual double-heal geometry (section 5.2) — a partition
must persist longer than `HEALING_TIMEOUT` *and* have healing capacity
on both sides before divergence becomes possible. Five days is far
above any plausible benign outage, yet short enough that domain
holders in their 30-day renewal grace window lose little of it.

If signer loss is real and persistent, however, *every* window heals,
and a fixed five-day wait per window throttles the chain to ~6 domains
per month while buying nothing: the safety work the long timeout does
— proving the stall is genuine, to humans and to the protocol — has
already been paid by the first heal. Hence the adaptive rule of
section 3.4: once the chain demonstrably operates in the healed regime
(a healing signature within the last `HEALING_LOOKBACK` blocks, i.e.
roughly the last two lock windows), subsequent windows wait only three
days.

The fast path cannot be entered synthetically: establishing "healing
in the lookback" requires an honestly healed window, which requires a
real five-day stall plus an anchor signature. On any branch that was
healthy at the moment of a split, the first heal therefore always pays
the full five days, so the double-heal gate of section 5.2 is
unchanged for partitions of healthy chains; only a chain *already* in
the degraded regime at the moment of a split starts both sides at
three days. De-escalation is automatic: two consecutive normally
locked windows push all healing signatures out of the lookback and the
timeout reverts to five days. An escalating schedule (shortening
further after many consecutive healed windows) was considered and left
out for simplicity.

### 4.6 Partition analysis

Consider the realistic split geometries, using the present topology
(one operator with a distributed multi-site fleet holding roughly half
of the standby pool; other holders on single home machines):

* **The fleet goes dark entirely.** This is an outage, not a
  partition: the dark nodes build nothing. The surviving side heals
  after five days using the independent anchors plus recent keys; when
  the fleet returns, it is merely behind and resyncs cleanly. This is
  the primary bus-factor scenario, and the mechanism handles it with
  zero coordination.
* **A partition isolates the fleet from everyone else.** The fleet
  side heals unilaterally. The other side heals only if it contains an
  anchor key *and* four pool signatures in total; otherwise it stalls,
  its divergent suffix stays within `LIMITED_CONFIDENCE_DEPTH` (an
  unlocked full block plus at most three signatures, since honest
  nodes never build over an unlocked block), and the existing
  Fork/lagged machinery reabsorbs it automatically at reunion.
* **Both sides hold anchors and pool capacity, and the partition
  outlasts the timeout.** Both sides heal and a durable fork forms.
  This is the residual risk, bounded by the anchor rule, the timeout,
  and the improbability of a clean long-lived split that separates a
  deliberately multi-homed fleet from four cooperating independent
  holders. It is made *visible* by the mandatory fork alarm of
  section 3.7.

### 4.7 What healing deliberately does not do

Healing adds empty blocks. It cannot register, transfer, or seize a
domain (all identity rules are untouched); it cannot rewrite history
(the `LIMITED_CONFIDENCE_DEPTH` rule is untouched); it cannot mint full
blocks under the standby keys with any special rights; and it does not
alter the drawn-signer selection for subsequent blocks. Its entire
power is to complete a lock that the drawn signers failed to complete,
five days late.

## 5. Security considerations

### 5.1 Grinding into the recent pool

Entry into `R(F)` requires out-producing the currently active non-anchor
keys within a 5,000-block window. Because domain renewals are exempt
from the 24-hour cooldown and receive a difficulty discount, block
production for activity's sake is cheaper than the cooldown suggests
(this cooldown gap exists independently of this RFC and is worth fixing
separately). The anchor rule caps the payoff: grinded keys can
contribute healing signatures but can never complete a lock without an
anchor, so the attack cannot unstick anything — let alone fork anything
— on its own. The residual effect of a grind is displacement: pushing
honest keys out of `R(F)` reduces honest healing capacity by up to five
signatures. The anchors plus one honest recent key still suffice.

### 5.2 Double-heal across a partition

Covered in section 4.6. Requirements for a durable fork: a partition
longer than `HEALING_TIMEOUT` (or `HEALING_TIMEOUT_FAST`, if the chain
was already in the healed regime when the split occurred — see
section 4.5), four pool signatures available on each
side, an anchor on each side, and a genuine stall (the timeout cannot be
induced; it requires the drawn signers to actually fail). Each factor is
individually plausible; their conjunction is the accepted residual risk,
and it degrades gracefully — the fork alarm makes it a loud operational
incident rather than a silent permanent split.

### 5.3 Compromise of pool keys

A single compromised pool key (anchor or recent) contributes at most one
signature per lock window and only after a five-day public stall. Four
compromised pool keys including an anchor can heal unilaterally — the
same capability the honest pool has — but gain none of the powers listed
in section 4.7. The value of stealing standby keys is therefore low; the
main defence is that anchors are, by construction, keys whose operators
have run infrastructure for years.

### 5.4 Spam and DoS

Healing blocks cost `SIGNER_DIFFICULTY` proof-of-work, are limited to
one per key per lock window, are only valid five days into a stall, and
a lock window admits at most one block per drawn or standby key — and
at most seven in total once locked (section 3.7, item 2). There is no
gossip-level session state to flood; the messages are ordinary blocks.

### 5.5 Interaction with RFC-0001

If both RFCs are eventually deployed, healing is the first line
(automatic, covers partial signer loss) and the RFC-0001 emergency block
is the second (human-gated, covers loss of substantially the whole pool).
Their preconditions are naturally ordered: healing at five days,
emergency at seven. A chain healed by this RFC never reaches the
RFC-0001 precondition.

## 6. Backwards compatibility

Nodes that do not implement this RFC will reject healing blocks as
having a wrong signer, and will reject every subsequent block built on
them. All node operators MUST upgrade to keep following the chain once
healing begins. The release shipping this RFC SHOULD raise
the minimum peer version (`version_compatible` in `src/p2p/network.rs`)
so that stale nodes are excluded from the swarm rather than left to
fork off silently.

No historical block is re-judged: all rules, including the hardening
fixes of section 3.7, apply only above the activation height.
`CHAIN_VERSION` is unchanged; the activation height is the sole gate.

### 6.1 Activation on an already-stalled chain

Normally an activation height is chosen above the current tip with a
generous buffer so that operators can upgrade before the rules can
fire. A stalled chain breaks that scheme: the height never moves, so a
height above the tip is never reached and provides no buffer at all.

The resolution is to set `HEALING_ACTIVATION_HEIGHT` to the index of
the currently unsigned full block itself (22,521 for the present
stall), so that the new rules govern exactly the lock window that is
stuck. No buffer is needed, because a stall is the one moment when a
consensus change is safe by construction:

* Under the pre-RFC rules the chain cannot be extended — that is what
  a stall is. Un-upgraded nodes therefore cannot build a competing
  branch. They reject the healing blocks, freeze at the stall tip,
  and keep serving their frozen state until their operator upgrades —
  at which point they fast-forward onto the healed chain, of which
  their own chain is a strict prefix. There is nothing to fork.
* If a missing drawn signature unexpectedly arrives *before* healing
  does, the chain unsticks by itself and the new rules remain dormant.
  If it arrives *after*, it competes with a healing block at a single
  index and the existing `is_better_than` fork rule resolves it.

The upgrade window is therefore an operational question, not a
consensus-safety one — but it should still be short, because a stall
actively destroys value: domains whose 30-day renewal grace elapses
during the stall pass irrevocably out of their owners' reach. Measured
on the current chain (1,391 domains ever registered, 594 still
resolving at the stall date): ~22 domains fall out of their grace
window by 2026-09-01, ~57 by 2026-10-01, ~213 by 2027-01-01. Raising
the minimum peer version (above) also serves as the wake-up call:
frozen nodes are actively disconnected from the swarm instead of
idling forever on a chain that will never move again.

## 7. Limitations: runway, not permanence

The standby pool is drawn from the same mortal key population as the
drawn signers. This RFC extends the chain's survivable key-loss budget
substantially — any four pool keys with an anchor among them keep the
chain alive — but does not make it immortal:

* If the drawn-signer population decays wholesale while the pool
  survives, every lock window waits out the timeout and chain
  throughput degrades to roughly one full block per
  `HEALING_TIMEOUT_FAST` (three days, once the degraded regime is
  established — section 3.4). This is survival, not health. (Each healed window adds blocks to the
  healers' totals, slowly shifting `A(F)` toward living keys, but the
  drawn-signer eligibility ratchet is out of scope of this RFC and
  will keep drawing from the same historical pool.)
* If the anchor pool itself decays to the point where no anchor is
  operational, healing stops working entirely and the chain is back to
  the pre-RFC failure mode. At current concentration, the departure of
  the majority operator leaves two independent anchor keys; the loss
  of those two as well exhausts the mechanism. That is the point where
  RFC-0001 (or a successor hard fork) is the remaining path.

These limits are accepted deliberately: the alternative designs that
remove them (moving-window signer eligibility, configured human lists,
threshold cryptography) were each rejected for the reasons in
section 1.3 and RFC-0001's own cost profile.

## 8. Reference implementation

Expected shape (all in existing files, no new modules):

1. `src/commons/constants.rs`: the eight constants of section 3.1.
2. `src/blockchain/chain.rs`:
   * `get_healing_pool(&self, full_block: &Block) -> HealingPool`
     (anchor and recent keys plus the per-window timeout) with a cache
     analogous to `SignersCache`; two SQL rankings with the
     lexicographic tie-break.
   * `is_locked(&self, full_block: &Block) -> bool` implementing the
     predicate of section 3.5; used by `is_waiting_signers`,
     `next_allowed_full_block`, and full-block validation (fix 3.7.1).
   * `is_good_signer_for_block`: accept pool members under the
     timeout condition (section 3.3/3.4); enforce key strength for
     empty blocks; reject extra empty blocks over a locked window
     (fix 3.7.2).
   * Healed-window detection for the adaptive timeout (empty block
     with author outside the drawn signer set), cached per window.
   * `get_sign_block`: offer healing jobs (section 3.6).
3. `src/p2p/network.rs` / UI event: the fork alarm of section 3.7.
4. Tests: pool derivation determinism (including ties), timeout
   boundary, anchor-rule compositions (3 drawn + 1 recent must not
   lock; 3 drawn + 1 anchor must; 4 recent must not; 3 recent +
   1 anchor must), race tolerance for blocks 5–7, activation-height
   gating against the historical DB in `tests/blockchain.db`.

## 9. Open questions

1. Timeout parameters: baseline `HEALING_TIMEOUT` (five days proposed;
   3–7 defensible — seven would align with RFC-0001's precondition),
   degraded-regime `HEALING_TIMEOUT_FAST` (three days proposed), and
   `HEALING_LOOKBACK` (10 blocks ≈ the last two lock windows; a larger
   value keeps the fast path open across occasional normal locks in a
   mostly-degraded chain).
2. `HEALING_ANCHORS_MIN`: 1 (proposed) vs 2 (stronger anti-grind and
   anti-straddle, more fragile succession).
3. Whether `R(F)` should rank by signing blocks only. This would make
   the recent pool un-grindable (signing requires being drawn, which
   requires eligibility), at the cost of closing the entry path for
   domain-mining keys — reintroducing the closed-shop property the
   recent pool exists to break. Proposed: rank by all blocks, rely on
   the anchor rule.
4. Whether to fix the renewal cooldown gap (renewals exempt from
   `NEW_DOMAINS_INTERVAL`) in the same release. Recommended, as it
   cheapens grinding generally, but it is an independent change.
5. The release timeline. (Two parts of this are no longer open: for
   the present stall, `HEALING_ACTIVATION_HEIGHT = 22,521` — the stuck
   full block — per section 6.1; and the release shipping this RFC is
   `0.9.0`, with `version_compatible` requiring peers `>= 0.9.0`.)

## Appendix A. Measured pool composition (height 22,524, 2026-07-05)

Chain: 22,524 blocks, 715 distinct author keys, 242 keys active in the
last 5,000 blocks, 16 keys eligible as drawn signers (threshold 225).

Anchor pool `A` (top 7 all-time; key = first 8 bytes, hex):

| Rank | Key              | Total blocks | Signing | Full | Last 1,000 blocks |
|------|------------------|--------------|---------|------|-------------------|
| 1    | `BE467BA69F6072DD` | 2,329 | 2,312 | 17  | 115 |
| 2    | `9B890FBB8B862CCC` | 2,252 | 2,230 | 22  | 97  |
| 3    | `BBA064CF02A50E85` | 2,172 | 2,156 | 16  | 108 |
| 4    | `41163A38B9E760A3` | 2,098 | 2,069 | 29  | 72  |
| 5    | `6E2482A41083C1F4` | 1,970 | 1,907 | 63  | 107 |
| 6    | `A980EF2374545790` | 1,492 | 1,450 | 42  | 88  |
| 7    | `15020121FC10BD93` | 1,411 | 1,383 | 28  | 60  |

Recent pool `R` (top 5 of window 17,525–22,524, excluding `A`):

| Rank | Key              | Window blocks | of which full | Total blocks |
|------|------------------|---------------|---------------|--------------|
| 1    | `9A460084CDE9ACC8` | 275 | 5  | 1,326 |
| 2    | `2A02D5EED12C03D0` | 270 | 0  | 1,213 |
| 3    | `B7FB7A49828AF3EB` | 88  | 86 | 229   |
| 4    | `268E47DD5268A2EA` | 87  | 1  | 341   |
| 5    | `BC1034328DDA03AF` | 84  | 0  | 436   |

Note `B7FB…`: almost purely a domain-mining key — the kind of
participant that can never enter the drawn-signer pool under the
eligibility ratchet, but enters the standby pool through genuine
activity.

## Appendix B. Worked example

The snapshot itself supplies the scenario. Full block 22,521 (author
`BD3E…`) is mined 2026-07-05 03:58:50 UTC; drawn signing blocks
22,522–22,524 — authored by anchor keys `BE46…`, `BBA0…` and `6E24…` —
arrive within six minutes; the fourth drawn signature never comes.

Under this RFC (with `HEALING_ACTIVATION_HEIGHT = 22,521`): from
2026-07-10 03:58:50 UTC, every empty block whose author is one of the
twelve keys above (minus the three that already signed and the full
block's author) and whose timestamp is at or past that moment is a
valid signature for block 22,521. Nodes holding those keys queue
healing jobs automatically with randomized delays. Suppose `9A46…`
(recent pool) mines block 22,525 at 04:11. The window now holds four
signatures, three of them by anchors, so the predicate of section 3.5
is satisfied and block 22,521 is locked. The next domain block 22,526
is permitted immediately; normal operation resumes.

(Had the three drawn signatures come from non-anchor eligible keys, the
single `9A46…` healing signature would *not* have locked the window —
a fifth block by any anchor would have been required. In practice the
most active drawn signers and the anchors overlap heavily, as here.)

The five-day gap remains visible in the chain forever as an honest
record that healing occurred; no other trace distinguishes healing
blocks from ordinary signing blocks.
