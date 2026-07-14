# RFC-0003: Permanent Exclusion of Dead Signer Keys

| Field      | Value                                            |
|------------|--------------------------------------------------|
| RFC Number | 0003                                             |
| Title      | Permanent Exclusion of Dead Signer Keys          |
| Status     | Draft                                            |
| Type       | Standards Track (consensus change)               |
| Created    | 2026-07-14                                       |
| Authors    | ALFIS Project                                    |
| Relates to | RFC-0002 (Chain Self-Healing), RFC-0001          |

## Abstract

RFC-0002 lets a stalled lock window complete after a timeout using
healing signatures from a standby pool. It deliberately did not change
the drawn-signer selection, and the consequence is now measured on the
live chain: dead keys keep being drawn for every new full block, so
nearly every window stalls and heals, throttling the chain to roughly
one full block per healing timeout — indefinitely.

This RFC adds the missing feedback loop. Every healed lock window
constitutes on-chain **proof of absence**: the drawn signers that
produced nothing during a stall of at least `HEALING_TIMEOUT` days,
while the whole standby pool watched, are considered dead. Such keys
are **permanently banned**: they are skipped by the drawn-signer
selection and by the standby-pool rankings of all subsequent full
blocks. The ban set is a pure function of chain data — no new messages,
no new block fields, no configuration.

Two safety valves bound the mechanism: a **crystallization floor**
(bans are not applied when they would shrink the eligible population
below `BAN_POOL_FLOOR` keys) and a **draw-time minimum** (a draw that
cannot find enough distinct keys deterministically re-admits the most
recently banned ones rather than looping forever — closing a
pre-existing termination hazard in `get_block_signers` that rising
eligibility thresholds could trigger even without bans).

## 1. Motivation

### 1.1 Measured post-healing behaviour

RFC-0002 activated at height 22,521 (the 2026-07-05 stall). Snapshot
at height 22,529 (2026-07-11):

* The stuck window of full block 22,521 was healed on 2026-07-10+ and
  locked on 2026-07-11 — six days for one full block.
* The next window (full block 22,526) accumulated three drawn
  signatures within four minutes and then stopped: the fourth drawn
  signature again belongs to a key that no longer exists as an
  operating node. That window is expected to heal after
  `HEALING_TIMEOUT_FAST` (three days), and the one after it, and so on.
* Of the 16 keys that pass the drawn-signer eligibility threshold
  (`height/100 ≈ 225` authored blocks), the last authored block per
  key dates:

  | Last authored block | Keys |
  |---------------------|------|
  | 2026-07-11 (alive)  | `A980…`, `9B89…`, `BBA0…`, `6E24…` |
  | 2026-07-05 (alive)  | `BE46…` |
  | 2026-07-03/04       | `2A02…`, `BBE5…`, `268E…`, `BC10…` |
  | 2026-06-26          | `4116…`, `9A46…`, `1502…` |
  | 2026-06-16          | `B830…`, `CEE7…` |
  | 2026-05-28          | `22DF…` |
  | 2025-09-14          | `B7FB…` |

The draw for each full block selects 7 of the 15 non-author eligible
keys, weighted by all-time authored-block count. The four proven-dead
keys (`4116…`, `1502…`, `9A46…`, `B7FB…` — the exact no-shows of the
healed window of block 22,521) carry 5,064 of the 18,722 blocks of
total eligible weight (~27%). With that much dead weight in the urn,
the expected number of dead keys per 7-key draw is ~3, and the
4-of-7 lock fails on roughly every other window. The chain is not
recovering between healings because **nothing ever removes a dead key
from the draw**: the all-time ranking is a one-way accumulator, and a
key dead since 2025 will still be drawn at height 200,000.

### 1.2 Healing produces exactly the evidence needed

Detecting death from silence alone is unsound — a key that was simply
never drawn had no duty to sign, and one that was drawn for a window
that locked in four minutes never got a meaningful chance either. But
a *healed* window is different in kind:

* the drawn signers had a duty (they were selected);
* they had time (at least `HEALING_TIMEOUT` — five days — of publicly
  visible stall, or three in the degraded regime);
* they had unambiguous knowledge (their own node computes its signing
  duty automatically; signing requires no human action);
* and the outcome is recorded forever (the healed window's block
  sequence).

A drawn key that authored nothing across such a window is dead for
every practical purpose, and the chain itself is the witness. This RFC
turns that witness into consensus: proof-of-absence, one healed window
at a time.

### 1.3 Why exclusion rather than the designs already rejected

RFC-0002 section 1.3 rejected **moving-window eligibility** (an
attacker grinds cheap blocks, becomes "recently active", enters the
draw, then vanishes or turns hostile). This RFC does not reintroduce
it: eligibility is still *earned* exactly as before (the slow
`height/100` accumulation), and no rule here admits anyone. The ban is
the opposite polarity — **negative evidence only removes**. It even
punishes the grind-and-vanish attack directly: a ground-in key that
goes silent while drawn is excluded after its first healed window,
instead of poisoning draws forever. And it cannot be aimed at others:
the only key an attacker can make silent is their own (see 5.1 for the
eclipse caveat).

Likewise this RFC keeps the RFC-0002 decision that all state is
derived from chain data: the ban set requires no configuration, no
gossip, and no ceremony.

## 2. Terminology

Terms from RFC-0002 (full block, lock window, drawn signers, anchor
pool `A(F)`, recent pool `R(F)`, standby pool `P(F)`, healing
signature, healed window) are used unchanged. New terms:

| Term | Definition |
|------|------------|
| Closing block `F'` | The full block that ends the lock window of full block `F` (the next full block after `F`). |
| No-show set `N(F)` | The drawn signers of a healed window of `F` that authored no block with index in `(F.index, F'.index]`. |
| Eligible set `E(H)` | Keys passing the existing drawn-signer filter at height `H`: authored block count at `H` ≥ `minimum_block_count(H)` (`H/100`). |
| Ban set `B(H)` | All keys banned by crystallizations at full blocks with index ≤ `H` (section 3.3). |
| Crystallization | The deterministic act of adding a window's no-shows to the ban set, evaluated at that window's closing block. |

## 3. Specification

### 3.1 Constants

```
BAN_ACTIVATION_HEIGHT  = 22,529   (the chain tip at release, see 6)
BAN_POOL_FLOOR         = 10       (crystallization stops at this population)
BAN_DRAW_MIN           = 8        (a draw never sees fewer eligible keys than this)
```

Bans affect only the drawn-signer selection and standby-pool
derivation for full blocks with `index > BAN_ACTIVATION_HEIGHT`.
Historical validation is unchanged.

### 3.2 No-show derivation

For every full block `F'` with `F'.index > HEALING_ACTIVATION_HEIGHT`
that closes the lock window of the previous full block `F`:

1. Determine whether the window of `F` is **healed**, by the RFC-0002
   structural test (it contains an empty block whose author is not
   among the drawn signers of `F`).
2. If healed, compute the no-show set:

   ```
   N(F) = drawn(F) \ { authors of all blocks with index in (F.index, F'.index] }
   ```

The author set deliberately includes `F'` itself: a drawn signer that
failed to sign but mined the closing full block has proven it is alive
and is not a no-show. A drawn signer that signed *late* — after
healing signatures already appeared, even after the lock — is likewise
credited: absence is judged over the whole window, not over any
sub-interval. Windows that lock without healing crystallize nothing:
their silent drawn keys were simply not needed and their silence
proves nothing (a healthy window closes within minutes).

Every quantity above is a pure function of blocks with index
`≤ F'.index`, so all nodes — including nodes syncing from genesis —
derive identical no-show sets.

### 3.3 Crystallization and the floor

The ban set is built by processing closing blocks in chain order.
At each closing block `F'` with a non-empty `N(F)`:

1. Order the candidates of `N(F)` by **descending** authored-block
   count as of `F'.index`, ties broken by ascending lexicographic
   order of the public key bytes. (Descending: the heaviest dead key
   poisons the most draws, so when the floor limits how many bans can
   apply, the most damaging keys are removed first.)
2. For each candidate in that order: add it to the ban set **iff**
   afterwards `|E(F'.index) \ B| ≥ BAN_POOL_FLOOR`. A candidate that
   would breach the floor is **skipped, not deferred** — it remains
   eligible and carries no state. If it is genuinely dead it will be
   drawn again, no-show again, and crystallize at a later closing
   block when the floor allows (e.g. after other keys have grown past
   the eligibility threshold).

Bans are **permanent**: no block, timeout, or activity removes a key
from `B`. (Rationale in 4.3; the pressure-release of 3.4 re-admits
keys to individual draws but never un-bans.)

### 3.4 Effect on the drawn-signer selection

For a full block `G` with `G.index > BAN_ACTIVATION_HEIGHT`, the
pseudorandom walk of `get_block_signers(G)` skips authors in `B(G)`
exactly as it skips authors below the `minimum_block_count` threshold.
`B(G)` includes crystallizations at closing blocks with index
`≤ G.index` — including a crystallization at `G` itself, if `G` closes
a healed window; there is no circularity, since the no-shows of that
window are fully determined by blocks preceding `G`.

**Draw-time minimum (termination guarantee).** If
`|E(G.index) \ B(G)| < BAN_DRAW_MIN`, banned keys are re-admitted *for
this draw only*, in reverse crystallization order (most recently
banned first; within one crystallization, reverse of the 3.3 order),
until the count reaches `BAN_DRAW_MIN`. This bounds the walk: with at
least 8 eligible keys, 7 distinct non-author signers always exist.
Note this guard is required even independently of bans — the
`height/100` threshold rises by one every 100 blocks and shrinks
`E(H)` on its own; the current implementation's
`while set.len() < BLOCK_SIGNERS_ALL` loop has no other exit.
Re-admission is a per-draw computation, not an un-ban: the key remains
in `B` and remains excluded from windows where the minimum is met.

### 3.5 Effect on the standby pool

For a full block `F` with `F.index > BAN_ACTIVATION_HEIGHT`, the
RFC-0002 rankings skip banned keys:

* `A(F)` — top `HEALING_POOL_ANCHORS` by all-time count **among keys
  not in `B(F.index)`**;
* `R(F)` — top `HEALING_POOL_RECENT` of the recent window, excluding
  `A(F)` **and `B(F.index)`**.

The next keys in each ranking move up. The anchor pool therefore
tracks the living: proven-dead anchors stop diluting the
`HEALING_ANCHORS_MIN` requirement, and replacement anchors are still
selected by the un-grindable all-time ranking (see 4.5). The
draw-time minimum of 3.4 does not apply here — a small standby pool
is safe (it only reduces healing capacity), whereas a starved draw
walk does not terminate.

### 3.6 What a ban does not do

* **Domain rights are untouched.** A banned key may register, renew,
  and transfer domains exactly as before; its full blocks are valid
  and its authored-block count keeps growing (the count simply no
  longer matters for selection).
* **Open windows keep their composition.** The drawn set and standby
  pool of a full block are fixed when that block is mined; a ban
  crystallizing later does not invalidate a signature in an
  already-open window, and a key drawn before its ban may still sign
  that window.
* **No historical re-judging.** Blocks at or below
  `BAN_ACTIVATION_HEIGHT` validate exactly as before.
* **No wire changes.** The ban set is computed locally by every node;
  no message, field, or transaction class is added.

### 3.7 Operational visibility (non-consensus, required behaviour)

A node MUST log at `warn` level, and surface as a UI event where a UI
exists, every crystallization it performs — listing the banned keys,
the closing block, and the healed window that proved the absence. A
key exclusion is a governance-relevant event; it must never happen
silently.

## 4. Rationale

### 4.1 Why negative evidence only

Any rule that *admits* keys on recent behaviour is grindable
(RFC-0002 section 1.3, item 2). A rule that only *removes* keys on
proven dereliction admits no one and cannot be farmed. The worst an
attacker can do with the ban machinery is get their own keys
excluded. The asymmetry is the point.

### 4.2 Why only drawn signers can be banned

Only the drawn signers of a window have a duty to sign it. Standby
pool members who do not heal prove nothing: healing is voluntary
surplus capacity, several pool keys race for at most a few slots, and
the fastest ones crowd out the rest. Dead *anchors* are still removed
by this RFC, just via their drawn-signer role: the all-time top keys
dominate the draw weight, are drawn constantly, and therefore
no-show quickly once dead — after which 3.5 drops them from the
anchor ranking too.

### 4.3 Why bans are permanent

Alternatives were considered and rejected:

* **Un-ban by mining a full block.** Resurrection through
  proof-of-work sounds fair, but domain renewals are exempt from the
  24-hour cooldown and discounted (the known gap of RFC-0002 section
  5.1), so a hostile key could cycle vanish → banned → one cheap
  renewal → un-banned → drawn → vanish, charging the network a
  multi-day freeze per cycle.
* **Expiry after N blocks.** Deterministic, but every expiry of a
  genuinely dead key re-inserts it into the draw and eventually costs
  one more healed window to re-ban — periodic self-inflicted stalls
  forever.
* **Escalating un-ban cost.** Prevents the cycle but adds offence
  counters to consensus state for a marginal benefit.

Permanence is the simplest rule that never re-admits a corpse. Its
false-positive cost is real but bounded: the trigger requires a
*specific* key to stay silent through a five-day publicly visible
stall of the whole chain (three days only in the already-degraded
regime) — far beyond any benign crash-and-restart — and a wrongly
exiled operator retains all domain rights (3.6). What they lose is
the signing role; what the network loses is one signer it had already
demonstrated it can live without (it healed without them). The keys ≠
people reality cuts here too: the chain can only ever exclude a key,
and a returning operator is a person. Their path back to signing is
the eligibility on-ramp problem, which is out of scope here but
explicitly flagged in section 7.

### 4.4 Why absence is judged over the whole window

Judging "before the first healing signature" would ban a drawn key
that signed on day six — alive, contributing, and punished for
slowness. Judging at the lock would miss the closing block's author.
The window-inclusive rule (`(F.index, F'.index]`) counts every
possible proof of life the chain can record, so a ban means exactly:
*this key produced nothing, of any kind, for the entire stalled
window plus the healing aftermath*.

### 4.5 Why the standby pool is filtered too

Two of the seven current anchors are in the first ban batch. Anchors
exist to gate healing (`HEALING_ANCHORS_MIN`); dead anchors are dead
weight in the exact mechanism that compensates for dead signers.
Filtering is safe against capture: replacements are chosen by the
same all-time ranking, which cannot be entered quickly (RFC-0002
section 4.2), and an attacker cannot get a *live* anchor banned —
that requires the anchor itself to stay silent while drawn through a
multi-day public stall (see 5.1 for the eclipse caveat). The
promotion effect is strictly liveness-positive: measured on the
current chain, filtering promotes two veteran keys into the anchor
pool and admits two genuinely new domain-mining keys into the recent
pool (Appendix A).

### 4.6 Why the floor, and why 10

The eligible population is 16 and shrinks monotonically (deaths and
the rising `height/100` threshold; there is no on-ramp — section 7).
The draw needs 7 distinct non-author keys, so 8 is the hard minimum
for termination; `BAN_POOL_FLOOR = 10` keeps a margin of two above
that so that natural attrition after a crystallization does not
immediately starve the draw, while still allowing the removal of all
seven currently-suspect keys as evidence accumulates (16 − 6 = 10;
the seventh waits until a living key's growth or a dead key's
threshold-dropout makes room). The floor gates only *new* bans; the
draw-time minimum of 3.4 is the backstop that no combination of bans
and attrition can defeat.

### 4.7 Forks, rewinds, and partitions

`B(H)` is a pure function of the chain prefix, so it needs no
protocol: a rewind (`replace_block`) recomputes it (implementations
must invalidate ban caches exactly as `SignersCache` and
`HealingCache` are invalidated today). Across a partition healed on
both sides (the RFC-0002 residual risk), the two branches may
crystallize different ban sets; at reunion the losing branch is
rewound and its bans evaporate with its blocks. Bans therefore add no
new fork-formation mechanism — they only follow whichever branch
wins under the existing rules. One second-order effect is noted
honestly: on each branch, the other side's keys are silent and will
crystallize as no-shows wherever they were drawn, so a long partition
converts into mutual bans on reunion-losing branches. Since only the
winning branch's bans survive, the surviving chain bans at most the
keys that were genuinely absent *from it* — which is the definition
working as intended, but operators of multi-homed fleets should be
aware that straddling a partition (deliberately signing on both
sides) is what prevents their own keys from crystallizing on either.

## 5. Security considerations

### 5.1 Using bans as a weapon

To get a victim key banned, an attacker must cause a healed window in
which the victim was drawn and authored nothing. Silence cannot be
forged — signatures are ordinary gossiped blocks — so the only vector
is denying the victim's connectivity for the entire timeout: a
sustained eclipse or DoS of one specific operator for five-plus days,
during which the rest of the network visibly stalls and heals, the
crystallization is loudly announced (3.7), and at most the keys drawn
for that one window can be affected. The attack is expensive,
slow, visible, and its payoff (removing one key from a draw the
attacker does not control) is small. It is accepted as residual risk;
the mitigation is the same as for RFC-0002's residual risks —
operational visibility and human response.

### 5.2 Self-protection is free

A drawn signer avoids banning by doing exactly what a signer exists
to do: run a node that signs. The grace period is the healing
timeout — a key's node can be down for days within a drawn window
without consequence, as long as it returns before the window closes.
No new operator behaviour is required.

### 5.3 Interaction with grinding

The ban set neither eases nor rewards entry anywhere: eligibility
still requires the `height/100` accumulation, the anchor ranking is
still all-time, and the recent pool is unchanged except for skipping
proven corpses. The renewal-cooldown gap (RFC-0002 section 5.1)
remains worth fixing independently; it is the reason resurrection-by-
full-block was rejected (4.3), so fixing it would allow a future RFC
to revisit permanence.

### 5.4 Spam and DoS

Nothing new travels the wire and no new validation is triggerable by
a peer: crystallization work is bounded by one set computation per
full block, cacheable, and performed identically by all nodes.

## 6. Backwards compatibility

This is a hard fork, and — unlike RFC-0002, which activated on a
chain that could not move under the old rules — this one activates on
a **live** chain. Nodes that do not implement it will compute drawn
sets and standby pools containing banned keys, accept signature
blocks that upgraded nodes reject and reject blocks that upgraded
nodes accept, and fork off at the first post-activation window where
the sets differ. Therefore:

* `BAN_ACTIVATION_HEIGHT` is set to **22,529** — the chain tip at
  release. A zero buffer would normally be reckless, but on this
  chain today it is safe for the same structural reason as RFC-0002
  section 6.1: the degraded regime advances roughly one full block
  per healing timeout, so the first post-activation draw lands days
  after the release, and the raised minimum peer version (below)
  disconnects stale nodes before they can follow a diverging branch.
  The window of full block 22,526 — still open at release — keeps its
  pre-activation draw and pool by construction.
* The release is **0.10.0** and raises the minimum peer version to
  `>= 0.10.0` (`version_compatible` in `src/p2p/network.rs`) so stale
  nodes are disconnected rather than left to fork silently, exactly
  as RFC-0002 section 6 prescribes.

Healed windows between `HEALING_ACTIVATION_HEIGHT` and
`BAN_ACTIVATION_HEIGHT` **do count as evidence**: their no-shows
crystallize retroactively (in chain order, floor applied as of each
closing block), but are *enforced* only in draws and pools above the
activation height. The July 2026 stall evidence is thus not wasted —
the first post-activation draw already excludes the four keys that
caused it. `CHAIN_VERSION` is unchanged; the activation height is the
sole gate.

## 7. Limitations: the pool still only shrinks

This RFC removes dead weight; it does not add living weight. The
eligible population has no on-ramp — a new key needs ~225 authored
blocks to be drawable but cannot sign until it is drawable, and 225
full blocks is not a realistic path. Bans accelerate the pool toward
its floor of 10, of which today at most 9 keys are demonstrably or
plausibly alive, and roughly half of those belong to one operator.
The end state of this RFC alone is a smaller, cleaner, more
centralized draw that mostly locks in minutes instead of days —
runway, not permanence, exactly as RFC-0002 section 7 framed it.

Consequences accepted deliberately:

* Once the floor pins the population at 10, remaining dead keys
  cannot be banned; windows that draw ≥4 of them still heal on the
  RFC-0002 path. The floor trades some residual stalling for draw
  diversity.
* A wrongly banned operator cannot return to signing under any
  current rule, because a fresh key cannot reach eligibility either.
  This is not made worse by this RFC — it is the pre-existing
  on-ramp gap — but permanence makes it bite. A future RFC-0004
  (signer eligibility on-ramp) is the complement this design assumes;
  fixing the renewal-cooldown gap first would also reopen the
  resurrection option rejected in 4.3.
* If attrition someday defeats even the draw-time minimum's
  re-admissions (fewer than 8 keys pass the eligibility threshold at
  all), the draw starves regardless of bans. That is the eligibility
  ratchet's endgame, out of scope here, and the point where RFC-0001
  or a successor fork is the remaining path.

## 8. Reference implementation

Expected shape (all in existing files, no new modules):

1. `src/commons/constants.rs`: the three constants of 3.1.
2. `src/blockchain/chain.rs`:
   * A `BansCache` analogous to `HealingCache`: cumulative ban list
     with per-entry crystallization index, extended incrementally as
     full blocks are added, cleared in `replace_block`.
   * Crystallization at each closing full block: healed-window test
     (already implemented for the adaptive timeout), `N(F)` from the
     window walk, `E(H)` via one SQL count, floor check, ordering.
   * `get_block_signers`: skip keys in `B(G)` inside the walk (same
     shape as the `minimum_block_count` skip); pre-compute the
     re-admission set when `|E \ B| < BAN_DRAW_MIN`. Note the walk
     will iterate more when heavy keys are banned (their historical
     blocks become dead samples); the existing `tail / 13` mitigation
     applies unchanged.
   * `get_healing_pool`: add `NOT IN` filtering (or post-filter) of
     banned keys to both rankings.
   * The crystallization log line and UI event (3.7).
3. Tests: no-show derivation (late signer credited, closing-block
   author credited, non-healed window crystallizes nothing);
   descending-order floor cut; draw determinism with bans; draw-time
   re-admission (exactly `BAN_DRAW_MIN`, reverse order); pool
   filtering and promotion; retroactive crystallization below the
   activation height with enforcement above; rewind invalidation.

## 9. Open questions

1. `BAN_POOL_FLOOR`: 10 proposed (hard minimum 8 plus a margin of
   two). A lower floor bans more corpses sooner; a higher one keeps
   more diversity but leaves dead keys drawable longer.
2. Draw-time re-admission order: most-recently-banned-first
   (proposed: most recently seen alive, hence most likely to still
   exist) vs lightest-first (least draw weight if truly dead).
3. Whether a floor-skipped candidate should instead be deferred and
   crystallize automatically when room appears, sparing one further
   healed window. (Proposed: no — statelessness is worth one window.)
4. Whether to bundle the renewal-cooldown fix (RFC-0002 section 9,
   item 4) into a near-term release. (No longer open:
   `BAN_ACTIVATION_HEIGHT = 22,529` and the release is `0.10.0` with
   `version_compatible >= 0.10.0`, per section 6; the cooldown fix is
   not part of it.)
5. The signer eligibility on-ramp (future RFC-0004): without it, this
   RFC's end state is a floor-sized pool with no succession path.

## Appendix A. Worked example (real chain data, height 22,529)

Full block `F` = 22,521 (author `BD3E…`), mined 2026-07-05 03:58:50
UTC. Drawn signers: `BE46…`, `BBA0…`, `6E24…`, `9A46…`, `4116…`,
`B7FB…`, `1502…`. Drawn signatures 22,522–22,524 (`BE46…`, `BBA0…`,
`6E24…`) arrive within six minutes; then nothing. The healing timeout
elapses 2026-07-10 03:58:50; healing signature 22,525 (`9B89…`, an
anchor) arrives 2026-07-11 18:29:24 and locks the window. Closing
block `F'` = 22,526 (full, author `6E24…`, 2026-07-11 20:21:44).

The window is healed (`9B89…` ∉ drawn(F)). Authors of blocks
22,522–22,526: `{BE46…, BBA0…, 6E24…, 9B89…}`. Therefore:

```
N(F) = { 4116…, 1502…, 9A46…, B7FB… }
```

Crystallization at 22,526, candidates in descending authored-count
order: `4116…` (2,098), `1502…` (1,411), `9A46…` (1,326), `B7FB…`
(229). `|E(22,526)| = 16`; banning all four leaves 12 ≥
`BAN_POOL_FLOOR`, so all four crystallize. (Their last authored
blocks: 2026-06-26, 2026-06-26, 2026-06-26, and 2025-09-14 — the
mechanism's verdict matches the operator-visible reality.)

Effect on the next draw: the banned keys carried ~27% of the eligible
draw weight; the remaining suspect keys (`22DF…`, `CEE7…`, `B830…`)
carry ~5.6%. The expected number of dead keys per 7-key draw falls
from ~3 (coin-flip stalls) to well under 1 (rare stalls, each of
which crystallizes further evidence).

Effect on the standby pool of subsequent full blocks:

```
A = { BE46…, 9B89…, BBA0…, 6E24…, A980…, 2A02…, BBE5… }   (2A02…, BBE5… promoted)
R = { 268E…, BC10…, 22DF…, 9B84…, 70AB… }                 (9B84…, 70AB… enter)
```

Both promoted anchors are veteran keys (1,213 and 683 all-time
blocks); the two recent-pool entrants are active domain-mining keys —
the entry path RFC-0002 section 4.3 describes, now no longer crowded
out by corpses.
