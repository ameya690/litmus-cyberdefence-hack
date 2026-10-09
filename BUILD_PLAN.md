# Litmus — Build Plan

The scoped, decision-complete build plan for the one-day cyberdefense hackathon.
Derived from `prd.txt` and the Antiproof paper, hardened through a full design review.
Where this document and `prd.txt` disagree, **this document wins** — it reflects decisions
made after the PRD was written.

---

## 0. The one idea being protected

**PROVEN means a random secret — generated live on screen, never shown to the attacker —
was extracted from the target *through the vulnerability under test*, and the oracle
confirmed it by reading the target's actual HTTP response bytes off the wire.**

Everything in this plan exists to make that one moment real, unfakeable, and visible.
Any scanner can list "maybes." Litmus extracts a secret that didn't exist ten seconds ago.

---

## 1. Scope (v1)

- **One capability class: arbitrary file read via path traversal.** This is the entire v1.
- RCE, SSRF, and other capability classes are **stretch** (§8), not v1.
- The paper uses a *separate oracle per capability*. We do the same. We never claim
  cross-capability generality we haven't built — the honest claim is "proven across
  multiple candidate *sites* of the file-read class."

---

## 2. Integrity model — the heart

The whole premise collapses if the attacker can obtain the flag any way *other* than
through the vulnerability under test. These controls are non-negotiable.

1. **Network-only isolation.** The attacker agent talks to the target **only over HTTP,
   from a separate container.** No shell into the target, no shared filesystem, no exec.
   The agent has a shell only in *its own* sandbox container (with curl/python), reachable
   to the target over a Docker network and nothing else.

2. **The flag is unreachable except through the bug.** `FLAG-<random>` lives in
   `/challenge/secret` (a mounted volume), outside every legitimate route's reach. It
   **never** appears in source, env vars, logs, stack traces, or error output.

3. **The secret is never disclosed to the agent.** The agent is not told the flag in its
   prompt, env, or any tool output — the *only* way to produce it is to read the file
   through the traversal. (This is the paper's real echo-proofing: the file-read oracle
   accepts iff the prover returns `s`, and `s` is never given to the prover.)

4. **The oracle reads the wire, not the agent's claim.** A thin proxy (or the harness)
   captures the **target's actual HTTP response bytes** and greps them for the planted
   flag. The oracle never trusts the agent's self-report. This also makes the agent and
   the scripted fallback automatically indistinguishable — both merely cause the target to
   emit the flag on the wire.

5. **Negative control runs first.** Before crediting any exploit, a plain **benign,
   non-traversing request** to the same endpoint must come back **without** the flag. If
   the baseline yields the flag, the candidate is **rejected, not proven** — the bug
   wasn't what produced it. This automated control replaces the paper's manual
   human review of every environment, which we have no time for.

6. **Fresh secret per attempt.** Rotate `FLAG-<random>` for every candidate/attempt
   (overwrite `/challenge/secret`). Kills replay and leakage from a prior run.

---

## 3. Architecture

### Topology
- **Two long-lived containers**, brought up once with `docker compose up`:
  - `target` — the vulnerable Flask app.
  - `attacker` — the agent's sandbox (shell + network tools), network-only to `target`.
- **"Per-candidate" is cheap:** rotate the secret + point the exploit at the specific
  endpoint/param the Semgrep hit names. **Never respawn a container per candidate.**
  Reset = overwrite a file. (`docker compose restart target` is a stretch nicety, not the
  baseline.)

### Four stages

1. **Detect.** `semgrep --config=auto` against the target app → candidate list (file,
   line, CWE). The planted traversal is chosen to match a **known default rule**
   (`python.flask.security.injection.path-traversal-open` on an `open(user_controlled)`
   sink). **Verify Semgrep actually fires on the plant in the first 30 minutes** — don't
   plant and hope.

2. **Prove.** For each candidate: rotate secret → run negative control → Claude attacker
   agent attempts the exploit live → scripted exploit is the silent fallback → oracle reads
   the target's response bytes and stamps PROVEN / UNPROVEN.

3. **Report.** Dashboard (the demo surface) on a **local SQLite/JSON event log**. Emits
   every pipeline event (candidate found, negative control, proof attempted, accepted/
   rejected, per-stage latency). ClickHouse swaps in **behind the same read interface**.

4. *(Triage — cut from the critical path.* The **oracle is the false-positive reducer**:
   PROVEN/UNPROVEN is ground truth, more convincing than an LLM label. Add the Triage LLM
   stage back only as stretch garnish.)

### Attacker runtime
- **Model:** Claude, Sonnet-class for agentic speed (Opus only if a candidate is stubborn,
  which file-read won't be). Tight prompt, few turns, hard token cap.
- **Fallback trigger:** hard wall-clock timeout **60–90s** per candidate, plus
  fire-on-exception and fire-after-*k*-failed-attempts.
- **Handoff is invisible in the UI** ("attempting…" → "PROVEN", never which driver). The
  honesty is in what we *say* if asked, not an on-screen asterisk.

### The target app
- AI-generated (~150 lines), **screenshot the generation** for the Semgrep prize.
- **One provable traversal + 3–4 other genuine Semgrep hits that end UNPROVEN** (a couple
  of real-but-not-file-read-exploitable sinks, one classic false positive). Without
  rejects there's no funnel to show.

---

## 4. The demo spine

1. **Plant the secret live, on screen:** oracle prints
   `planted FLAG-9f3a2c… (the agent is never told this value)`.
2. Show **Semgrep's raw, noisy candidate list** — "maybes."
3. Run Litmus live; watch the list **collapse to one PROVEN + the rest UNPROVEN**, with the
   exact HTTP request that worked rendered next to the PROVEN stamp.
4. The one-liner: *"Any scanner lists maybes. Watch Litmus extract a secret that didn't
   exist when I started this sentence."*

The funnel shrinking on screen **is** the narrative. Visible randomness is the showstopper.

---

## 5. Prize framing (honest)

- **Semgrep prize:** "Semgrep surfaces a real vulnerability in AI-generated code; Litmus
  proves it's genuinely exploitable." The oracle *elevates* the Semgrep finding, doesn't
  compete with it. (App is AI-generated, so the finding qualifies.)
- **ClickHouse prize:** lean into **query latency and the insight the funnel gives**, not
  raw row count. Scale **honestly** — AI-generate several apps and scan them all. **Never
  replay one candidate thousands of times to inflate rows.**
- **The fallback:** keep it, present it honestly — "an LLM agent attempts the exploit live;
  if it stalls, a deterministic exploit for the same vulnerability guarantees the proof
  lands, and the oracle validates the result regardless of which produced it." Never claim
  pure autonomy.

---

## 6. Build order

The risk profile is **gold-plating that breaks the working loop**, not time pressure
(the full day is available). The lunch floor and the ~16:30 checkpoint are **de-risking
gates**, not endpoints.

| Time | Work | Gate |
|---|---|---|
| **by 10:20** | Repo + `docker compose` skeleton, API key pre-flighted, Semgrep installed | setup done |
| **10:20–11:00** | AI-generate the app (1 plant + 3–4 decoys). **Immediately run Semgrep → confirm it flags the plant.** Adjust the sink until it fires. | **Semgrep green** |
| **11:00–12:15** | Oracle (plant/rotate secret, read the wire) + negative control + two-container net-only setup + **scripted exploit, end-to-end PROVEN** | **FLOOR: one proof, live, by lunch** |
| **12:15–12:45** | Lunch + gate check. Green? Climb. Not green? It's the *only* thing you touch. | |
| **12:45–14:00** | Claude attacker on top (script → fallback) + dashboard on local log + wire the demo spine | agent + UI demoable |
| **14:00–15:30** | Full candidate set → real funnel with rejects. ClickHouse behind the same interface + funnel/latency panels. 2–4 more AI-gen apps for honest scale. | sponsor depth |
| **~15:30–16:30** | **Freeze a safe version and bank it** — if anything is nominally due at 16:30, submit *this* working build. Pre-record the backup run. First full dry-run on the real network. | **safe version banked** |
| **16:30 → live slot** | Climb, sequenced by value (§8). Every item on a branch/flag; green baseline always runnable. | ceiling work |
| **~45 min before live slot** | Re-freeze, re-dry-run the exact demo, time it, stop touching it | **demo locked** |

---

## 7. The one discipline that protects all of this

**You must be able to `git stash` back to a working demo in ten seconds, all day.**

Every stretch item in §8 must be addable **without editing the files the green demo runs
on** — a new oracle module, a new dashboard panel, a feature flag. The moment a stretch
item forces a change to the proven path, branch it. The green baseline is sacred.

---

## 8. Stretch, in value order

Do these in order after the safe version is banked; stop wherever the day runs out.

1. **RCE as a second capability class** — highest value. Proves the oracle *generalizes
   across capabilities* (the paper's real structure). Upgrades the story from "a clever
   file-read trick" to "a proof *framework*."
2. **ClickHouse honest scale** — more apps, more candidates, latency/funnel-insight panels.
3. **Triage LLM stage** — the "reduce false positives before exploitation" narrative
   garnish; cheap once the loop exists.
4. **Guild.ai** — host the agents; only after the agents are solid.

Explicitly **not** pursued: Akash/Pi/Senso (correctly cut — no fit for this build).

---

## 9. Non-goals (out of scope for the day)

- Detector *synthesis* (we use Semgrep's rules as-is).
- The paper's custom graph engine / eCPG traversals / Antigraph.
- Client-side vulnerability classes (XSS, etc.).
- Scanning or attacking any system we do not own.
- Cross-capability generality claims we haven't actually built.

---

## 10. Open item

**The exact live judging slot** sets the "re-freeze 45 min before" clock time. Fill it in
once known:

- Live demo / judging slot: `____`
- Therefore final freeze at: `____`
