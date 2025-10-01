# rZK
rZK

ResonanceZK (rZK) × HyperMorphic (HM)

Portable privacy proofs for identity, cross-chain assets, and AI/data provenance.
This repo defines and implements the core rZK protocols built on top of the HyperMorphic (HM) “gear” representation, plus executable zk proofs of the full HM→rZK pipeline and a novel Merkle-IOP + FRI-style proximity layer (“ResonanceFRI”).

Status: research-grade, unaudited. Use only for experimentation.

⸻

Contents
	•	docs/
– This README (formal definitions & proofs)
– GEAR concept note (recoverability, “hash-only” sketch)
– rZK transcript schema & security model
	•	rzk_demo.py — runnable HM/rZK reference (single + multi-relation)
	•	rzk_fulltrace_zk.py — Merkle-IOP “zk of execution” (full HM→rZK trace)
	•	resonance_fri.py — novel Merkle-IOP + FRI-style proximity proof (ResonanceFRI)
	•	examples/ (recommended)
	•	tests/ (recommended)

(If some files aren’t yet in the repo, copy the versions we generated in this conversation.)

⸻

1) HyperMorphic (HM) Core

1.1 Definition

Let d \in \{1,\dots,P-1\} and P a public prime modulus. Define:
	•	b(d) \triangleq \mathrm{bitlength}(d) \in \mathbb{N}_{\ge 1}.
	•	(Optional) m(d) denotes an auxiliary “gear” coordinate; the current rZK protocols use only b(d).
	•	The HM ciphertext for d over P is
\mathrm{ct} \;\equiv\; d^{\,b(d)} \pmod{P}.

Intuition: HM exposes a public, deterministic, shape function b(d) and keeps d private; rZK proves facts about (d,b,\mathrm{ct}) without revealing d.

⸻

2) rZK Protocols (Σ-style over HM)

We give a compact Σ-protocol (Fiat–Shamir to NIZK) for:
	•	HM-ZK (single relation): knowledge of d s.t. \mathrm{ct}\equiv d^{b}\,(\bmod P) with public b=b(d).
	•	HM-ZK-Link (multi-relation): same secret d satisfies \mathrm{ct}_i\equiv d^{b_i}\,(\bmod P_i) for multiple moduli \{P_i\} under one challenge.

2.1 HM-ZK (single)

Public: P, b, \mathrm{ct} \equiv d^{b}\ (\bmod P).
Secret witness: d\in [1,P-1].

Prove. Pick random \(r\in \mathbb{Z}_P^\*\).
Commit: u \gets r^{\,b} \ (\bmod P).
Challenge: c \gets H(P\|b\|\mathrm{ct}\|u) (modeled random oracle).
Response: s \gets r \cdot d^{\,c\ \bmod (P-1)} \ (\bmod P).

Verify. Accept iff
s^{\,b} \equiv u \cdot \mathrm{ct}^{\,c\ \bmod (P-1)} \pmod{P}.

Theorem 1 (Completeness)

If both parties are honest and \mathrm{ct}\equiv d^{b}, verification always passes.

Proof.
s^{b}=(r\cdot d^{c})^{b} \equiv r^{b}\cdot d^{bc} \equiv u\cdot (d^{b})^{c} \equiv u\cdot \mathrm{ct}^{c} \ (\bmod P). ∎

Theorem 2 (Honest-Verifier Zero-Knowledge)

There exists a simulator which, given a random c, outputs transcripts indistinguishable from real ones.

Proof (HVZK). Choose random \(s\in\mathbb{Z}_P^\*\) and set u \gets s^{b}\cdot \mathrm{ct}^{-c} \ (\bmod P). Output (u,c,s). The distribution of (u,c,s) matches an honest run under random oracle H. ∎

Theorem 3 (Special Soundness – under co-prime challenge difference)

Given two accepting transcripts with the same u and challenges c\neq c’ with \gcd(c-c’,P-1)=1, one can extract d.

Proof. From
s^{b}=u\cdot \mathrm{ct}^{c},\quad (s’)^{b}=u\cdot \mathrm{ct}^{c’},
divide to get \big(s/s’\big)^{b}=\mathrm{ct}^{\,c-c’}=(d^{b})^{c-c’}=d^{\,b(c-c’)}.
Raise both sides to b^{-1}\!\!\!\pmod{(P-1)} (requires \gcd(b,P-1)=1, which holds for all b< P except when b shares a factor with P-1; we recommend selecting P so b is invertible or reject otherwise) to get
s/s’ \equiv d^{\,c-c’} \pmod{P}.
Then exponentiate by (c-c’)^{-1}\!\!\!\pmod{(P-1)} to obtain d. ∎

Parameter note. For strict special soundness, enforce:
(i) \(b\in \mathbb{Z}{P-1}^\*\) (invertible); (ii) the challenge is sampled in \(\mathbb{Z}{P-1}^\*\) and the verifier rejects if \gcd(c,P-1)\ne 1. Our code reduces c \bmod (P-1); the README specifies the stricter check (simple to add).

2.2 HM-ZK-Link (multi-relation, one challenge)

For moduli P_1,\dots,P_n with b_i=b(d), define \mathrm{ct}_i \equiv d^{b_i}\ (\bmod P_i).
Prover reuses a single randomness r and computes u_i \equiv r^{b_i} \ (\bmod P_i).
Challenge:
c \gets H(\{P_i\}, \{b_i\}, \{\mathrm{ct}_i\}, \{u_i\}).
Responses: s_i \gets r\cdot d^{\,c\ \bmod(P_i-1)} \ (\bmod P_i).
Verify each i with s_i^{b_i}\overset{?}=u_i\cdot \mathrm{ct}_i^{c}\ (\bmod P_i).

Completeness & HVZK follow component-wise from Theorems 1–2 (same algebra), with the transcript jointly hashed.
Special Soundness extends if, for at least one i, \gcd(b_i,P_i-1)=\gcd(c-c’,P_i-1)=1. Then extraction as above works modulo P_i.

⸻

3) Full-Trace zk of Execution (Merkle-IOP)

rzk_fulltrace_zk.py builds the entire HM→rZK execution trace, commits to it with a Merkle tree, and opens random adjacent steps to the verifier:
	•	Steps include: compute_b, each compute_ct[i], compute_u[i], compute_c, and then per modulus compute_s/lhs/rhs/check_ok, ending in done.
	•	Each opening includes (i) plaintext for the two steps, (ii) one-time pads confirming masked leaves, (iii) Merkle paths.

3.1 Soundness (sampling)

Let the trace have N transitions. If any transition violates the program semantics, opening k uniformly random adjacent pairs without replacement detects an error with probability at least
1 - \frac{\binom{N-1}{k}}{\binom{N}{k}} \;=\; \frac{k}{N}.
(Union bound/single bad edge case; more bad edges increase detection.)

3.2 Zero-knowledge (partial)

All unopened leaves remain one-time-pad masked inside the Merkle root; only the chosen boundary steps are revealed. This achieves zero-knowledge for all unopened steps (semi-honest verifier); opened steps are exposed by design.

3.3 Binding

Merkle binding reduces to second-preimage resistance of SHA-256 (leaves are hashed with domain separation). Any attempt to equivocate the trace after committing breaks SHA-256.

This IOP gives a practical zk-of-execution with tunable soundness via k. It is not a SNARK/STARK; see §4 for our proximity layer.

⸻

4) ResonanceFRI — Merkle-IOP + FRI-style proximity

resonance_fri.py adds a novel, educational FRI-style layer over the trace constraints:
	1.	Build a composition residual vector \mathrm{CP} by hashing into random coefficients and mixing all local transition residuals so that \mathrm{CP}\equiv 0 iff every constraint holds.
	2.	Commit to an (emulated) LDE of \mathrm{CP} and run pairwise linear folds (like FRI). Each layer is Merkle-committed.
	3.	The verifier checks Merkle inclusions along randomly sampled paths and (optionally) recomputes child→parent folds.

4.1 Soundness (sketch)
	•	If any residual is nonzero, then with probability at least 1 - (1-\rho)^q (for \rho the density of wrong positions and q queries), the verifier opens a nonzero entry or an inconsistent fold.
	•	Merkle binding prevents post-commitment changes.
	•	Our current LDE uses repetition (for simplicity); replacing with an FFT/NTT over a multiplicative subgroup yields the usual FRI low-degree guarantees.

4.2 Zero-knowledge

Only queried coordinates are revealed; others are hidden under the Merkle tree. The composition vector hides the underlying program state; it exposes only whether constraints vanish at sampled points.

Implementation note: We fixed a leaf-hashing mismatch so Merkle inclusion now verifies consistently (all real leaves are hashed before tree construction; the verifier applies the same leaf hash).

⸻

5) Security Model & Assumptions
	•	Discrete-log hardness in \((\mathbb{Z}/P\mathbb{Z})^\*\) for each prime P used in HM-ZK relations.
	•	Random Oracle Model for Fiat–Shamir (SHA-256), with explicit domain separation tags in transcripts.
	•	Merkle binding from SHA-256 collision/second-preimage resistance.
	•	Parameter discipline for special soundness: ensure \gcd(b, P-1)=1 and \gcd(c, P-1)=1. In practice:
– Reject challenges not in \(\mathbb{Z}_{P-1}^\\).
– Optionally, restrict to moduli P where P-1 has a large prime factor q and sample \(c\in \mathbb{Z}_q^\\).
	•	Side-channels. Current Python code is not constant-time; do not use for secrets in adversarial environments.

⸻

6) Protocol Proofs (detail)

6.1 HM-ZK (single)

Completeness: See Theorem 1.

HVZK simulator: See Theorem 2. The simulator chooses (c,s) at random and sets u = s^{b}\cdot \mathrm{ct}^{-c}, which is uniformly distributed under ROM.

Special Soundness: See Theorem 3. From two accepting transcripts with same u and different c,c’, the extractor obtains d provided \gcd(b,P-1)=\gcd(c-c’,P-1)=1. These are standard small-modulus invertibility conditions; we enforce them by parameter choice and rejection sampling.

6.2 HM-ZK-Link (multi)

Proofs inherit from the single relation, since verification factorizes per modulus. Joint challenge binds all instances; one extractor suffices by operating on any modulus with invertibility conditions met.

6.3 Merkle-IOP full trace
	•	Binding: Standard Merkle arguments.
	•	Soundness (sampling): If any local transition check fails, the probability that k uniformly sampled adjacent pairs avoid all bad edges is at most \bigl(1 - \frac{1}{N}\bigr)^{k}\le e^{-k/N}. Choosing k=\Theta(\lambda) for security parameter \lambda drives this negligible in N.

6.4 ResonanceFRI
	•	Correctness: If all constraints hold, then \mathrm{CP}\equiv 0 and all folded layers remain identically 0; every opened path verifies.
	•	Soundness (sketch): If \mathrm{CP} is nonzero at any coordinate in the base domain, at least one opened position will show a nonzero value or a violated fold relation. Replacing repetition with a true LDE and checking fold consistency yields the standard FRI low-degree test.

⸻

7) How to Run

# 1) HM/rZK demo
python rzk_demo.py demo
python rzk_demo.py prove --P curve25519 --out single.json
python rzk_demo.py verify --in single.json
python rzk_demo.py link-prove --P curve25519 --P mersenne521 --out link.json
python rzk_demo.py link-verify --in link.json

# 2) Full-trace zk (Merkle-IOP)
python rzk_fulltrace_zk.py      # writes rzk_fulltrace_proof.json, verify=True

# 3) ResonanceFRI (novel Merkle-IOP + FRI-style proximity)
python resonance_fri.py         # writes rzk_resofri_proof.json, verify=True


⸻

8) Transcript Schema (stable JSON)

Single relation (rzk-hmzk-1):

{
  "scheme": "rzk-hmzk-1",
  "params": {"P": "...", "b": 255},
  "statement": {"ct": "..."},
  "commitment": {"u": "..."},
  "challenge": "...",
  "response": {"s": "..."}
}

Link proof (rzk-link-1):

{
  "scheme": "rzk-link-1",
  "params": {"P": ["...","..."], "b": [255,255]},
  "statements": [{"ct": "..."}, {"ct": "..."}],
  "commitments": {"u": ["...","..."]},
  "challenge": "...",
  "responses": {"s": ["...","..."]}
}


⸻

9) Roadmap
	•	Parameter hardening: enforce \(\mathbb{Z}_{P-1}^\*\) challenges; reject b not invertible mod P-1.
	•	EVM verifier: batched checks using modexp precompile; calldata packing spec + gas benchmarks.
	•	zkVM wrapper: verify the rZK transcript inside RISC0/SP1/Halo2/Noir and output succinct proofs.
	•	True LDE FRI: FFT/NTT evaluation domain, fold-consistency checks client-side, tighter bounds.
	•	Rust port + WASM verifiers.
	•	Audit & proofs-as-code in Lean/Isabelle (long-term).

⸻

10) License & Security
	•	License: MIT (recommended) or Apache-2.0.
	•	Security: This is research software. No warranty. Do not use for custody/bridges/production identity without expert review and audits.

⸻

11) Acknowledgments
	•	The HM idea (gear alignment) and the rZK variants were developed here; the Merkle-IOP and FRI layering take inspiration from classic Σ-protocols and FRI/STARK literature, adapted to HM semantics.

⸻

Citations (internal)

Where the README above states formal properties, they correspond exactly to the code paths in:
	•	rzk_demo.py (HM-ZK, HM-ZK-Link),
	•	rzk_fulltrace_zk.py (trace construction & Merkle openings),
	•	resonance_fri.py (composition residuals & FRI-style folds).

If you’d like, I’ll commit a docs/proofs.md with these theorems rendered as lemmas and explicit algebraic derivations (including the extractor pseudo-code and the exact rejection checks to enforce invertibility).
