# NuMeQ Math

This document collects the mathematical content implemented across the repo into one place. The code remains the source of truth, but this file is meant to be the single human-readable map of the algebra, constraints, folding rules, and seal-layer relations used by NuMeQ.

## 1. Canonical Instance

NuMeQ's current production profile is the canonical profile selected by `NuProfile.canonical`:

- Profile name: `AG64-SNQ-OneStack-A` v3
- Base field modulus: 

  `q = 2^64 - 2^32 - 31 = 0xFFFF_FFFE_FFFF_FFE1`

- Ring polynomial

  `Phi(X) = X^64 + 1`

- Ring degree: `d = 64`
- Commitment rank: `16`
- Recursive-fold decomposition base: `b_dec = 2`
- Recursive-fold decomposition limbs: `L_dec = 13`
- Recursive-fold PiDEC representability ceiling:

  `B_max = b_dec^L_dec = 2^13 = 8192`

- Challenge set for ring-valued fold challenges:

  `C_rho = {-1, 0, 1, 2}`

- Max supported recursive depth: `32`
- Fiat-Shamir challenge count: `16`
- Hachi table-budget metadata: `1024` evaluations (`2^10`); actual multilinear arities are shape-dependent
- Hachi batching width: `8`
- PiDEC interval: `1`
- Informational security estimates from the in-repo heuristic profile search:
  - raw bits = `222`
  - composed bits = `174`

The raw/composed security-bit figures above are profile metadata copied from the heuristic estimator in `NuProfile.swift`. They are not derived from the algebra in this note and should not be read as theorem statements.

The algebraic tower is:

- `Fq`
- `Fq2 = Fq[u] / (u^2 - 3)`
- `Fq4 = Fq2[v] / (v^2 - eta)` for a certified nonsquare `eta in Fq2`
- `Rq = Fq[X] / (X^64 + 1)`

For exposition below, it is convenient to take `eta = u`, which is a valid certified choice. The implementation stores a deterministic certified `eta` in `NuProfile.quarticEta`; the field formulas below hold for any nonsquare `eta in Fq2`.

The seal layer also has a separate direct-packed relation proof with its own decomposition parameters:

- `b_dir = 2`
- `L_dir = 64`

### 1.1 Notation used below

To avoid collisions, the rest of this note uses:

- `m_fold` for PiRLC fold arity
- `(b_dec, L_dec, B_max)` for the recursive-fold decomposition schedule
- `(b_dir, L_dir)` for the direct-packed seal relation
- `C_rho = {-1, 0, 1, 2}` for the coefficient alphabet of ring-valued PiRLC challenges

## 2. Base Field Fq

The base field is the Almost Goldilocks prime field:

`Fq = Z / qZ`

with

`q = 2^64 - 2^32 - 31`.

The repo uses a Solinas-style reduction identity for 128-bit products. If

`z = z_hi * 2^64 + z_lo`

then

`z mod q = z_lo + z_hi * (2^32 + 31) mod q`.

This works because

`2^64 = 2^32 + 31 mod q`.

The code keeps centered representatives when norms matter:

- centered magnitude:

  `|a|_c = min(a, q - a)`

- centered signed lift in

  `[-(q-1)/2, (q-1)/2]`

Field inversion is implemented with Fermat:

`a^(-1) = a^(q-2) mod q`.

## 3. Extension Fields

### 3.1 Quadratic extension Fq2

The quadratic extension is

`Fq2 = Fq[u] / (u^2 - beta)`

with `beta = 3`.

Why `beta = 3` instead of `-1`:

- for this modulus, `q = 1 mod 4`
- therefore `-1` is a square in `Fq`
- so `X^2 + 1` is reducible
- the repo certifies that `3` is a nonsquare via Euler's criterion:

  `3^((q-1)/2) = -1 mod q`

Write elements as

`a + b*u`, with `u^2 = 3`.

Multiplication is:

`(a0 + b0*u)(a1 + b1*u) = (a0*a1 + beta*b0*b1) + (a0*b1 + a1*b0)u`

The implementation uses Karatsuba:

- `aa = a0*a1`
- `bb = b0*b1`
- `ab = (a0+b0)(a1+b1)`
- result:
  - real part = `aa + beta*bb`
  - `u` part = `ab - aa - bb`

Conjugate, norm, inverse:

- `conj(a + b*u) = a - b*u`
- `N_{Fq2/Fq}(a + b*u) = a^2 - beta*b^2`
- `(a + b*u)^(-1) = conj(a + b*u) / N_{Fq2/Fq}(a + b*u)`

These are relative norms from `Fq2` down to `Fq`.

### 3.2 Quartic tower Fq4

The quartic tower is any extension

`Fq4 = Fq2[v] / (v^2 - eta)`

with `eta` a certified nonsquare in `Fq2`.

For clean hand calculations, one may take

`eta = u = (0, 1) in Fq2`.

This choice is valid because

`N_{Fq2/Fq}(u) = u * (-u) = -u^2 = -3`,

and in `Fq` the element `-1` is a square while `3` is a nonsquare, so `-3` is also a nonsquare. In a quadratic extension, an element is a square if and only if its relative norm is a square in the base field, hence `u` is a nonsquare in `Fq2`.

The implementation pins a deterministic certified `eta` in the profile certificate. The formulas below are valid for any such nonsquare `eta`.

Write elements as

`A + B*v`, with `A, B in Fq2` and `v^2 = eta`.

Multiplication is:

`(A0 + B0*v)(A1 + B1*v) = (A0*A1 + eta*B0*B1) + (A0*B1 + A1*B0)v`

The implementation again uses Karatsuba:

- `AA = A0*A1`
- `BB = B0*B1`
- `cross = (A0+B0)(A1+B1) - AA - BB`
- result:
  - real part = `AA + eta*BB`
  - `v` part = `cross`

Conjugate, norm, inverse:

- `conj(A + B*v) = A - B*v`
- `N_{Fq4/Fq2}(A + B*v) = A^2 - eta*B^2`
- `(A + B*v)^(-1) = conj(A + B*v) / N_{Fq4/Fq2}(A + B*v)`

These are relative norms from `Fq4` down to `Fq2`.

The quartic tower is also structurally forced by the ring polynomial. Since

`X^64 + 1 = Phi_128(X)`,

the factor degree over `Fq` is controlled by the order of `q` modulo `128`. Here

`q mod 128 = 97`

and `ord_128(q) = 4`, so `X^64 + 1` factors over `Fq` into `64 / 4 = 16` irreducible quartics. Therefore `Fq4` is the smallest extension where the negacyclic ring polynomial splits completely, which is why scalar extension into a quartic field is mathematically natural.

The ring multiplication code scalar-extends into `Fq4`, multiplies there, checks that every accumulated coefficient still lies in the embedded copy of `Fq`, and only then reinterprets that value as a base-field coefficient.

## 4. Negacyclic Ring Rq

The ring is

`Rq = Fq[X] / (X^64 + 1)`.

Since

`X^64 = -1`,

this is a negacyclic ring.

If

`a(X) = sum_{i=0}^{63} a_i X^i`

and

`b(X) = sum_{i=0}^{63} b_i X^i`,

then the product coefficients satisfy

`c_k = sum_{i+j=k} a_i b_j - sum_{i+j=k+64} a_i b_j`

for `0 <= k < 64`.

Multiplication by `X^k` is a negacyclic rotation:

- shift coefficients by `k`
- negate coefficients that wrap past degree `63`

The repo tracks two norms on ring elements:

- infinity norm:

  `||r||_inf = max_i |c_i|_c`

- squared `L2` norm:

  `||r||_2^2 = sum_i |c_i|_c^2`

## 5. Rotation Matrices

For `a in Rq`, the rotation matrix `Rot(a)` is the `64 x 64` negacyclic convolution matrix such that

`Rot(a) * vec(b) = vec(a * b)`.

Entrywise:

- `Rot(a)[i, j] = a_{i-j}` when `i >= j`
- `Rot(a)[i, j] = -a_{i-j+64}` when `i < j`

This is the math behind the Metal commitment kernels: instead of doing a full symbolic ring multiplication, the implementation performs sparse rotation-matrix accumulation.

## 6. Witness Packing

NuMeQ uses the canonical SuperNeo embedding from field vectors into ring vectors:

- every contiguous block of `64` field elements becomes one ring element
- the block is written directly into the coefficient slots
- the final partial block is zero-padded

So a field vector of length `64*n` becomes a ring vector of length `n`.

## 7. Ajtai Commitment

The commitment key is a vector

`a = (a1, ..., an) in Rq^n`.

For a witness vector

`w = (w1, ..., wn) in Rq^n`,

the commitment is

`Com_a(w) = sum_i a_i * w_i in Rq`.

This same linear form is reused throughout the repo:

- witness commitments
- decomposition-limb commitments
- direct-packed relation images
- direct-packed outer commitments

The Metal kernels compute the same quantity with the rotation-table representation of the key.

## 8. Multilinear Polynomials

A multilinear polynomial in `nu` variables is represented by its evaluations on the Boolean hypercube:

`f : {0,1}^nu -> Fq`.

The repo stores the full evaluation table of size `2^nu`.

The actual arity `nu` is determined by the concrete oracle being committed. The profile metadata field named `hachiVariableCount` carries the legacy value `1024`; mathematically that should be read as an evaluation-table budget (`2^10`), not as a claim that the protocol uses `1024` literal multilinear variables.

Evaluation at an arbitrary point `r in Fq^nu` is the multilinear extension:

`f(r) = sum_{x in {0,1}^nu} f(x) * eq_r(x)`

where

`eq_r(x) = prod_i ((1-r_i) if x_i = 0 else r_i)`.

The implementation computes this by repeated interpolation:

`next[j] = (1-r_i) * table[2j] + r_i * table[2j+1]`.

Binding the first variable to `r` reduces the variable count by one using the same interpolation rule.

## 9. CCS Relation

The repo lowers constraints to a Customizable Constraint System (CCS).

A CCS instance consists of:

- matrices `M1, ..., Mt in Fq^(m x n)`
- gate index multisets `S1, ..., Ss`, where each `Si` is represented as an ordered list

  `Si = (s_{i,1}, ..., s_{i,deg_i})`, with every `s_{i,a} in [t]`

- coefficients `c1, ..., cs in Fq`
- witness/public assignment `z in Fq^n`

The satisfaction relation is:

`sum_i c_i * (circ_{a=1}^{deg_i} (M_{s_{i,a}} * z)) = 0 in Fq^m`

where `circ` is the Hadamard product.

For row `r`, the row constraint is:

`sum_i c_i * prod_{a=1}^{deg_i} (M_{s_{i,a}} z)[r] = 0`.

This notation preserves multiplicity. If the same matrix index appears more than once in a gate, the corresponding row value is repeated in the Hadamard product, exactly as in the Swift `matrixIndices: [UInt16]` representation.

Sparse matrices are stored in CSR format, but the math is ordinary sparse matrix-vector multiplication:

`y = M * z`.

## 10. PiCCS: Strong CCS Reduction

PiCCS is the first folding stage. It reduces the `m` row constraints to a single multilinear sum-check claim.

Given a folded CCS instance, PiCCS samples

`tau in Fq^m`

from the transcript and forms a linearized table:

`gateSum[i] = sum_g c_g * prod_{a=1}^{deg_g} (M_{s_{g,a}} z)[i]`

`p(i) = tau_i * gateSum[i]`

The repo places these values into a multilinear evaluation table of size

`2^ceil(log2(m))`,

padding with zeros beyond the first `m` rows.

The resulting sum-check claim is

`sum_{x in {0,1}^nu} p(x) = 0`.

PiCCS also records the projected matrix evaluations

`proj_j = sum_i tau_i * (M_j z)[i]`.

### Sum-check form used in the repo

For each round, the prover sends the two evaluations of the round polynomial:

`s_r(0)` and `s_r(1)`

where

`s_r(X) = sum_{b in {0,1}^{nu-r-1}} p(r1, ..., r_{r-1}, X, b)`.

The verifier checks:

- `s_r(0) + s_r(1) = previous_claim`
- samples the next challenge `r_r`
- updates:

  `previous_claim = (1-r_r) * s_r(0) + r_r * s_r(1)`

The final claim must match the polynomial evaluation at the final challenge point.

## 11. PiRLC: Random Linear Combination Fold

PiRLC is the second folding stage. The implementation performs an accumulator-style `m_fold`-ary fold with a distinguished base instance `0`; it should not be read as the generic quadratic residual formula for simultaneously folding all instances of a relaxed quadratic relation.

Each ring challenge is a ring

`rho_i in Rq`

whose coefficients are independently drawn from

`C_rho = {-1, 0, 1, 2}`.

Field-valued claims are folded with separate Fiat-Shamir scalars

`alpha_i in Fq`

derived from transcript domain `PiRLC.scalar_fold`. They are not taken from a coefficient of `rho_i`.

Given inputs

`(C_i, w_i, x_i, y_i, u_i, e_i)`,

the repo computes:

- folded commitment:

  `C' = sum_i rho_i * C_i`

- folded witness:

  `w' = sum_i rho_i * w_i`

- folded public inputs:

  `x' = sum_i alpha_i * x_i`

- folded CCS evaluations:

  `y' = sum_i alpha_i * y_i`

- folded relaxation factor:

  `u' = sum_i alpha_i * u_i`

The implementation also forms cross terms against the distinguished witness `w_0`:

`T_j[l] = w_0[l] * w_j[l]`

for `j = 1, ..., m_fold-1`.

These are committed with the same Ajtai commitment.

Folded error terms are computed as:

`e'[l] = sum_{i=0}^{m_fold-1} rho_i * e_i[l] + sum_{j=1}^{m_fold-1} rho_j * T_j[l]`

with missing entries treated as zero.

This is the exact accumulator recurrence implemented in `NuMetal-Q/NuFold/PiRLC.swift`. A generic quadratic expansion of a simultaneous relaxed fold would instead involve squared challenge weights and pairwise bilinear terms for all `i < j`. The current note therefore documents PiRLC as a specific accumulator update, not as the generic formula for every quadratic relaxed relation.

To turn this section into a theorem statement, one would first need the exact relaxed-instance invariant `I(C, w, x, y, u, e)` that the code intends the tuple to satisfy, and then a proof that the recurrence above plus the committed cross terms preserve `I`. This note does not currently supply that invariant or preservation proof, so Section 11 should be read as an implementation map rather than a standalone soundness theorem.

## 12. Norm Budget and PiDEC

Folding grows witness norms, but the implementation variable `currentNorm` is not a certified upper bound for negacyclic multiplication. It is an operational scheduler used together with a fixed PiDEC cadence.

### 12.1 Deterministic ring bound

For `a, b in Rq`, the coefficientwise negacyclic convolution satisfies the deterministic inequality

`||a * b||_inf <= ||a||_1 * ||b||_inf <= 64 * ||a||_inf * ||b||_inf`

where

`||a||_1 = sum_i |a_i|_c`.

For a PiRLC challenge ring `rho` with coefficients in `C_rho = {-1, 0, 1, 2}`, one has

`||rho||_inf <= 2`

and

`||rho||_1 <= 64 * 2 = 128`.

Therefore, for a folded witness

`w' = sum_{i=0}^{m_fold-1} rho_i * w_i`,

the safe deterministic bound is

`||w'||_inf <= sum_{i=0}^{m_fold-1} ||rho_i||_1 * ||w_i||_inf`.

If all incoming witnesses satisfy a common bound `||w_i||_inf <= B`, then

`||w'||_inf <= 128 * m_fold * B`.

This `L1/L_inf` estimate is the certified bound available from the ring algebra described in this note.

### 12.2 Why the current scheduler is only heuristic

The implementation in `NuMetal-Q/NuFold/NormBudget.swift` initializes `currentNorm` to the maximum coefficient infinity norm of the packed witness. After an `m_fold`-ary PiRLC step it sets

`challengeMagnitude = max_i ||rho_i||_inf`

and updates:

`currentNorm <- m_fold * currentNorm + challengeMagnitude`

and increments the fold counter.

This recurrence is not a valid convolution certificate. A concrete counterexample is

`rho = 2 * (1 + X + ... + X^63)`

and

`w = 1 + X + ... + X^63`.

Then `||rho||_inf = 2` and `||w||_inf = 1`, but the actual negacyclic product satisfies

`||rho * w||_inf = 128`.

Starting from `currentNorm = 1`, the scheduler above would predict `3`, not `128`. With two such terms in a two-way fold, the true infinity norm can reach `256` while the scheduler predicts only `4`. Accordingly, `currentNorm` must be read as an operational proxy tied to the profile's forced PiDEC cadence, not as a standalone theorem about ring multiplication.

After a decomposition, the implementation resets the proxy by

`currentNorm <- b_dec - 1`.

That reset is likewise scheduler bookkeeping rather than a proof artifact.

### 12.3 Canonical one-step proof path

The canonical profile uses PiDEC interval `1`. If each witness entering PiRLC has already been normalized to signed binary digits, so that `||w_i||_inf <= 1`, then the deterministic bound above gives

`||w'||_inf <= 128 * m_fold`.

Since `B_max = 8192`, this stays below the PiDEC representability ceiling whenever

`m_fold < 64`.

So a real proof path exists for the canonical cadence, but it is the `L1/L_inf` bound above, not the current `currentNorm` recurrence.

### 12.4 Decomposition

In the canonical recursive fold path,

`b_dec = 2`, `L_dec = 13`, and `B_max = 2^13 = 8192`.

For a centered coefficient `c` with `|c|_c < B_max`, PiDEC decomposes it as:

`c = sum_{l=0}^{L_dec-1} d_l * b_dec^l`

with digits satisfying

`|d_l| < b_dec`.

Because `b_dec = 2` in the canonical profile, every digit lies in

`d_l in {-1, 0, 1}`.

For a ring element, decomposition is done coefficientwise, producing `L_dec` ring limbs.

The strict inequality is essential: `8191` is representable, while `8192` is not. Any statement or code path using `|c|_c <= B_max` would be too strong.

### PiDEC commitment check

Let `L_l` be the commitment to the vector of all `l`-th limbs. PiDEC checks:

`sum_{l=0}^{L_dec-1} b_dec^l * L_l = C_orig`

The verifier also checks that every output limb coefficient satisfies the centered bound `< b_dec`; in the canonical profile this is equivalent to checking digits in `{-1, 0, 1}`.

## 13. Hachi Backend: General Path

The terminal seal layer uses a multilinear opening backend with two modes. In the code this component is called a PCS backend; mathematically, the general path is an authenticated repetition oracle built on top of the multilinear evaluation table.

For the general path:

1. The polynomial evaluation table `base = f.evals` of size `2^nu` is packed into ring chunks with the canonical 64-to-1 packing.
2. The packed table is committed with an Ajtai commitment, and the raw evaluation table is hashed into `tableDigest`.
3. The implementation then forms a length-`4n` repetition oracle (named `codeword` in the code) by repeating the base table with blowup factor `4`:

   `codeword[t] = base[t mod n]`

4. A Merkle tree is built over the codeword.

This repetition step is not a low-degree extension. By itself it is only a Merklized repetition oracle. In NuMeQ, soundness for the general path comes from the surrounding seal relation, transcript binding, table digest, Ajtai table commitment, and Merkle authentication, not from a standalone low-degree PCS argument.

### Merkle hashing

Leaves use SHA-256 over the domain-tagged payload:

`leaf = SHA256(0x00 || little_endian_64(field_element))`

Parents use:

`parent = SHA256(left || right)`

Odd levels duplicate the last node before hashing upward.

### Query indexing

For opening point `r` and oracle label `o`, the queried codeword position is:

`index = H(r || o) mod codewordLength`

where `H` is the repo's cSHAKE256 digest with domain

`NuMeQ.Decider.Hachi.QueryIndex`.

### Batch scheduling

For a batch seed `s`, point `r`, and sorted oracle list `(o_1, ..., o_t)`, the schedule digest is

`Sched = H(s || r || o_1 || ... || o_t)`

with domain

`NuMeQ.Decider.Hachi.Schedule`.

## 14. Hachi Backend: Direct-Packed Path

If the packed witness has chunk count in `{1, 2, 4}`, the repo switches to a direct-packed relation opening instead of the codeword/Merkle path.

### 14.1 Evaluation weights

For point `r in Fq^ell`, the multilinear equality weights are:

`eq_r(x) = prod_i ((1-r_i) if x_i = 0 else r_i)`

for all `x in {0,1}^ell`.

These weights are chunked into groups of 64 coefficients and then expanded across decomposition limbs:

`lambda_{chunk, limb} = b_dir^limb * chunkWeights`

with `b_dir = 2` and `L_dir = 64` in the direct-packed relation.

Because `(q - 1) / 2 < 2^63`, a `64`-limb signed binary expansion is sufficient for every centered field representative.

### 14.2 Short linear witness relation

For each packed witness chunk:

1. Decompose the packed chunk into `L_dir = 64` base-`b_dir = 2` limb rings. This is the short witness.
2. Form an inner linear image with the direct-packed relation key.
3. Decompose that inner image into another `L_dir = 64` base-`b_dir = 2` limb rings. These are the outer digits.
4. Commit those outer digits with the outer key.

The direct-packed proof simultaneously enforces four linear relations:

1. Binding relation:

   `bindingImage_i = <A_bind, shortWitness_i>`

2. Inner/outer consistency relation:

   `<A_rel, shortWitness_i> - sum_l b_dir^l * outerDigits_{i,l} = 0`

3. Evaluation relation:

   `sum_{i,l} <shortWitness_{i,l}, lambda_{i,l}>_0 = claimedValue`

   For ring elements

   `w(X) = sum_{j=0}^{63} w_j X^j`

   and

   `lambda(X) = sum_{j=0}^{63} lambda_j X^j`,

   define the negacyclic involution

   `sigma(lambda)(X) = lambda(X^(-1)) mod (X^64 + 1) = lambda_0 - sum_{j=1}^{63} lambda_j X^{64-j}`.

   Then

   `<w, lambda>_0 = const( w * sigma(lambda) ) = sum_{j=0}^{63} w_j lambda_j`.

4. Outer commitment relation:

   `outerCommitment_i = <A_outer, outerDigits_i>`

### 14.3 Compression strategy

The proof reduces these vector relations by repeated halving:

- each round splits vectors into left and right halves
- commits to cross-images
- samples a fold challenge from `{+1, -1}`
- folds witnesses with `x + c*y`
- folds coefficient vectors with the inverse challenge

After logarithmically many rounds, the proof performs a masked response step:

- mask coefficient vectors are sampled by a cSHAKE-seeded inverse-CDF discrete Gaussian sampler over centered integers with sigmas `4096` and `8192`; the implementation truncates support at `16 sigma`, where the omitted tail is negligible for the canonical parameters, and then reduces coefficientwise into `Fq`
- response challenge is sampled from `{-1, 0, 1}`
- responses are accepted only if:
  - all centered coefficients stay below `2^16`
  - the rejection test accepts

Because the accepted centered coefficients stay far below `q / 2`, the centered integer lift used in this step is unambiguous.

The rejection test uses the standard norm-ratio style log condition:

`log(coin) <= min(0, (||mask||^2 - ||response||^2)/(2*sigma^2) - log(slack))`

with slack parameter `12`.

## 15. Metal Kernel Equivalences

The Metal side mirrors the same math:

- `NuAG64Common.metal`
  - `Fq` in two 32-bit limbs
  - same `beta = 3`
  - same negacyclic ring product formula
  - same Solinas-style reduction folded through the `2^64 = 2^32 + 31 mod q` identity
- `NuCommitKernels.metal`
  - Ajtai commitment as sparse rotation-matrix accumulation
  - batched ring multiplication and batched linear folds
- `NuMatrixKernels.metal`
  - sparse CCS matrix-vector multiplication
- `NuSumCheckKernels.metal`
  - partial sums for `s_r(0)` and `s_r(1)`
  - multilinear bind step `(1-r)e0 + r e1`
- `NuDecompKernels.metal`
  - centered digit extraction for power-of-two decomposition bases
- `NuSealKernels.metal`
  - repeated-table oracle extension
  - Merkle leaf hashing `SHA256(0x00 || leaf)`
  - Merkle parent hashing `SHA256(left || right)`

## 16. File Map

The main math-bearing files are:

- `NuMetal-Q/NuField/Fq.swift`
- `NuMetal-Q/NuField/Fq2.swift`
- `NuMetal-Q/NuField/Fq4.swift`
- `NuMetal-Q/NuField/RingElement.swift`
- `NuMetal-Q/NuField/RotationMatrix.swift`
- `NuMetal-Q/NuField/Transcript.swift`
- `NuMetal-Q/NuField/NuProfile.swift`
- `NuMetal-Q/NuField/NuParams.swift`
- `NuMetal-Q/NuIR/CCSRelation.swift`
- `NuMetal-Q/NuIR/MultilinearPoly.swift`
- `NuMetal-Q/NuIR/WitnessPacking.swift`
- `NuMetal-Q/NuFold/AjtaiCommitment.swift`
- `NuMetal-Q/NuFold/PiCCS.swift`
- `NuMetal-Q/NuFold/PiRLC.swift`
- `NuMetal-Q/NuFold/NormBudget.swift`
- `NuMetal-Q/NuFold/PiDEC.swift`
- `NuMetal-Q/NuSeal/HachiPCSBackend.swift`
- `NuMetal-Q/NuSeal/ShortLinearWitnessPoK.swift`
- `NuMetal-Q/NuSeal/SpartanProof.swift`
- `NuMetal-Q/NuMetal/Shaders/NuAG64Common.metal`
- `NuMetal-Q/NuMetal/Shaders/NuCommitKernels.metal`
- `NuMetal-Q/NuMetal/Shaders/NuMatrixKernels.metal`
- `NuMetal-Q/NuMetal/Shaders/NuSumCheckKernels.metal`
- `NuMetal-Q/NuMetal/Shaders/NuDecompKernels.metal`
- `NuMetal-Q/NuMetal/Shaders/NuSealKernels.metal`
