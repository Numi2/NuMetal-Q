# NuMeQ Math

This document collects the mathematical content implemented across the repo into one place. The code remains the source of truth, but this file is meant to be the single human-readable map of the algebra, constraints, folding rules, and seal-layer relations used by NuMeQ.

## 1. Canonical Instance

NuMeQ's current production profile is the canonical profile selected by `NuProfile.canonical`:

- Profile name: `AG64-SNQ-OneStack-A` v3
- Base field modulus:

  `q = 2^64 - 2^32 - 31 = 0xFFFF_FFFE_FFFF_FFE1`

- Ring polynomial:

  `Phi(X) = X^64 + 1`

- Ring degree: `d = 64`
- Commitment rank: `16`
- Fold decomposition base: `b = 2`
- Fold decomposition limbs: `k = 13`
- Fold norm ceiling:

  `B = b^k = 2^13 = 8192`

- Challenge set for ring-valued fold challenges:

  `C = {-1, 0, 1, 2}`

- Max supported recursive depth: `32`
- Fiat-Shamir challenge count: `16`
- Hachi variable count: `1024`
- Hachi batching width: `8`
- PiDEC interval: `1`
- Informational security estimates:
  - raw bits = `222`
  - composed bits = `174`

The algebraic tower is:

- `Fq`
- `Fq2 = Fq[u] / (u^2 - 3)`
- `Fq4 = Fq2[v] / (v^2 - u)`
- `Rq = Fq[X] / (X^64 + 1)`

The seal layer also has a separate direct-packed relation proof with its own decomposition parameters:

- direct-packed base = `2`
- direct-packed limbs = `64`

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
- `N(a + b*u) = a^2 - beta*b^2`
- `(a + b*u)^(-1) = conj(a + b*u) / N(a + b*u)`

### 3.2 Quartic tower Fq4

The quartic tower is

`Fq4 = Fq2[v] / (v^2 - eta)`

with deterministic certified choice

`eta = u = (0, 1) in Fq2`.

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
- `N(A + B*v) = A^2 - eta*B^2`
- `(A + B*v)^(-1) = conj(A + B*v) / N(A + B*v)`

The ring multiplication code scalar-extends into `Fq4`, multiplies there, and then requires projection back into the base subfield `Fq`.

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
- gate multisets `S1, ..., Ss`, each `Si subseteq [t]`
- coefficients `c1, ..., cs in Fq`
- witness/public assignment `z in Fq^n`

The satisfaction relation is:

`sum_i c_i * (circ_{j in S_i} (M_j * z)) = 0 in Fq^m`

where `circ` is the Hadamard product.

For row `r`, the row constraint is:

`sum_i c_i * prod_{j in S_i} (M_j z)[r] = 0`.

Sparse matrices are stored in CSR format, but the math is ordinary sparse matrix-vector multiplication:

`y = M * z`.

## 10. PiCCS: Strong CCS Reduction

PiCCS is the first folding stage. It reduces the `m` row constraints to a single multilinear sum-check claim.

Given a folded CCS instance, PiCCS samples

`tau in Fq^m`

from the transcript and forms a linearized table:

`gateSum[i] = sum_g c_g * prod_{j in S_g} (M_j z)[i]`

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

PiRLC is the second folding stage. It folds `k` running instances with ring-valued challenges.

Each challenge is a ring

`rho_i in Rq`

whose coefficients are independently drawn from

`C = {-1, 0, 1, 2}`.

The constant coefficient `rho_i[0]` is used as the scalar challenge for public-input and field-level folding.

Given inputs

`(C_i, w_i, x_i, y_i, u_i, e_i)`,

the repo computes:

- folded commitment:

  `C' = sum_i rho_i * C_i`

- folded witness:

  `w' = sum_i rho_i * w_i`

- folded public inputs:

  `x' = sum_i rho_i[0] * x_i`

- folded CCS evaluations:

  `y' = sum_i rho_i[0] * y_i`

- folded relaxation factor:

  `u' = sum_i rho_i[0] * u_i`

The implementation also forms cross terms against the first witness:

`T_j[l] = w_0[l] * w_j[l]`

for `j = 1, ..., k-1`.

These are committed with the same Ajtai commitment.

Folded error terms are computed as:

`e'[l] = sum_i rho_i * e_i[l] + sum_{j=1}^{k-1} rho_{j+1} * T_j[l]`

with missing entries treated as zero.

## 12. Norm Budget and PiDEC

Folding grows witness norms, so the repo keeps an explicit norm budget.

After a `k`-ary fold, the budget update rule is:

`currentNorm <- k * currentNorm + challengeMagnitude`

and the fold counter increments.

Decomposition is forced by a fixed cadence and also serves to re-normalize the witness.

### Decomposition

For a centered coefficient `c`, PiDEC decomposes it into signed base-`B` digits:

`c = c_0 + c_1 * B + c_2 * B^2 + ...`

with

`|c_l| < B`.

In the fold pipeline, `B = 2` and `k = 13`.

For a ring element, decomposition is done coefficientwise, producing `k` ring limbs.

### PiDEC commitment check

Let `L_l` be the commitment to the vector of all `l`-th limbs. PiDEC checks:

`sum_l B^l * L_l = original_commitment`

The verifier also checks that every output limb coefficient satisfies the centered bound `< B`.

## 13. Hachi PCS: General Path

The terminal seal layer uses a multilinear PCS with two modes.

For the general path:

1. The polynomial evaluation table is packed into ring chunks with the canonical 64-to-1 packing.
2. The packed table is committed with an Ajtai commitment.
3. A codeword is formed by repeating the base evaluation table with blowup factor `4`:

   `codeword[t] = base[t mod n]`

4. A Merkle tree is built over the codeword.

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

## 14. Hachi PCS: Direct-Packed Path

If the packed witness has chunk count in `{1, 2, 4}`, the repo switches to a direct-packed relation opening instead of the codeword/Merkle path.

### 14.1 Evaluation weights

For point `r in Fq^ell`, the multilinear equality weights are:

`eq_r(x) = prod_i ((1-r_i) if x_i = 0 else r_i)`

for all `x in {0,1}^ell`.

These weights are chunked into groups of 64 coefficients and then expanded across decomposition limbs:

`lambda_{chunk, limb} = B^limb * chunkWeights`

with `B = 2` in the direct-packed relation.

### 14.2 Short linear witness relation

For each packed witness chunk:

1. Decompose the packed chunk into `64` base-2 limb rings. This is the short witness.
2. Form an inner linear image with the direct-packed relation key.
3. Decompose that inner image into another `64` base-2 limb rings. These are the outer digits.
4. Commit those outer digits with the outer key.

The direct-packed proof simultaneously enforces four linear relations:

1. Binding relation:

   `bindingImage_i = <A_bind, shortWitness_i>`

2. Inner/outer consistency relation:

   `<A_rel, shortWitness_i> - sum_l B^l * outerDigits_{i,l} = 0`

3. Evaluation relation:

   `sum_{i,l} <shortWitness_{i,l}, lambda_{i,l}>_0 = claimedValue`

   where `<., .>_0` means "take the constant coefficient of the negacyclic product", implemented as

   `const( w * sigma(lambda) )`

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

- Gaussian mask rings are sampled with sigmas `4096` and `8192`
- response challenge is sampled from `{-1, 0, 1}`
- responses are accepted only if:
  - all centered coefficients stay below `2^16`
  - the rejection test accepts

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
  - centered base-`B` digit extraction for power-of-two `B`
- `NuSealKernels.metal`
  - repeated-table codeword extension
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
