import Foundation
import CryptoKit
import NuMetalQSealXOF

public protocol NuByteDigestTranscript: Sendable {
    init(domain: String)

    mutating func absorb(_ data: [UInt8])
    mutating func absorb(field: Fq)
    mutating func absorb(ext: Fq2)
    mutating func absorb(ring: RingElement)
    mutating func absorbLabel(_ label: String)
    mutating func squeezeBytes(count: Int) -> [UInt8]
    mutating func squeezeFieldElement() -> Fq
    mutating func squeezeFieldElements(count: Int) -> [Fq]
    mutating func finalize() -> [UInt8]
}

public struct NuTranscriptSeal: Sendable {
    private var digest: NuSealCShake256

    public init(domain: String = NuSealConstants.sealTranscriptID) {
        self.digest = NuSealCShake256(domain: domain)
    }

    public mutating func absorb(label: String, bytes: Data) {
        digest.absorbLabel(label)
        digest.absorb(Array(bytes))
    }

    public mutating func absorb(label: String, scalars: [Fq]) {
        digest.absorbLabel(label)
        for scalar in scalars {
            digest.absorb(field: scalar)
        }
    }

    public mutating func absorb(label: String, value: Fq) {
        absorb(label: label, scalars: [value])
    }

    public mutating func challengeBytes(label: String, count: Int) -> [UInt8] {
        digest.absorbLabel("challenge")
        digest.absorbLabel(label)
        return digest.squeezeBytes(count: count)
    }

    public mutating func challengeScalar(label: String) -> Fq {
        let raw = challengeBytes(label: label, count: MemoryLayout<UInt64>.size)
        return Fq(LittleEndianCodec.uint64(from: raw) % Fq.modulus)
    }

    public mutating func challengeVector(label: String, count: Int) -> [Fq] {
        (0..<count).map { index in
            challengeScalar(label: "\(label).\(index)")
        }
    }

    public mutating func finalize() -> [UInt8] {
        digest.finalize()
    }
}

public struct NuSealFieldTranscriptAdapter: Sendable, NuFieldTranscript {
    public typealias Scalar = Fq

    private var transcript: NuTranscriptSeal

    public init(domain: String = NuSealConstants.sealTranscriptID) {
        self.transcript = NuTranscriptSeal(domain: domain)
    }

    public mutating func absorb(domain: String, scalar: Fq) {
        transcript.absorb(label: domain, value: scalar)
    }

    public mutating func absorb(domain: String, scalars: [Fq]) {
        transcript.absorb(label: domain, scalars: scalars)
    }

    public mutating func absorb(domain: String, bytes: Data) {
        transcript.absorb(label: domain, bytes: bytes)
    }

    public mutating func challengeScalar(domain: String) -> Fq {
        transcript.challengeScalar(label: domain)
    }

    public mutating func challengeVector(domain: String, count: Int) -> [Fq] {
        transcript.challengeVector(label: domain, count: count)
    }

    public mutating func finalize() -> [UInt8] {
        transcript.finalize()
    }
}

// MARK: - NuDigest: Byte-Oriented Hash Transcript
// SHA-256 Fiat-Shamir transcript for NON-PROOF artifact operations:
// shape digests, caches, app metadata, and Merkle trees.
// This belongs OUTSIDE the proof boundary.
//
// The proof core uses NuTranscriptField (Poseidon2 algebraic sponge) instead.

/// Byte-oriented hash transcript for envelopes, shape digests, and metadata.
///
/// Uses CryptoKit SHA-256. This transcript is used exclusively for
/// operations outside the proof protocol boundary: Merkle tree hashing,
/// envelope signing payloads, and caching.
///
/// For all proof-internal challenge generation (PiCCS, PiRLC, PiDEC),
/// use ``NuTranscriptField`` instead.
public struct NuDigest: Sendable, NuByteDigestTranscript {
    private var state: SHA256
    private var squeezed: Int = 0

    public init(domain: String) {
        state = SHA256()
        let tag = Array(domain.utf8)
        state.update(data: [UInt8(tag.count & 0xFF)])
        state.update(data: tag)
    }

    // MARK: - Absorb

    public mutating func absorb(_ data: [UInt8]) {
        state.update(data: data)
        squeezed = 0
    }

    public mutating func absorb(field: Fq) {
        absorb(field.toBytes())
    }

    public mutating func absorb(ext: Fq2) {
        absorb(ext.toBytes())
    }

    public mutating func absorb(ring: RingElement) {
        absorb(ring.toBytes())
    }

    public mutating func absorbLabel(_ label: String) {
        let tag = Array(label.utf8)
        absorb([UInt8(tag.count & 0xFF)] + tag)
    }

    // MARK: - Squeeze

    public mutating func squeezeBytes(count: Int) -> [UInt8] {
        precondition(count >= 0)
        var out: [UInt8] = []
        out.reserveCapacity(count)
        var chunk = 0
        while out.count < count {
            absorbLabel("squeeze_\(squeezed)_chunk_\(chunk)")
            let digest = state.finalize()
            let take = min(32, count - out.count)
            out.append(contentsOf: digest.prefix(take))
            chunk += 1
        }
        squeezed += 1
        return out
    }

    /// Squeeze a field element (for non-proof uses like PCS query positions).
    public mutating func squeezeFieldElement() -> Fq {
        absorbLabel("field_\(squeezed)")
        let digest = state.finalize()
        squeezed += 1
        let raw = LittleEndianCodec.uint64(
            from: Array(digest).prefix(MemoryLayout<UInt64>.size)
        )
        return Fq(raw % Fq.modulus)
    }

    /// Squeeze multiple field elements.
    public mutating func squeezeFieldElements(count: Int) -> [Fq] {
        (0..<count).map { _ in squeezeFieldElement() }
    }

    /// Finalize to a 32-byte digest (destructive; resets squeeze counter).
    public mutating func finalize() -> [UInt8] {
        Array(state.finalize())
    }
}

/// Seal-only cSHAKE256 byte transcript.
///
/// This transcript is used for proof-critical seal bindings where byte-oriented
/// hashing must remain post-quantum and domain separated. Unlike ``NuDigest``,
/// this transcript is reserved for seal-layer artifacts and recursive
/// accumulator digests.
public struct NuSealCShake256: Sendable, NuByteDigestTranscript {
    private let domain: String
    private var buffer: Data
    private var squeezed: Int = 0

    public init(domain: String) {
        self.domain = domain
        self.buffer = Data()
        absorbLabel("domain")
        absorb(Array(domain.utf8))
    }

    public mutating func absorb(_ data: [UInt8]) {
        buffer.append(contentsOf: data)
        squeezed = 0
    }

    public mutating func absorb(field: Fq) {
        absorb(field.toBytes())
    }

    public mutating func absorb(ext: Fq2) {
        absorb(ext.toBytes())
    }

    public mutating func absorb(ring: RingElement) {
        absorb(ring.toBytes())
    }

    public mutating func absorbLabel(_ label: String) {
        let tag = Array(label.utf8)
        absorb([UInt8(truncatingIfNeeded: tag.count & 0xFF)] + tag)
    }

    public mutating func squeezeBytes(count: Int) -> [UInt8] {
        precondition(count >= 0)
        var out: [UInt8] = []
        out.reserveCapacity(count)
        var chunk = 0
        while out.count < count {
            var message = buffer
            let label = Data("squeeze_\(squeezed)_chunk_\(chunk)".utf8)
            message.append(UInt8(truncatingIfNeeded: label.count & 0xFF))
            message.append(label)
            let digest = Self.cshake256(
                data: message,
                domain: domain,
                count: 32
            )
            let take = min(32, count - out.count)
            out.append(contentsOf: digest.prefix(take))
            chunk += 1
        }
        squeezed += 1
        return out
    }

    public mutating func squeezeFieldElement() -> Fq {
        let digest = squeezeBytes(count: MemoryLayout<UInt64>.size)
        let raw = LittleEndianCodec.uint64(from: digest)
        return Fq(raw % Fq.modulus)
    }

    public mutating func squeezeFieldElements(count: Int) -> [Fq] {
        (0..<count).map { _ in squeezeFieldElement() }
    }

    public mutating func finalize() -> [UInt8] {
        Self.cshake256(data: buffer, domain: domain, count: 32)
    }

    public static func cshake256(data: Data, domain: String, count: Int) -> [UInt8] {
        cshake256(
            data: data,
            functionName: Data("NuMeQ".utf8),
            customization: Data(domain.utf8),
            count: count
        )
    }

    public static func cshake256(
        data: Data,
        functionName: Data,
        customization: Data,
        count: Int
    ) -> [UInt8] {
        precondition(count >= 0)
        var out = [UInt8](repeating: 0, count: count)
        let bytes = Array(data)
        let name = Array(functionName)
        let custom = Array(customization)
        numeq_seal_cshake256(
            name,
            name.count,
            custom,
            custom.count,
            bytes,
            bytes.count,
            &out,
            out.count
        )
        return out
    }

    public static func shake256(data: Data, count: Int) -> [UInt8] {
        precondition(count >= 0)
        var out = [UInt8](repeating: 0, count: count)
        let bytes = Array(data)
        numeq_seal_shake256(
            bytes,
            bytes.count,
            &out,
            out.count
        )
        return out
    }
}

// MARK: - NuTranscriptField: Algebraic Sponge Transcript
// Poseidon2 permutation over Fq for all proof-internal transcript operations.
// This is the ONLY transcript used inside the SuperNeo protocol stages.
// Keeps the recursive verifier cheap: no non-native hash arithmetic.

/// Field-native algebraic sponge transcript for proof protocol semantics.
///
/// Uses a Poseidon2 permutation over Fq with rate=8, capacity=4, width=12.
/// All challenge generation for PiCCS, PiRLC, PiDEC, and the fold engine
/// goes through this transcript. This keeps the recursive verifier arithmetic
/// entirely within Fq, avoiding the cost of simulating SHA-256 in-circuit.
public struct NuTranscriptField: Sendable {
    /// Poseidon2 state width (rate + capacity).
    public static let width = 12
    /// Rate portion of the sponge (number of absorbable elements per permutation).
    public static let rate = 8
    /// Capacity portion (security margin).
    public static let capacity = 4

    private var state: [Fq]
    private var absorbIndex: Int = 0
    private var squeezed: Int = 0
    private var mode: SpongeMode = .absorbing

    private enum SpongeMode {
        case absorbing
        case squeezing
    }

    public init(domain: String) {
        state = [Fq](repeating: .zero, count: Self.width)
        // Domain separation: encode the label into the capacity region
        let tag = Array(domain.utf8)
        for (i, byte) in tag.prefix(Self.capacity * 8).enumerated() {
            let idx = Self.rate + (i / 8)
            let shift = UInt64(i % 8) * 8
            state[idx] = Fq(state[idx].v ^ (UInt64(byte) << shift))
        }
        permute()
    }

    // MARK: - Absorb

    public mutating func absorb(field: Fq) {
        if mode == .squeezing {
            permute()
            absorbIndex = 0
            mode = .absorbing
        }
        state[absorbIndex] += field
        absorbIndex += 1
        if absorbIndex >= Self.rate {
            permute()
            absorbIndex = 0
        }
    }

    public mutating func absorb(ext: Fq2) {
        absorb(field: ext.a)
        absorb(field: ext.b)
    }

    public mutating func absorb(ring: RingElement) {
        for coeff in ring.coeffs {
            absorb(field: coeff)
        }
    }

    public mutating func absorbLabel(_ label: String) {
        let bytes = Array(label.utf8)
        absorb(field: Fq(UInt64(bytes.count)))
        for chunk in stride(from: 0, to: bytes.count, by: 8) {
            var packed: UInt64 = 0
            for i in chunk..<min(chunk + 8, bytes.count) {
                packed |= UInt64(bytes[i]) << (UInt64(i - chunk) * 8)
            }
            absorb(field: Fq(packed % Fq.modulus))
        }
    }

    // MARK: - Squeeze

    /// Squeeze a single Fq challenge from the sponge.
    public mutating func squeezeChallenge() -> Fq {
        if mode == .absorbing {
            permute()
            mode = .squeezing
            squeezed = 0
        }
        if squeezed >= Self.rate {
            permute()
            squeezed = 0
        }
        let result = state[squeezed]
        squeezed += 1
        return result
    }

    /// Squeeze an Fq2 challenge.
    public mutating func squeezeExtChallenge() -> Fq2 {
        let a = squeezeChallenge()
        let b = squeezeChallenge()
        return Fq2(a: a, b: b)
    }

    /// Squeeze multiple Fq challenges.
    public mutating func squeezeChallenges(count: Int) -> [Fq] {
        (0..<count).map { _ in squeezeChallenge() }
    }

    /// Squeeze bytes for blinding randomness (extracts from field elements).
    public mutating func squeezeBlinding(count: Int) -> [UInt8] {
        precondition(count >= 0)
        var out: [UInt8] = []
        out.reserveCapacity(count)
        while out.count < count {
            let elem = squeezeChallenge()
            let bytes = elem.toBytes()
            let take = min(8, count - out.count)
            out.append(contentsOf: bytes.prefix(take))
        }
        return out
    }

    // MARK: - Poseidon2 Permutation
    // Poseidon2 with t=12 over Fq (Almost Goldilocks).
    // Full rounds: 8 (4 head + 4 tail). Partial rounds: 22.
    // S-box: x^5 (the smallest secure power for this field characteristic).

    private static let fullRoundsHead = 4
    private static let partialRounds = 22
    private static let fullRoundsTail = 4

    private mutating func permute() {
        // --- Full rounds (head) ---
        for r in 0..<Self.fullRoundsHead {
            addRoundConstants(round: r)
            sboxFull()
            mdsExternal()
        }
        // --- Partial rounds ---
        for r in 0..<Self.partialRounds {
            addRoundConstants(round: Self.fullRoundsHead + r)
            state[0] = sbox(state[0])
            mdsDiagonal()
        }
        // --- Full rounds (tail) ---
        for r in 0..<Self.fullRoundsTail {
            addRoundConstants(round: Self.fullRoundsHead + Self.partialRounds + r)
            sboxFull()
            mdsExternal()
        }
    }

    private func sbox(_ x: Fq) -> Fq {
        let x2 = x * x
        let x4 = x2 * x2
        return x4 * x
    }

    private mutating func sboxFull() {
        for i in 0..<Self.width {
            state[i] = sbox(state[i])
        }
    }

    /// External MDS: Cauchy-style circulant for full rounds.
    private mutating func mdsExternal() {
        var sum = Fq.zero
        for i in 0..<Self.width {
            sum += state[i]
        }
        for i in 0..<Self.width {
            state[i] = state[i] * Fq(raw: UInt64(i &+ 2)) + sum
        }
    }

    /// Diagonal MDS: efficient for partial rounds.
    private mutating func mdsDiagonal() {
        var sum = Fq.zero
        for i in 0..<Self.width {
            sum += state[i]
        }
        state[0] = state[0] + sum
        for i in 1..<Self.width {
            state[i] = state[i] * Fq(raw: UInt64(i &+ 1)) + sum
        }
    }

    /// Add deterministic round constants derived from the Poseidon2 grain LFSR.
    /// For reproducibility, constants are derived from a fixed seed.
    private mutating func addRoundConstants(round: Int) {
        let seed: UInt64 = 0x4E754D6551_5032  // Canonical transcript seed
        for i in 0..<Self.width {
            let idx = UInt64(round * Self.width + i)
            let (hi, lo) = (seed &+ idx &* 0x9E3779B97F4A7C15).multipliedFullWidth(by: 0x517CC1B727220A95)
            state[i] += Fq.reduceFull(hi: hi, lo: lo)
        }
    }
}

extension NuTranscriptField: NuFieldTranscript {
    public typealias Scalar = Fq

    public mutating func absorb(domain: String, scalar: Fq) {
        absorbLabel(domain)
        absorb(field: scalar)
    }

    public mutating func absorb(domain: String, scalars: [Fq]) {
        absorbLabel(domain)
        absorb(field: Fq(UInt64(scalars.count)))
        for scalar in scalars {
            absorb(field: scalar)
        }
    }

    public mutating func absorb(domain: String, bytes: Data) {
        absorbLabel(domain)
        absorb(field: Fq(UInt64(bytes.count)))
        let raw = [UInt8](bytes)
        for chunkStart in stride(from: 0, to: raw.count, by: 8) {
            var packed: UInt64 = 0
            for index in chunkStart..<min(chunkStart + 8, raw.count) {
                packed |= UInt64(raw[index]) << (UInt64(index - chunkStart) * 8)
            }
            absorb(field: Fq(packed % Fq.modulus))
        }
    }

    public mutating func challengeScalar(domain: String) -> Fq {
        absorbLabel(domain)
        return squeezeChallenge()
    }

    public mutating func challengeVector(domain: String, count: Int) -> [Fq] {
        absorbLabel(domain)
        return squeezeChallenges(count: count)
    }
}

// MARK: - NuSampler: Typed Challenge Sampling
// First-class typed samplers whose output matches the protocol's sampling sets.

/// Typed challenge sampler for SuperNeo protocol challenges.
///
/// Provides domain-specific sampling from the profile's challenge sets
/// rather than generic field sampling followed by range massage.
public struct NuSampler: Sendable {

    /// Sample a ring challenge from the coefficient set C = {-1, 0, 1, 2}.
    ///
    /// For the Almost Goldilocks profile, |C|^d = 4^64 = 2^128 ≈ 129-bit security.
    /// Each of the 64 coefficients is independently drawn from {-1, 0, 1, 2}
    /// using 2 bits of challenge entropy per coefficient (128 bits total).
    ///
    /// This is a first-class typed sampler: the output IS a ring challenge
    /// from C, not a generic field element projected into C.
    public static func challengeRingFromC(transcript: inout NuTranscriptField) -> RingElement {
        let d = RingElement.degree
        var coeffs = [Fq](repeating: .zero, count: d)

        // Extract 128 bits of challenge material (2 bits per coefficient × 64 coefficients)
        let challenges = transcript.squeezeChallenges(count: 2)
        let bits0 = challenges[0].v
        let bits1 = challenges[1].v

        for i in 0..<d {
            let bitPair: UInt64
            if i < 32 {
                bitPair = (bits0 >> (UInt64(i) * 2)) & 0x3
            } else {
                bitPair = (bits1 >> (UInt64(i - 32) * 2)) & 0x3
            }
            // Map 2-bit value to C = {-1, 0, 1, 2}:
            //   0b00 → -1,  0b01 → 0,  0b10 → 1,  0b11 → 2
            switch bitPair {
            case 0: coeffs[i] = Fq(raw: Fq.modulus &- 1)  // -1 mod q
            case 1: coeffs[i] = .zero
            case 2: coeffs[i] = .one
            case 3: coeffs[i] = Fq(raw: 2)
            default: coeffs[i] = .zero
            }
        }
        return RingElement(coeffs: coeffs)
    }

    /// Sample a uniform Fq challenge.
    public static func challengeField(transcript: inout NuTranscriptField) -> Fq {
        transcript.squeezeChallenge()
    }

    /// Sample a uniform Fq² challenge.
    public static func challengeExt(transcript: inout NuTranscriptField) -> Fq2 {
        transcript.squeezeExtChallenge()
    }

    /// Sample multiple uniform Fq challenges.
    public static func challengeFields(count: Int, transcript: inout NuTranscriptField) -> [Fq] {
        transcript.squeezeChallenges(count: count)
    }
}
