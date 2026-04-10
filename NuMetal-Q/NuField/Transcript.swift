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
// The proof core uses NuTranscriptField (cSHAKE256-backed field transcript) instead.

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
        let success = numeq_seal_cshake256(
            name,
            name.count,
            custom,
            custom.count,
            bytes,
            bytes.count,
            &out,
            out.count
        )
        precondition(success == 1, "NuSeal cSHAKE256 failed")
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

// MARK: - NuTranscriptField: cSHAKE256-Backed Field Transcript
// cSHAKE256 transcript for all proof-internal transcript operations.
// This is the ONLY transcript used inside the SuperNeo protocol stages.

/// Field-native transcript for proof protocol semantics.
///
/// Frames each absorbed value with an explicit type tag and derives challenges
/// from cSHAKE256 output reduced into Fq. This avoids relying on a custom
/// permutation for Fiat-Shamir while keeping the transcript API field-oriented.
public struct NuTranscriptField: Sendable {
    private static let fieldBytes = 16
    private static let squeezeBlockBytes = 32
    private static let functionName = Data("NuMeQ.TranscriptField".utf8)

    private let domain: String
    private var buffer: Data
    private var squeezeCounter: UInt64 = 0

    public init(domain: String) {
        self.domain = domain
        self.buffer = Data()
        appendFrame(tag: 0x00, payload: Data(domain.utf8))
    }

    // MARK: - Absorb

    public mutating func absorb(field: Fq) {
        appendFrame(tag: 0x01, payload: Data(field.toBytes()))
    }

    public mutating func absorb(ext: Fq2) {
        appendFrame(tag: 0x02, payload: Data(ext.toBytes()))
    }

    public mutating func absorb(ring: RingElement) {
        appendFrame(tag: 0x03, payload: Data(ring.toBytes()))
    }

    public mutating func absorbLabel(_ label: String) {
        appendFrame(tag: 0x04, payload: Data(label.utf8))
    }

    // MARK: - Squeeze

    public mutating func squeezeChallenge() -> Fq {
        let bytes = squeezeBytesInternal(label: "challenge.field", count: Self.fieldBytes)
        let lo = LittleEndianCodec.uint64(from: bytes.prefix(8))
        let hi = LittleEndianCodec.uint64(from: bytes.suffix(8))
        return Fq.reduceFull(hi: hi, lo: lo)
    }

    public mutating func squeezeExtChallenge() -> Fq2 {
        let a = squeezeChallenge()
        let b = squeezeChallenge()
        return Fq2(a: a, b: b)
    }

    public mutating func squeezeChallenges(count: Int) -> [Fq] {
        precondition(count >= 0)
        return (0..<count).map { _ in squeezeChallenge() }
    }

    public mutating func squeezeBlinding(count: Int) -> [UInt8] {
        squeezeBytesInternal(label: "challenge.blinding", count: count)
    }

    private mutating func appendFrame(tag: UInt8, payload: Data) {
        buffer.append(tag)
        var count = UInt32(clamping: payload.count).littleEndian
        buffer.append(contentsOf: withUnsafeBytes(of: &count) { Data($0) })
        buffer.append(payload)
    }

    private mutating func squeezeBytesInternal(label: String, count: Int) -> [UInt8] {
        precondition(count >= 0)
        var output = [UInt8]()
        output.reserveCapacity(count)
        var blockIndex: UInt32 = 0
        while output.count < count {
            let block = squeezeBlock(label: label, blockIndex: blockIndex)
            let take = min(block.count, count - output.count)
            output.append(contentsOf: block.prefix(take))
            blockIndex &+= 1
        }
        squeezeCounter &+= 1
        return output
    }

    private func squeezeBlock(label: String, blockIndex: UInt32) -> [UInt8] {
        var writer = BinaryWriter()
        writer.append(squeezeCounter)
        writer.append(blockIndex)
        writer.appendLengthPrefixed(Data(label.utf8))
        writer.appendLengthPrefixed(buffer)
        return NuSealCShake256.cshake256(
            data: writer.data,
            functionName: Self.functionName,
            customization: Data(domain.utf8),
            count: Self.squeezeBlockBytes
        )
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
