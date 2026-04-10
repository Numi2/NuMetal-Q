import XCTest
@testable import NuMetal_Q

final class TranscriptVectorTests: XCTestCase {
    func testFieldTranscriptDomainSeparationAndAbsorbOrderMatter() {
        func makeBaselineTranscript(domain: String) -> NuTranscriptField {
            var transcript = NuTranscriptField(domain: domain)
            transcript.absorbLabel("fixture")
            transcript.absorb(field: Fq(42))
            transcript.absorb(ext: Fq2(a: Fq(7), b: Fq(9)))
            transcript.absorb(ring: AcceptanceSupport.randomRing(seed: 77, index: 3))
            return transcript
        }

        let baselineDomain = "TranscriptBehavior.Alpha"
        var baselineA = makeBaselineTranscript(domain: baselineDomain)
        var baselineB = makeBaselineTranscript(domain: baselineDomain)
        let baselineChallenges = baselineA.squeezeChallenges(count: 4)

        XCTAssertEqual(baselineB.squeezeChallenges(count: 4), baselineChallenges)

        var differentDomain = makeBaselineTranscript(domain: "TranscriptBehavior.Omega")
        XCTAssertNotEqual(differentDomain.squeezeChallenges(count: 4), baselineChallenges)

        var differentOrder = NuTranscriptField(domain: baselineDomain)
        differentOrder.absorbLabel("fixture")
        differentOrder.absorb(ext: Fq2(a: Fq(7), b: Fq(9)))
        differentOrder.absorb(field: Fq(42))
        differentOrder.absorb(ring: AcceptanceSupport.randomRing(seed: 77, index: 3))
        XCTAssertNotEqual(differentOrder.squeezeChallenges(count: 4), baselineChallenges)
    }

    func testFieldTranscriptSequentialSqueezeMatchesBulkSqueeze() {
        func makeTranscript() -> NuTranscriptField {
            var transcript = NuTranscriptField(domain: "NuMetalQ.Tests.TranscriptSequential")
            transcript.absorbLabel("fixture")
            transcript.absorb(field: Fq(99))
            transcript.absorb(ext: Fq2(a: Fq(5), b: Fq(8)))
            return transcript
        }

        var bulk = makeTranscript()
        let bulkChallenges = bulk.squeezeChallenges(count: 5)

        var sequential = makeTranscript()
        let sequentialChallenges = (0..<5).map { _ in sequential.squeezeChallenge() }

        XCTAssertEqual(sequentialChallenges, bulkChallenges)
    }

    func testFieldTranscriptVectorsAreDeterministic() {
        var transcript = NuTranscriptField(domain: "NuMetalQ.Tests.TranscriptVectors")
        transcript.absorbLabel("fixture")
        transcript.absorb(field: Fq(42))
        transcript.absorb(ext: Fq2(a: Fq(7), b: Fq(9)))
        transcript.absorb(ring: AcceptanceSupport.randomRing(seed: 77, index: 3))

        let squeezed = transcript.squeezeChallenges(count: 4).map(\.v)
        let ext = transcript.squeezeExtChallenge()
        let blinding = transcript.squeezeBlinding(count: 16)
        let operations: [TranscriptReference.Operation] = [
            .label("fixture"),
            .field(Fq(42)),
            .ext(Fq2(a: Fq(7), b: Fq(9))),
            .ring(AcceptanceSupport.randomRing(seed: 77, index: 3)),
        ]
        var reference = TranscriptReference(
            domain: "NuMetalQ.Tests.TranscriptVectors",
            operations: operations
        )

        XCTAssertEqual(squeezed, reference.squeezeChallenges(count: 4).map(\.v))
        XCTAssertEqual(ext, reference.squeezeExtChallenge())
        XCTAssertEqual(blinding, reference.squeezeBlinding(count: 16))
    }

    func testTypedChallengeSamplerVectorsAreDeterministic() {
        var transcript = NuTranscriptField(domain: "NuMetalQ.Tests.SamplerVectors")
        transcript.absorbLabel("fixture")
        transcript.absorb(field: Fq(99))

        let samplerField = NuSampler.challengeField(transcript: &transcript).v
        let samplerExt = NuSampler.challengeExt(transcript: &transcript)
        let samplerFields = NuSampler.challengeFields(count: 3, transcript: &transcript).map(\.v)
        let samplerRing = NuSampler.challengeRingFromC(transcript: &transcript).coeffs.map(\.v)
        var reference = TranscriptReference(
            domain: "NuMetalQ.Tests.SamplerVectors",
            operations: [
                .label("fixture"),
                .field(Fq(99)),
            ]
        )

        XCTAssertEqual(samplerField, reference.squeezeChallenge().v)
        XCTAssertEqual(samplerExt, reference.squeezeExtChallenge())
        XCTAssertEqual(samplerFields, reference.squeezeChallenges(count: 3).map(\.v))
        XCTAssertEqual(samplerRing, reference.challengeRingFromC().coeffs.map(\.v))
    }
}

private struct TranscriptReference {
    enum Operation {
        case field(Fq)
        case ext(Fq2)
        case ring(RingElement)
        case label(String)
    }

    private static let functionName = Data("NuMeQ.TranscriptField".utf8)
    private static let squeezeBlockBytes = 32

    private let domain: String
    private let buffer: Data
    private var squeezeCounter: UInt64 = 0

    init(domain: String, operations: [Operation]) {
        self.domain = domain
        var buffer = Data()
        Self.appendFrame(tag: 0x00, payload: Data(domain.utf8), into: &buffer)
        for operation in operations {
            switch operation {
            case .field(let value):
                Self.appendFrame(tag: 0x01, payload: Data(value.toBytes()), into: &buffer)
            case .ext(let value):
                Self.appendFrame(tag: 0x02, payload: Data(value.toBytes()), into: &buffer)
            case .ring(let value):
                Self.appendFrame(tag: 0x03, payload: Data(value.toBytes()), into: &buffer)
            case .label(let value):
                Self.appendFrame(tag: 0x04, payload: Data(value.utf8), into: &buffer)
            }
        }
        self.buffer = buffer
    }

    mutating func squeezeChallenge() -> Fq {
        let bytes = squeezeBytes(label: "challenge.field", count: 16)
        let lo = LittleEndianCodec.uint64(from: bytes.prefix(8))
        let hi = LittleEndianCodec.uint64(from: bytes.suffix(8))
        return Fq.reduceFull(hi: hi, lo: lo)
    }

    mutating func squeezeExtChallenge() -> Fq2 {
        Fq2(a: squeezeChallenge(), b: squeezeChallenge())
    }

    mutating func squeezeChallenges(count: Int) -> [Fq] {
        (0..<count).map { _ in squeezeChallenge() }
    }

    mutating func squeezeBlinding(count: Int) -> [UInt8] {
        squeezeBytes(label: "challenge.blinding", count: count)
    }

    mutating func challengeRingFromC() -> RingElement {
        let challenges = squeezeChallenges(count: 2)
        let bits0 = challenges[0].v
        let bits1 = challenges[1].v
        let coeffs = (0..<RingElement.degree).map { index -> Fq in
            let pair: UInt64
            if index < 32 {
                pair = (bits0 >> (UInt64(index) * 2)) & 0x3
            } else {
                pair = (bits1 >> (UInt64(index - 32) * 2)) & 0x3
            }
            switch pair {
            case 0:
                return Fq(raw: Fq.modulus &- 1)
            case 1:
                return .zero
            case 2:
                return .one
            case 3:
                return Fq(raw: 2)
            default:
                return .zero
            }
        }
        return RingElement(coeffs: coeffs)
    }

    private mutating func squeezeBytes(label: String, count: Int) -> [UInt8] {
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

    private static func appendFrame(tag: UInt8, payload: Data, into buffer: inout Data) {
        buffer.append(tag)
        var count = UInt32(clamping: payload.count).littleEndian
        buffer.append(contentsOf: withUnsafeBytes(of: &count) { Data($0) })
        buffer.append(payload)
    }
}
