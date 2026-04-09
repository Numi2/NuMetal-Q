import XCTest
@testable import NuMetal_Q

final class TranscriptVectorTests: XCTestCase {
    func testFieldTranscriptVectorsAreDeterministic() {
        var transcript = NuTranscriptField(domain: "NuMetalQ.Tests.TranscriptVectors")
        transcript.absorbLabel("fixture")
        transcript.absorb(field: Fq(42))
        transcript.absorb(ext: Fq2(a: Fq(7), b: Fq(9)))
        transcript.absorb(ring: AcceptanceSupport.randomRing(seed: 77, index: 3))

        let squeezed = transcript.squeezeChallenges(count: 4).map(\.v)
        let ext = transcript.squeezeExtChallenge()
        let blinding = transcript.squeezeBlinding(count: 16)

        XCTAssertEqual(
            squeezed,
            [6044888351207392749, 6597049127249598833, 2039659454611996154, 4798920443624416340]
        )
        XCTAssertEqual(ext, Fq2(a: Fq(3391207842536485456), b: Fq(15374075142347075555)))
        XCTAssertEqual(
            blinding,
            [40, 92, 33, 233, 213, 206, 61, 102, 145, 30, 143, 85, 236, 199, 196, 220]
        )
    }

    func testTypedChallengeSamplerVectorsAreDeterministic() {
        var transcript = NuTranscriptField(domain: "NuMetalQ.Tests.SamplerVectors")
        transcript.absorbLabel("fixture")
        transcript.absorb(field: Fq(99))

        let samplerField = NuSampler.challengeField(transcript: &transcript).v
        let samplerExt = NuSampler.challengeExt(transcript: &transcript)
        let samplerFields = NuSampler.challengeFields(count: 3, transcript: &transcript).map(\.v)
        let samplerRing = NuSampler.challengeRingFromC(transcript: &transcript).coeffs.map(\.v)

        XCTAssertEqual(samplerField, 15446093897906189397)
        XCTAssertEqual(samplerExt, Fq2(a: Fq(17981690620747196212), b: Fq(16026010498911519955)))
        XCTAssertEqual(
            samplerFields,
            [11619197948624726363, 14592031892912268078, 5845020736507791066]
        )
        XCTAssertEqual(
            samplerRing,
            [
                2, 18446744069414584288, 2, 0, 0, 0, 18446744069414584288, 18446744069414584288,
                0, 2, 2, 0, 2, 18446744069414584288, 0, 18446744069414584288,
                1, 0, 2, 1, 1, 2, 2, 0, 18446744069414584288, 18446744069414584288, 18446744069414584288, 2, 0, 2, 2, 0,
                1, 2, 1, 0, 18446744069414584288, 18446744069414584288, 18446744069414584288, 1, 1, 1, 0, 1, 0, 18446744069414584288, 0, 1,
                0, 18446744069414584288, 0, 1, 0, 18446744069414584288, 1, 2, 0, 2, 1, 0, 18446744069414584288, 1, 18446744069414584288, 1
            ]
        )
    }
}
