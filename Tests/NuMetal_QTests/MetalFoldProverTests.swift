import XCTest
@testable import NuMetal_Q

final class MetalFoldProverTests: XCTestCase {
    func testTypedSeedVerifyRoundTripsAcrossVault() async throws {
        let compiledShape = try AcceptanceSupport.makeCompiledShape(name: "MetalFoldProverShape")
        let vaultDirectory = FileManager.default.temporaryDirectory
            .appendingPathComponent(UUID().uuidString, isDirectory: true)
        let vaultKey = Data("NuMetalQ.Tests.MetalFoldProver.Vault".utf8)

        let prover = try await MetalFoldProver(
            vaultDirectory: vaultDirectory,
            vaultKeyMaterial: vaultKey
        )
        let step = TestFoldStep(compiledShape: compiledShape)

        let witness = AcceptanceSupport.makeWitness(seed: 11)
        let pcd = try await prover.seed(step, witness: witness)

        let valid = try await prover.verify(pcd)
        XCTAssertTrue(valid)

        let resumedProver = try await MetalFoldProver(
            vaultDirectory: vaultDirectory,
            vaultKeyMaterial: vaultKey
        )
        await resumedProver.register(step)
        let resumedValid = try await resumedProver.verify(pcd)
        XCTAssertTrue(resumedValid)
    }

    func testTypedFuseVerifyRoundTripsAcrossVault() async throws {
        let compiledShape = try AcceptanceSupport.makeCompiledShape(name: "MetalFoldProverFuse")
        let vaultDirectory = FileManager.default.temporaryDirectory
            .appendingPathComponent(UUID().uuidString, isDirectory: true)
        let prover = try await MetalFoldProver(
            vaultDirectory: vaultDirectory,
            vaultKeyMaterial: Data("NuMetalQ.Tests.MetalFoldProver.Fuse".utf8)
        )
        let step = TestFoldStep(compiledShape: compiledShape)

        let left = try await prover.seed(step, witness: AcceptanceSupport.makeWitness(seed: 11))
        let right = try await prover.seed(step, witness: AcceptanceSupport.makeWitness(seed: 29))
        let fused = try await prover.fuse(
            step,
            witness: AcceptanceSupport.makeWitness(seed: 47),
            left: left,
            right: right
        )

        let fusedValid = try await prover.verify(fused)
        XCTAssertTrue(fusedValid)

        let resumedProver = try await MetalFoldProver(
            vaultDirectory: vaultDirectory,
            vaultKeyMaterial: Data("NuMetalQ.Tests.MetalFoldProver.Fuse".utf8)
        )
        await resumedProver.register(step)
        let resumedValid = try await resumedProver.verify(fused)
        XCTAssertTrue(resumedValid)
    }
}

private struct TestHeader: NuHeader, Hashable {
    let shapeDigest: ShapeDigest
    let publicInputs: [Fq]

    var digestByte: UInt8 {
        UInt8(truncatingIfNeeded: publicInputs.first?.v ?? 0)
    }

    func toBytes() -> [UInt8] {
        publicInputs.flatMap { $0.toBytes() }
    }

    static func decode(
        bytes: [UInt8],
        publicInputs: [Fq],
        shapeDigest: ShapeDigest
    ) throws -> TestHeader {
        guard bytes == publicInputs.flatMap({ $0.toBytes() }), publicInputs.count == 2 else {
            throw TestHeaderError.invalidEncoding
        }
        return TestHeader(shapeDigest: shapeDigest, publicInputs: publicInputs)
    }
}

private struct TestFoldStep: NuStep {
    typealias Witness = NuWitness
    typealias Left = TestHeader
    typealias Right = TestHeader
    typealias Output = TestHeader

    let compiledShape: CompiledShape

    func seedHeader(loweredWitness: NuWitness) throws -> TestHeader {
        makeHeader(digestByte: Self.digestByte(for: loweredWitness))
    }

    func fuseHeader(
        loweredWitness: NuWitness,
        left: TestHeader,
        right: TestHeader
    ) throws -> TestHeader {
        makeHeader(
            digestByte: left.digestByte &+ right.digestByte &+ Self.digestByte(for: loweredWitness)
        )
    }

    func lowerWitness(_ witness: NuWitness) throws -> NuWitness {
        witness
    }

    private func makeHeader(digestByte: UInt8) -> TestHeader {
        TestHeader(
            shapeDigest: compiledShape.shape.digest,
            publicInputs: [
                Fq(UInt64(digestByte)),
                Fq(UInt64(digestByte) &* 3 &+ 1)
            ]
        )
    }

    private static func digestByte(for witness: NuWitness) -> UInt8 {
        let sum = witness.flatten().reduce(UInt64(0)) { partial, field in
            partial &+ field.v
        }
        return UInt8(truncatingIfNeeded: sum)
    }
}

private enum TestHeaderError: Error {
    case invalidEncoding
}
