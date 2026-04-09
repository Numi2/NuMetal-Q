import Foundation
import XCTest
@testable import NuMetal_Q

final class MetalFoldProverTests: XCTestCase {
    func testTypedSeedVerifyRoundTripsAcrossVault() async throws {
        let compiledShape = try AcceptanceSupport.makeConstrainedCompiledShape(name: "MetalFoldProverShape")
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

        let isValid = try await prover.verify(pcd)
        XCTAssertTrue(isValid)

        let resumedProver = try await MetalFoldProver(
            vaultDirectory: vaultDirectory,
            vaultKeyMaterial: vaultKey
        )
        await resumedProver.register(step)
        let resumedIsValid = try await resumedProver.verify(pcd)
        XCTAssertTrue(resumedIsValid)
    }

    func testTypedVerifyFailsWithWrongVaultKeyAcrossRestart() async throws {
        let compiledShape = try AcceptanceSupport.makeConstrainedCompiledShape(name: "MetalFoldWrongKey")
        let vaultDirectory = FileManager.default.temporaryDirectory
            .appendingPathComponent(UUID().uuidString, isDirectory: true)
        let step = TestFoldStep(compiledShape: compiledShape)

        let prover = try await MetalFoldProver(
            vaultDirectory: vaultDirectory,
            vaultKeyMaterial: Data("NuMetalQ.Tests.MetalFoldProver.Right".utf8)
        )
        let pcd = try await prover.seed(step, witness: AcceptanceSupport.makeWitness(seed: 19))

        let wrongKeyProver = try await MetalFoldProver(
            vaultDirectory: vaultDirectory,
            vaultKeyMaterial: Data("NuMetalQ.Tests.MetalFoldProver.Wrong".utf8)
        )
        await wrongKeyProver.register(step)

        let isValid = try await wrongKeyProver.verify(pcd)
        XCTAssertFalse(isValid)
    }

    func testTypedVerifyFailsAfterVaultTamperingAcrossRestart() async throws {
        let compiledShape = try AcceptanceSupport.makeConstrainedCompiledShape(name: "MetalFoldTamper")
        let vaultDirectory = FileManager.default.temporaryDirectory
            .appendingPathComponent(UUID().uuidString, isDirectory: true)
        let vaultKey = Data("NuMetalQ.Tests.MetalFoldProver.Tamper".utf8)
        let step = TestFoldStep(compiledShape: compiledShape)

        let prover = try await MetalFoldProver(
            vaultDirectory: vaultDirectory,
            vaultKeyMaterial: vaultKey
        )
        let pcd = try await prover.seed(step, witness: AcceptanceSupport.makeWitness(seed: 23))

        let vaultURL = vaultDirectory.appendingPathComponent("\(pcd.chainID.uuidString).vault")
        var bytes = try Data(contentsOf: vaultURL)
        bytes[bytes.index(before: bytes.endIndex)] ^= 0x01
        try bytes.write(to: vaultURL, options: .atomic)

        let resumedProver = try await MetalFoldProver(
            vaultDirectory: vaultDirectory,
            vaultKeyMaterial: vaultKey
        )
        await resumedProver.register(step)

        let isValid = try await resumedProver.verify(pcd)
        XCTAssertFalse(isValid)
    }

    func testTypedVerifyFailsWithoutStepRegistrationAfterRestart() async throws {
        let compiledShape = try AcceptanceSupport.makeConstrainedCompiledShape(name: "MetalFoldMissingStep")
        let vaultDirectory = FileManager.default.temporaryDirectory
            .appendingPathComponent(UUID().uuidString, isDirectory: true)
        let vaultKey = Data("NuMetalQ.Tests.MetalFoldProver.MissingStep".utf8)
        let step = TestFoldStep(compiledShape: compiledShape)

        let prover = try await MetalFoldProver(
            vaultDirectory: vaultDirectory,
            vaultKeyMaterial: vaultKey
        )
        let pcd = try await prover.seed(step, witness: AcceptanceSupport.makeWitness(seed: 29))

        let resumedProver = try await MetalFoldProver(
            vaultDirectory: vaultDirectory,
            vaultKeyMaterial: vaultKey
        )
        await resumedProver.register(compiledShape)

        let isValid = try await resumedProver.verify(pcd)
        XCTAssertFalse(isValid)
    }

    func testTypedVerifyFailsForForgedHeaderOnExistingChain() async throws {
        let compiledShape = try AcceptanceSupport.makeConstrainedCompiledShape(name: "MetalFoldForgedHeader")
        let vaultDirectory = FileManager.default.temporaryDirectory
            .appendingPathComponent(UUID().uuidString, isDirectory: true)
        let prover = try await MetalFoldProver(
            vaultDirectory: vaultDirectory,
            vaultKeyMaterial: Data("NuMetalQ.Tests.MetalFoldProver.ForgedHeader".utf8)
        )
        let step = TestFoldStep(compiledShape: compiledShape)
        let pcd = try await prover.seed(step, witness: AcceptanceSupport.makeWitness(seed: 31))

        let forgedHeader = TestHeader(
            shapeDigest: pcd.header.shapeDigest,
            publicInputs: pcd.header.publicInputs.map { $0 + .one }
        )
        let forged = Pcd(
            chainID: pcd.chainID,
            header: forgedHeader,
            shapeDigest: pcd.shapeDigest
        )

        let isValid = try await prover.verify(forged)
        XCTAssertFalse(isValid)
    }

    func testTypedFuseRejectsForgedChildHeader() async throws {
        let compiledShape = try AcceptanceSupport.makeConstrainedCompiledShape(name: "MetalFoldForgedChild")
        let vaultDirectory = FileManager.default.temporaryDirectory
            .appendingPathComponent(UUID().uuidString, isDirectory: true)
        let prover = try await MetalFoldProver(
            vaultDirectory: vaultDirectory,
            vaultKeyMaterial: Data("NuMetalQ.Tests.MetalFoldProver.ForgedChild".utf8)
        )
        let step = TestFoldStep(compiledShape: compiledShape)
        let left = try await prover.seed(step, witness: AcceptanceSupport.makeWitness(seed: 37))
        let right = try await prover.seed(step, witness: AcceptanceSupport.makeWitness(seed: 41))

        let forgedLeft = Pcd(
            chainID: left.chainID,
            header: TestHeader(
                shapeDigest: left.header.shapeDigest,
                publicInputs: left.header.publicInputs.map { $0 + .one }
            ),
            shapeDigest: left.shapeDigest
        )

        do {
            _ = try await prover.fuse(
                step,
                witness: AcceptanceSupport.makeWitness(seed: 43),
                left: forgedLeft,
                right: right
            )
            XCTFail("Expected forged child header to be rejected during fuse")
        } catch let error as MetalFoldProverError {
            guard case .unsupportedStoredState = error else {
                return XCTFail("Unexpected prover error: \(error)")
            }
        }
    }
}

private struct TestHeader: NuHeader, Hashable {
    let shapeDigest: ShapeDigest
    let publicInputs: [Fq]

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
        makeHeader(firstPublicInput: loweredWitness.flatten()[0])
    }

    func fuseHeader(
        loweredWitness: NuWitness,
        left: TestHeader,
        right: TestHeader
    ) throws -> TestHeader {
        makeHeader(firstPublicInput: left.publicInputs[0] + right.publicInputs[0] + loweredWitness.flatten()[0])
    }

    func lowerWitness(_ witness: NuWitness) throws -> NuWitness {
        witness
    }

    private func makeHeader(firstPublicInput: Fq) -> TestHeader {
        TestHeader(
            shapeDigest: compiledShape.shape.digest,
            publicInputs: [firstPublicInput, firstPublicInput + Fq(1)]
        )
    }
}

private enum TestHeaderError: Error {
    case invalidEncoding
}
