import Foundation
import XCTest
@testable import NuMetal_Q

final class SyncProtocolTests: XCTestCase {
    func testClassicalSyncRoundTripsEnvelopeWithStrictAttestation() async throws {
        let senderID = UUID()
        let recipientID = UUID()
        let sender = try makeChannel(localDeviceID: senderID)
        let recipient = try makeChannel(localDeviceID: recipientID)
        let compiledShape = try AcceptanceSupport.makeCompiledShape(name: "SyncRoundTrip")
        let unsignedEnvelope = try AcceptanceSupport.makeSyntheticEnvelope(compiledShape: compiledShape)
        let attestedEnvelope = try AcceptanceSupport.resignEnvelope(
            unsignedEnvelope,
            attestation: try syncAttestation(
                for: unsignedEnvelope,
                senderDeviceID: senderID,
                recipientDeviceID: recipientID
            )
        )

        let message = try await sender.seal(
            envelope: attestedEnvelope,
            recipientID: recipientID,
            kemCiphertext: Data("test-kem-ciphertext".utf8),
            sign: AcceptanceSupport.signer
        )
        let opened = try await recipient.openEnvelope(
            message: message,
            verifySignature: AcceptanceSupport.verifier
        )

        XCTAssertEqual(opened.serialize(), attestedEnvelope.serialize())
    }

    func testClassicalSyncRejectsAttestationBoundToDifferentRecipientBeforeSend() async throws {
        let senderID = UUID()
        let recipientID = UUID()
        let sender = try makeChannel(localDeviceID: senderID)
        let compiledShape = try AcceptanceSupport.makeCompiledShape(name: "SyncRecipientMismatch")
        let unsignedEnvelope = try AcceptanceSupport.makeSyntheticEnvelope(compiledShape: compiledShape)
        let attestedEnvelope = try AcceptanceSupport.resignEnvelope(
            unsignedEnvelope,
            attestation: try syncAttestation(
                for: unsignedEnvelope,
                senderDeviceID: senderID,
                recipientDeviceID: UUID()
            )
        )

        do {
            _ = try await sender.seal(
                envelope: attestedEnvelope,
                recipientID: recipientID,
                kemCiphertext: Data("test-kem-ciphertext".utf8),
                sign: AcceptanceSupport.signer
            )
            XCTFail("Expected sender-side attestation mismatch to be rejected")
        } catch let error as SyncError {
            XCTAssertEqual(error, .attestationInvalid)
        } catch {
            XCTFail("Unexpected error: \(error)")
        }
    }

    func testClassicalSyncRejectsReplayOfOpenedMessage() async throws {
        let senderID = UUID()
        let recipientID = UUID()
        let sender = try makeChannel(localDeviceID: senderID)
        let recipient = try makeChannel(localDeviceID: recipientID)
        let compiledShape = try AcceptanceSupport.makeCompiledShape(name: "SyncReplay")
        let unsignedEnvelope = try AcceptanceSupport.makeSyntheticEnvelope(compiledShape: compiledShape)
        let attestedEnvelope = try AcceptanceSupport.resignEnvelope(
            unsignedEnvelope,
            attestation: try syncAttestation(
                for: unsignedEnvelope,
                senderDeviceID: senderID,
                recipientDeviceID: recipientID
            )
        )

        let message = try await sender.seal(
            envelope: attestedEnvelope,
            recipientID: recipientID,
            kemCiphertext: Data("test-kem-ciphertext".utf8),
            sign: AcceptanceSupport.signer
        )
        _ = try await recipient.openEnvelope(
            message: message,
            verifySignature: AcceptanceSupport.verifier
        )

        do {
            _ = try await recipient.openEnvelope(
                message: message,
                verifySignature: AcceptanceSupport.verifier
            )
            XCTFail("Expected replayed sync message to be rejected")
        } catch let error as SyncError {
            XCTAssertEqual(error, .replayedMessage)
        } catch {
            XCTFail("Unexpected error: \(error)")
        }
    }

    private func makeChannel(localDeviceID: UUID) throws -> SyncChannel {
        try SyncChannel(
            localDeviceID: localDeviceID,
            hpkeSharedSecret: AcceptanceSupport.sharedSecret,
            salt: AcceptanceSupport.syncSalt,
            info: AcceptanceSupport.syncInfo,
            attestationVerifier: AcceptanceSupport.attestationVerifier,
            replayCacheDirectory: FileManager.default.temporaryDirectory
                .appendingPathComponent(UUID().uuidString, isDirectory: true)
        )
    }

    private func syncAttestation(
        for envelope: ProofEnvelope,
        senderDeviceID: UUID,
        recipientDeviceID: UUID
    ) throws -> Data {
        try AcceptanceSupport.makeAttestation(
            context: AttestationContext(
                purpose: .syncEnvelope,
                appID: envelope.appID,
                teamID: envelope.teamID,
                localDeviceID: senderDeviceID,
                remoteDeviceID: recipientDeviceID,
                shapeDigest: envelope.shapeDigest,
                signerKeyID: envelope.signerKeyID,
                timestamp: envelope.timestamp,
                payloadDigest: NuSecurityDigest.sha256(envelope.attestationBindingPayload())
            )
        )
    }
}
