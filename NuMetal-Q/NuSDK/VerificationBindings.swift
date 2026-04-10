import Foundation

package func publicHeaderMatchesShape(
    _ publicHeader: Data,
    shape: Shape
) -> Bool {
    guard shape.publicHeaderSize > 0 else {
        return publicHeader.isEmpty
    }
    return publicHeader.isEmpty == false
        && publicHeader.count.isMultiple(of: shape.publicHeaderSize)
}

package func envelopeMatchesNamespace(
    envelope: ProofEnvelope,
    expectedAppID: String,
    expectedTeamID: String
) -> VerificationFailure? {
    guard envelope.appID == expectedAppID else {
        return .appIDMismatch
    }
    guard envelope.teamID == expectedTeamID else {
        return .teamIDMismatch
    }
    return nil
}

package func keyedEnvelopeVerifier(
    expectedSignerKeyID: Data,
    verifySignature: @escaping PQVerifyClosure
) -> PQKeyedVerifyClosure {
    { message, signature, signerKeyID in
        guard signerKeyID == expectedSignerKeyID else {
            return false
        }
        return try verifySignature(message, signature)
    }
}
