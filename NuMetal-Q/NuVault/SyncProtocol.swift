import Foundation
import CryptoKit

// MARK: - Sync Protocol
// HPKE-encrypted, ML-DSA-signed proof sync between devices.
// Uses X-Wing / ML-KEM shared secrets for HPKE-style key derivation,
// AES-GCM-256 for payloads, and ML-DSA for message authentication.
// No sync format that isn't signed with ML-DSA and encrypted with HPKE + AES-GCM.

/// A sync message containing an encrypted proof envelope.
public struct SyncMessage: Sendable {
    /// Message identifier.
    public let messageID: UUID

    /// Sender device identifier.
    public let senderDeviceID: UUID

    /// Recipient device identifier.
    public let recipientDeviceID: UUID

    /// HPKE encapsulated key.
    public let encapsulatedKey: Data

    /// Encrypted payload (ProofEnvelope serialized + AES-GCM).
    public let ciphertext: Data

    /// AES-GCM nonce.
    public let nonce: Data

    /// AES-GCM tag.
    public let tag: Data

    /// ML-DSA signature over (messageID || sender || recipient || encapsulatedKey || ciphertext).
    public let signature: Data

    /// Timestamp.
    public let timestamp: Date

    public func signingPayload() -> Data {
        var payload = Data()
        payload.append(contentsOf: withUnsafeBytes(of: messageID.uuid) { Array($0) })
        payload.append(contentsOf: withUnsafeBytes(of: senderDeviceID.uuid) { Array($0) })
        payload.append(contentsOf: withUnsafeBytes(of: recipientDeviceID.uuid) { Array($0) })

        func appendLengthPrefixed(_ value: Data) {
            var count = UInt32(clamping: value.count)
            payload.append(contentsOf: withUnsafeBytes(of: &count) { Data($0) })
            payload.append(value)
        }

        appendLengthPrefixed(encapsulatedKey)
        appendLengthPrefixed(ciphertext)
        appendLengthPrefixed(nonce)
        appendLengthPrefixed(tag)
        var ts = timestamp.timeIntervalSince1970
        payload.append(contentsOf: withUnsafeBytes(of: &ts) { Data($0) })
        return payload
    }
}

/// Manages encrypted sync channels between NuMeQ devices.
public actor SyncChannel {
    private static let replayCacheLimit = 4_096
    private static let replayCacheWindow: TimeInterval = 60 * 60 * 24
    private static let maximumFutureSkew: TimeInterval = 60 * 5

    private let localDeviceID: UUID
    private let rootSharedSecret: Data
    private let salt: Data
    private let info: Data
    private let attestationVerifier: AttestationVerifier?
    private let replayCacheURL: URL
    private var openedMessages: [UUID: Date] = [:]

    /// Creates a channel from an HPKE / X-Wing shared secret (not raw passphrase material).
    public init(
        localDeviceID: UUID,
        hpkeSharedSecret: Data,
        salt: Data,
        info: Data,
        attestationVerifier: AttestationVerifier? = nil,
        replayCacheDirectory: URL? = nil
    ) throws {
        self.localDeviceID = localDeviceID
        self.rootSharedSecret = hpkeSharedSecret
        self.salt = salt
        self.info = info
        self.attestationVerifier = attestationVerifier
        self.replayCacheURL = try Self.resolveReplayCacheURL(
            localDeviceID: localDeviceID,
            replayCacheDirectory: replayCacheDirectory
        )
        self.openedMessages = try Self.loadReplayCache(from: replayCacheURL)
    }

    /// Encrypt a proof envelope for transmission to a peer.
    public func seal(
        envelope: ProofEnvelope,
        recipientID: UUID,
        kemCiphertext: Data,
        requireAttestation: Bool = true,
        sign: PQSignClosure
    ) throws -> SyncMessage {
        try validateClassicalChannelConfiguration(encapsulatedKey: kemCiphertext)
        if requireAttestation && envelope.attestation == nil {
            throw SyncError.attestationRequired
        }
        if requireAttestation {
            try verifyEnvelopeAttestation(
                envelope,
                remoteDeviceID: recipientID,
                purpose: .syncEnvelope
            )
        }
        let payload = envelope.serialize()
        let sessionKey = messageKey(encapsulatedKey: kemCiphertext)
        let nonce = AES.GCM.Nonce()
        let sealed = try AES.GCM.seal(payload, using: sessionKey, nonce: nonce)

        let messageID = UUID()
        let unsigned = SyncMessage(
            messageID: messageID,
            senderDeviceID: localDeviceID,
            recipientDeviceID: recipientID,
            encapsulatedKey: kemCiphertext,
            ciphertext: sealed.ciphertext,
            nonce: Data(nonce),
            tag: Data(sealed.tag),
            signature: Data(),
            timestamp: Date()
        )
        let sig = try sign(unsigned.signingPayload())

        return SyncMessage(
            messageID: unsigned.messageID,
            senderDeviceID: unsigned.senderDeviceID,
            recipientDeviceID: unsigned.recipientDeviceID,
            encapsulatedKey: unsigned.encapsulatedKey,
            ciphertext: unsigned.ciphertext,
            nonce: unsigned.nonce,
            tag: unsigned.tag,
            signature: sig,
            timestamp: unsigned.timestamp
        )
    }

    /// Encrypt a proof envelope with Apple HPKE using the X-Wing hybrid KEM.
    ///
    /// The returned `SyncMessage` stores the HPKE ciphertext in `ciphertext`
    /// and the sender's encapsulated key in `encapsulatedKey`. The legacy
    /// `nonce` and `tag` fields remain empty because HPKE owns the AEAD state.
    @available(iOS 26.0, macOS 26.0, watchOS 26.0, tvOS 26.0, macCatalyst 26.0, visionOS 26.0, *)
    public func sealUsingXWingHPKE(
        envelope: ProofEnvelope,
        recipientID: UUID,
        recipientPublicKey: XWingMLKEM768X25519.PublicKey,
        requireAttestation: Bool = true,
        sign: PQSignClosure
    ) throws -> SyncMessage {
        if requireAttestation && envelope.attestation == nil {
            throw SyncError.attestationRequired
        }
        if requireAttestation {
            try verifyEnvelopeAttestation(
                envelope,
                remoteDeviceID: recipientID,
                purpose: .syncEnvelope
            )
        }

        let messageID = UUID()
        let timestamp = Date()
        var sender = try HPKE.Sender(
            recipientKey: recipientPublicKey,
            ciphersuite: .XWingMLKEM768X25519_SHA256_AES_GCM_256,
            info: ApplePostQuantum.syncHPKEInfo
        )

        let aad = Self.hpkeAssociatedData(
            messageID: messageID,
            senderDeviceID: localDeviceID,
            recipientDeviceID: recipientID,
            encapsulatedKey: sender.encapsulatedKey,
            timestamp: timestamp
        )
        let ciphertext = try sender.seal(envelope.serialize(), authenticating: aad)

        let unsigned = SyncMessage(
            messageID: messageID,
            senderDeviceID: localDeviceID,
            recipientDeviceID: recipientID,
            encapsulatedKey: sender.encapsulatedKey,
            ciphertext: ciphertext,
            nonce: Data(),
            tag: Data(),
            signature: Data(),
            timestamp: timestamp
        )
        let signature = try sign(unsigned.signingPayload())

        return SyncMessage(
            messageID: unsigned.messageID,
            senderDeviceID: unsigned.senderDeviceID,
            recipientDeviceID: unsigned.recipientDeviceID,
            encapsulatedKey: unsigned.encapsulatedKey,
            ciphertext: unsigned.ciphertext,
            nonce: unsigned.nonce,
            tag: unsigned.tag,
            signature: signature,
            timestamp: unsigned.timestamp
        )
    }

    /// Decrypt a sync message from a peer.
    public func open(message: SyncMessage, verifySignature: PQVerifyClosure) throws -> Data {
        guard message.recipientDeviceID == localDeviceID else {
            throw SyncError.wrongRecipient
        }
        guard try verifySignature(message.signingPayload(), message.signature) else {
            throw SyncError.signatureInvalid
        }
        let now = Date()
        try validateClassicalChannelConfiguration(encapsulatedKey: message.encapsulatedKey)
        try validateTimestamp(message.timestamp, now: now)
        try rejectReplay(of: message, now: now)

        let opened: Data
        do {
            let box = try AES.GCM.SealedBox(
                nonce: AES.GCM.Nonce(data: message.nonce),
                ciphertext: message.ciphertext,
                tag: message.tag
            )
            let sessionKey = messageKey(encapsulatedKey: message.encapsulatedKey)
            opened = try AES.GCM.open(box, using: sessionKey)
        } catch {
            throw SyncError.decryptionFailed
        }
        try recordOpened(message.messageID, now: now)
        return opened
    }

    /// Decrypt an HPKE/X-Wing sync message from a peer.
    @available(iOS 26.0, macOS 26.0, watchOS 26.0, tvOS 26.0, macCatalyst 26.0, visionOS 26.0, *)
    public func openUsingXWingHPKE(
        message: SyncMessage,
        recipientPrivateKey: XWingMLKEM768X25519.PrivateKey,
        verifySignature: PQVerifyClosure
    ) throws -> Data {
        guard message.recipientDeviceID == localDeviceID else {
            throw SyncError.wrongRecipient
        }
        guard try verifySignature(message.signingPayload(), message.signature) else {
            throw SyncError.signatureInvalid
        }
        let now = Date()
        guard !message.encapsulatedKey.isEmpty else {
            throw SyncError.invalidEncapsulatedKey
        }
        try validateTimestamp(message.timestamp, now: now)
        try rejectReplay(of: message, now: now)

        let aad = Self.hpkeAssociatedData(
            messageID: message.messageID,
            senderDeviceID: message.senderDeviceID,
            recipientDeviceID: message.recipientDeviceID,
            encapsulatedKey: message.encapsulatedKey,
            timestamp: message.timestamp
        )
        var recipient = try HPKE.Recipient(
            privateKey: recipientPrivateKey,
            ciphersuite: .XWingMLKEM768X25519_SHA256_AES_GCM_256,
            info: ApplePostQuantum.syncHPKEInfo,
            encapsulatedKey: message.encapsulatedKey
        )
        let opened = try recipient.open(message.ciphertext, authenticating: aad)
        try recordOpened(message.messageID, now: now)
        return opened
    }

    /// Decrypt and deserialize a proof envelope from a peer, optionally enforcing attestation.
    public func openEnvelope(
        message: SyncMessage,
        verifySignature: PQVerifyClosure,
        requireAttestation: Bool = true
    ) throws -> ProofEnvelope {
        let payload = try open(message: message, verifySignature: verifySignature)
        let envelope = try ProofEnvelope.deserialize(payload)
        if requireAttestation && envelope.attestation == nil {
            throw SyncError.attestationRequired
        }
        if requireAttestation {
            try verifyEnvelopeAttestation(
                envelope,
                remoteDeviceID: message.senderDeviceID,
                purpose: .syncEnvelope
            )
        }
        return envelope
    }

    @available(iOS 26.0, macOS 26.0, watchOS 26.0, tvOS 26.0, macCatalyst 26.0, visionOS 26.0, *)
    public func openEnvelopeUsingXWingHPKE(
        message: SyncMessage,
        recipientPrivateKey: XWingMLKEM768X25519.PrivateKey,
        verifySignature: PQVerifyClosure,
        requireAttestation: Bool = true
    ) throws -> ProofEnvelope {
        let payload = try openUsingXWingHPKE(
            message: message,
            recipientPrivateKey: recipientPrivateKey,
            verifySignature: verifySignature
        )
        let envelope = try ProofEnvelope.deserialize(payload)
        if requireAttestation && envelope.attestation == nil {
            throw SyncError.attestationRequired
        }
        if requireAttestation {
            try verifyEnvelopeAttestation(
                envelope,
                remoteDeviceID: message.senderDeviceID,
                purpose: .syncEnvelope
            )
        }
        return envelope
    }

    private static func hpkeAssociatedData(
        messageID: UUID,
        senderDeviceID: UUID,
        recipientDeviceID: UUID,
        encapsulatedKey: Data,
        timestamp: Date
    ) -> Data {
        var data = Data()
        data.append(contentsOf: withUnsafeBytes(of: messageID.uuid) { Array($0) })
        data.append(contentsOf: withUnsafeBytes(of: senderDeviceID.uuid) { Array($0) })
        data.append(contentsOf: withUnsafeBytes(of: recipientDeviceID.uuid) { Array($0) })

        var encapsulatedCount = UInt32(clamping: encapsulatedKey.count)
        data.append(contentsOf: withUnsafeBytes(of: &encapsulatedCount) { Data($0) })
        data.append(encapsulatedKey)

        var ts = timestamp.timeIntervalSince1970
        data.append(contentsOf: withUnsafeBytes(of: &ts) { Data($0) })
        return data
    }

    private func messageKey(encapsulatedKey: Data) -> SymmetricKey {
        let kemBinding = Data(SHA256.hash(data: encapsulatedKey))
        var derivedSalt = salt
        derivedSalt.append(kemBinding)
        return NuPQKDF.deriveAEADKey(
            sharedSecret: rootSharedSecret,
            salt: derivedSalt,
            info: info
        )
    }

    private func validateClassicalChannelConfiguration(encapsulatedKey: Data) throws {
        guard !rootSharedSecret.isEmpty else {
            throw SyncError.invalidSharedSecret
        }
        guard !encapsulatedKey.isEmpty else {
            throw SyncError.invalidEncapsulatedKey
        }
    }

    private func validateTimestamp(_ timestamp: Date, now: Date) throws {
        let raw = timestamp.timeIntervalSince1970
        guard raw.isFinite else {
            throw SyncError.invalidTimestamp
        }
        guard timestamp <= now.addingTimeInterval(Self.maximumFutureSkew) else {
            throw SyncError.invalidTimestamp
        }
        guard timestamp >= now.addingTimeInterval(-Self.replayCacheWindow) else {
            throw SyncError.invalidTimestamp
        }
    }

    private func rejectReplay(of message: SyncMessage, now: Date) throws {
        pruneReplayCache(now: now)
        guard openedMessages[message.messageID] == nil else {
            throw SyncError.replayedMessage
        }
    }

    private func recordOpened(_ messageID: UUID, now: Date) throws {
        pruneReplayCache(now: now)
        openedMessages[messageID] = now
        try persistReplayCache()
    }

    private func pruneReplayCache(now: Date) {
        let cutoff = now.addingTimeInterval(-Self.replayCacheWindow)
        openedMessages = openedMessages.filter { _, seenAt in
            seenAt >= cutoff
        }
        guard openedMessages.count > Self.replayCacheLimit else {
            return
        }

        let overflow = openedMessages.count - Self.replayCacheLimit
        let oldest = openedMessages
            .sorted { lhs, rhs in lhs.value < rhs.value }
            .prefix(overflow)
        for entry in oldest {
            openedMessages.removeValue(forKey: entry.key)
        }
    }

    private func verifyEnvelopeAttestation(
        _ envelope: ProofEnvelope,
        remoteDeviceID: UUID,
        purpose: AttestationPurpose
    ) throws {
        guard let attestation = envelope.attestation, attestation.isEmpty == false else {
            throw SyncError.attestationRequired
        }
        guard let attestationVerifier else {
            throw SyncError.attestationVerifierMissing
        }
        let context = AttestationContext(
            purpose: purpose,
            appID: envelope.appID,
            teamID: envelope.teamID,
            localDeviceID: localDeviceID,
            remoteDeviceID: remoteDeviceID,
            shapeDigest: envelope.shapeDigest,
            signerKeyID: envelope.signerKeyID,
            timestamp: envelope.timestamp,
            payloadDigest: NuSecurityDigest.sha256(envelope.attestationBindingPayload())
        )
        guard try attestationVerifier(attestation, context) else {
            throw SyncError.attestationInvalid
        }
    }

    private func persistReplayCache() throws {
        let entries = openedMessages
            .sorted { lhs, rhs in lhs.value < rhs.value }
            .map { PersistedReplayEntry(messageID: $0.key, seenAt: $0.value) }
        let payload = PersistedReplayCache(entries: entries)
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys]
        do {
            let data = try encoder.encode(payload)
            try data.write(to: replayCacheURL, options: .atomic)
        } catch {
            throw SyncError.replayCachePersistenceFailed
        }
    }

    private static func resolveReplayCacheURL(
        localDeviceID: UUID,
        replayCacheDirectory: URL?
    ) throws -> URL {
        let directory: URL
        if let replayCacheDirectory {
            directory = replayCacheDirectory
        } else {
            guard let appSupport = FileManager.default.urls(
                for: .applicationSupportDirectory,
                in: .userDomainMask
            ).first else {
                throw SyncError.replayCachePersistenceFailed
            }
            directory = appSupport.appendingPathComponent("NuMeQ/SyncReplay", isDirectory: true)
        }
        do {
            try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        } catch {
            throw SyncError.replayCachePersistenceFailed
        }
        return directory.appendingPathComponent("\(localDeviceID.uuidString).json")
    }

    private static func loadReplayCache(from url: URL) throws -> [UUID: Date] {
        guard FileManager.default.fileExists(atPath: url.path) else {
            return [:]
        }
        do {
            let data = try Data(contentsOf: url)
            let payload = try JSONDecoder().decode(PersistedReplayCache.self, from: data)
            return Dictionary(uniqueKeysWithValues: payload.entries.map { ($0.messageID, $0.seenAt) })
        } catch {
            throw SyncError.replayCachePersistenceFailed
        }
    }
}

public enum SyncError: Error, Sendable, Equatable {
    case wrongRecipient
    case authenticationFailed
    case decryptionFailed
    case signatureInvalid
    case replayedMessage
    case channelClosed
    case attestationRequired
    case attestationVerifierMissing
    case attestationInvalid
    case invalidTimestamp
    case invalidEncapsulatedKey
    case invalidSharedSecret
    case replayCachePersistenceFailed
}

private struct PersistedReplayCache: Codable {
    let entries: [PersistedReplayEntry]
}

private struct PersistedReplayEntry: Codable {
    let messageID: UUID
    let seenAt: Date
}
