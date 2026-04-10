import Foundation
import CryptoKit
#if canImport(Network)
import Network
#endif

// MARK: - NuCluster
// Paired iPhone/MacBook proving mode.
// iPhone owns secrets and witness acquisition.
// MacBook acts as local co-prover for wide folds and seal compression.
// HPKE-protected local channels and signed job fragments.

/// Role in a cluster proving session.
public enum ClusterRole: Sendable {
    case principal   // iPhone: owns secrets, witness, and final proof
    case coProver    // MacBook: executes delegated fold/seal work
}

/// State of a cluster session.
public enum ClusterState: Sendable {
    case discovering
    case handshaking
    case paired
    case proving
    case completed
    case failed(Error)

    var isActive: Bool {
        switch self {
        case .paired, .proving: return true
        default: return false
        }
    }
}

/// A cluster proving session between an iPhone (principal) and MacBook (co-prover).
public actor ClusterSession {
    private static let replayCacheLimit = 4_096
    private static let replayCacheWindow: TimeInterval = 60 * 60 * 24
    private static let maximumFutureSkew: TimeInterval = 60 * 5

    public let sessionID: UUID
    public let role: ClusterRole
    public private(set) var state: ClusterState = .discovering

    private let localDeviceID: UUID
    private var peerDeviceID: UUID?
    private var remoteSessionID: UUID?

    /// Session key derived from HPKE key exchange.
    private var sessionKey: SymmetricKey?

    /// ML-DSA signature over delegated job fragments.
    private let signFragment: PQSignClosure
    private let verifyPeerSignature: PQVerifyClosure
    private let attestationVerifier: AttestationVerifier?

    /// Pending job fragments awaiting results.
    private var pendingFragments: [UUID: JobFragment] = [:]

    /// Completed fragment results.
    private var completedResults: [UUID: FragmentResult] = [:]

    /// Signed fragment payloads already accepted for this session.
    private var processedFragmentPayloads: [UUID: Data] = [:]

    /// Fragments currently being executed to avoid duplicate work.
    private var inFlightFragmentPayloads: [UUID: Data] = [:]

    /// Durable fragment replay cache for this local role.
    private let replayCacheURL: URL
    private var processedFragments: [UUID: Date] = [:]

    /// Installed executor for delegated fold/seal/decomposition work.
    private var workExecutor: ClusterWorkExecutor?

    public init(
        role: ClusterRole,
        fragmentSigner: @escaping @Sendable (Data) throws -> Data,
        peerVerifier: @escaping PQVerifyClosure,
        attestationVerifier: AttestationVerifier? = nil,
        replayCacheDirectory: URL? = nil
    ) throws {
        self.sessionID = UUID()
        self.role = role
        self.localDeviceID = UUID()
        self.signFragment = fragmentSigner
        self.verifyPeerSignature = peerVerifier
        self.attestationVerifier = attestationVerifier
        self.replayCacheURL = try Self.resolveReplayCacheURL(
            role: role,
            replayCacheDirectory: replayCacheDirectory
        )
        self.processedFragments = try Self.loadReplayCache(from: replayCacheURL)
    }

    /// Stable device identifier for pairing and channel binding.
    public var deviceID: UUID { localDeviceID }

    /// Install delegated work handlers for a co-prover session.
    ///
    /// The session fails closed if it receives a fragment and no matching
    /// executor is installed for that fragment kind.
    public func installWorkExecutor(_ executor: ClusterWorkExecutor) throws {
        guard role == .coProver else { throw ClusterError.wrongRole }
        self.workExecutor = executor
    }

    // MARK: - Pairing

    /// Initiate pairing with a discovered peer.
    public func pair(peerDeviceID: UUID, sharedSecret: Data) throws {
        guard !sharedSecret.isEmpty else {
            throw ClusterError.invalidSharedSecret
        }
        self.peerDeviceID = peerDeviceID
        self.remoteSessionID = nil
        self.pendingFragments.removeAll()
        self.completedResults.removeAll()
        self.processedFragmentPayloads.removeAll()
        self.inFlightFragmentPayloads.removeAll()

        let orderedPeers = [localDeviceID, peerDeviceID].map(\.uuidString).sorted()
        let salt = Data("NuMeQ.Cluster.HPKE.v1".utf8)
        let info = Data(orderedPeers.joined(separator: "|").utf8)
        self.sessionKey = NuPQKDF.deriveAEADKey(
            sharedSecret: sharedSecret,
            salt: salt,
            info: info
        )

        self.state = .paired
    }

    // MARK: - Job Delegation (Principal → Co-Prover)

    /// Create a job fragment to delegate fold work to the co-prover.
    public func createFoldFragment(
        shapeDigest: ShapeDigest,
        delegation: DelegationPayload,
        foldArity: Int
    ) throws -> JobFragment {
        guard role == .principal else { throw ClusterError.wrongRole }
        guard state.isActive else { throw ClusterError.notPaired }
        guard !delegation.attestation.isEmpty else { throw ClusterError.attestationRequired }
        guard foldArity > 0 else { throw ClusterError.invalidFragment }

        let fragment = JobFragment(
            fragmentID: UUID(),
            sessionID: sessionID,
            kind: .fold(arity: foldArity),
            shapeDigest: shapeDigest,
            encryptedPayload: try encrypt(delegation.payload),
            laneClasses: delegation.laneClasses,
            confinedIndices: delegation.confinedIndices,
            attestation: delegation.attestation,
            timestamp: Date()
        )
        try verifyAttestation(fragment, purpose: .clusterDelegation)

        let signed = try sign(fragment)
        pendingFragments[fragment.fragmentID] = signed
        self.state = .proving
        return signed
    }

    /// Create a job fragment to delegate seal compression.
    ///
    /// - Parameter vaultEncryptedWorkPackage: Ciphertext produced by the vault or
    ///   another binding layer. **Never** pass raw `FoldState` serialization in cleartext.
    public func createSealFragment(
        shapeDigest: ShapeDigest,
        vaultEncryptedWorkPackage: Data,
        attestation: Data
    ) throws -> JobFragment {
        guard role == .principal else { throw ClusterError.wrongRole }
        guard state.isActive else { throw ClusterError.notPaired }
        guard !attestation.isEmpty else { throw ClusterError.attestationRequired }

        let fragment = JobFragment(
            fragmentID: UUID(),
            sessionID: sessionID,
            kind: .seal,
            shapeDigest: shapeDigest,
            encryptedPayload: try encrypt(vaultEncryptedWorkPackage),
            laneClasses: [:],
            confinedIndices: [],
            attestation: attestation,
            timestamp: Date()
        )
        try verifyAttestation(fragment, purpose: .clusterDelegation)

        let signed = try sign(fragment)
        pendingFragments[fragment.fragmentID] = signed
        self.state = .proving
        return signed
    }

    /// Create a job fragment to delegate decomposition work.
    public func createDecomposeFragment(
        shapeDigest: ShapeDigest,
        workPackage: Data,
        attestation: Data
    ) throws -> JobFragment {
        guard role == .principal else { throw ClusterError.wrongRole }
        guard state.isActive else { throw ClusterError.notPaired }
        guard !attestation.isEmpty else { throw ClusterError.attestationRequired }

        let fragment = JobFragment(
            fragmentID: UUID(),
            sessionID: sessionID,
            kind: .decompose,
            shapeDigest: shapeDigest,
            encryptedPayload: try encrypt(workPackage),
            laneClasses: [:],
            confinedIndices: [],
            attestation: attestation,
            timestamp: Date()
        )
        try verifyAttestation(fragment, purpose: .clusterDelegation)

        let signed = try sign(fragment)
        pendingFragments[fragment.fragmentID] = signed
        self.state = .proving
        return signed
    }

    // MARK: - Job Execution (Co-Prover side)

    /// Process a received job fragment (co-prover side).
    public func processFragment(_ fragment: JobFragment) async throws -> FragmentResult {
        guard role == .coProver else { throw ClusterError.wrongRole }
        guard state.isActive else { throw ClusterError.notPaired }
        try fragment.validateSecurityInvariants()
        let now = Date()
        try validateTimestamp(fragment.timestamp, now: now)
        let signingPayload = fragment.signingPayload()
        try verifySignatureIfNeeded(payload: signingPayload, signature: fragment.signature)
        try bindRemoteSessionIfNeeded(fragment.sessionID)
        guard let attestation = fragment.attestation, !attestation.isEmpty else {
            throw ClusterError.attestationRequired
        }
        _ = attestation
        try verifyAttestation(fragment, purpose: .clusterExecution)
        if let processedPayload = processedFragmentPayloads[fragment.fragmentID] {
            guard processedPayload == signingPayload,
                  let cachedResult = completedResults[fragment.fragmentID] else {
                throw ClusterError.replayedFragment
            }
            return cachedResult
        }
        if let inFlightPayload = inFlightFragmentPayloads[fragment.fragmentID] {
            guard inFlightPayload == signingPayload else {
                throw ClusterError.replayedFragment
            }
            throw ClusterError.replayedFragment
        }
        try rejectReplay(of: fragment, now: now)

        inFlightFragmentPayloads[fragment.fragmentID] = signingPayload

        state = .proving
        defer {
            inFlightFragmentPayloads.removeValue(forKey: fragment.fragmentID)
            state = .paired
        }

        let decrypted = try decrypt(fragment.encryptedPayload)
        let context = ClusterWorkContext(
            sessionID: fragment.sessionID,
            shapeDigest: fragment.shapeDigest,
            laneClasses: fragment.laneClasses,
            confinedIndices: fragment.confinedIndices,
            attestation: attestation
        )
        let processed = try await execute(fragment.kind, payload: decrypted, context: context)
        let result = FragmentResult(
            fragmentID: fragment.fragmentID,
            sessionID: fragment.sessionID,
            encryptedResult: try encrypt(processed),
            signature: nil,
            timestamp: Date()
        )

        let signed = try sign(result)
        try recordProcessed(fragment.fragmentID, now: now)
        processedFragmentPayloads[fragment.fragmentID] = signingPayload
        completedResults[fragment.fragmentID] = signed
        return signed
    }

    /// Receive a result from the co-prover (principal side).
    public func receiveResult(_ result: FragmentResult) throws -> Data {
        guard role == .principal else { throw ClusterError.wrongRole }
        try validateTimestamp(result.timestamp, now: Date())
        guard pendingFragments[result.fragmentID] != nil else {
            throw ClusterError.unknownFragment
        }
        guard result.sessionID == sessionID else {
            throw ClusterError.sessionExpired
        }
        try verifySignatureIfNeeded(payload: result.signingPayload(), signature: result.signature)

        let decrypted = try decrypt(result.encryptedResult)
        pendingFragments.removeValue(forKey: result.fragmentID)

        if pendingFragments.isEmpty {
            state = .paired
        } else {
            state = .proving
        }

        return decrypted
    }

    /// Round-trip a fragment through an external transport/processor and return
    /// the decrypted payload on the principal side.
    public func roundTrip(
        _ fragment: JobFragment,
        dispatch: @Sendable (JobFragment) async throws -> FragmentResult
    ) async throws -> Data {
        guard role == .principal else { throw ClusterError.wrongRole }
        let result = try await dispatch(fragment)
        return try receiveResult(result)
    }

    // MARK: - Encryption

    private func encrypt(_ data: Data) throws -> Data {
        guard let key = sessionKey else { throw ClusterError.notPaired }
        let nonce = AES.GCM.Nonce()
        let sealed = try AES.GCM.seal(data, using: key, nonce: nonce)
        return sealed.combined!
    }

    private func decrypt(_ data: Data) throws -> Data {
        guard let key = sessionKey else { throw ClusterError.notPaired }
        let box = try AES.GCM.SealedBox(combined: data)
        return try AES.GCM.open(box, using: key)
    }

    private func sign(_ fragment: JobFragment) throws -> JobFragment {
        try fragment.validateSecurityInvariants()
        let sig = try signFragment(fragment.signingPayload())

        return JobFragment(
            fragmentID: fragment.fragmentID,
            sessionID: fragment.sessionID,
            kind: fragment.kind,
            shapeDigest: fragment.shapeDigest,
            encryptedPayload: fragment.encryptedPayload,
            laneClasses: fragment.laneClasses,
            confinedIndices: fragment.confinedIndices,
            attestation: fragment.attestation,
            signature: sig,
            timestamp: fragment.timestamp
        )
    }

    private func sign(_ result: FragmentResult) throws -> FragmentResult {
        let sig = try signFragment(result.signingPayload())
        return FragmentResult(
            fragmentID: result.fragmentID,
            sessionID: result.sessionID,
            encryptedResult: result.encryptedResult,
            signature: sig,
            timestamp: result.timestamp
        )
    }

    private func verifySignatureIfNeeded(payload: Data, signature: Data?) throws {
        guard let signature, try verifyPeerSignature(payload, signature) else {
            throw ClusterError.signatureInvalid
        }
    }

    private func bindRemoteSessionIfNeeded(_ incomingSessionID: UUID) throws {
        if let remoteSessionID {
            guard remoteSessionID == incomingSessionID else {
                throw ClusterError.sessionExpired
            }
            return
        }
        remoteSessionID = incomingSessionID
    }

    private func execute(
        _ kind: FragmentKind,
        payload: Data,
        context: ClusterWorkContext
    ) async throws -> Data {
        guard let workExecutor else {
            throw ClusterError.executorUnavailable
        }

        switch kind {
        case .fold(let arity):
            guard let handler = workExecutor.fold else {
                throw ClusterError.executorUnavailable
            }
            return try await handler(payload, context, arity)
        case .seal:
            guard let handler = workExecutor.seal else {
                throw ClusterError.executorUnavailable
            }
            return try await handler(payload, context)
        case .decompose:
            guard let handler = workExecutor.decompose else {
                throw ClusterError.executorUnavailable
            }
            return try await handler(payload, context)
        }
    }

    private func verifyAttestation(
        _ fragment: JobFragment,
        purpose: AttestationPurpose
    ) throws {
        guard let attestation = fragment.attestation, attestation.isEmpty == false else {
            throw ClusterError.attestationRequired
        }
        guard let attestationVerifier else {
            throw ClusterError.attestationVerifierMissing
        }
        let context = AttestationContext(
            purpose: purpose,
            localDeviceID: localDeviceID,
            remoteDeviceID: peerDeviceID,
            sessionID: fragment.sessionID,
            shapeDigest: fragment.shapeDigest,
            timestamp: fragment.timestamp,
            payloadDigest: NuSecurityDigest.sha256(fragment.attestationBindingPayload())
        )
        guard try attestationVerifier(attestation, context) else {
            throw ClusterError.attestationInvalid
        }
    }

    private func validateTimestamp(_ timestamp: Date, now: Date) throws {
        let raw = timestamp.timeIntervalSince1970
        guard raw.isFinite else {
            throw ClusterError.invalidTimestamp
        }
        guard timestamp <= now.addingTimeInterval(Self.maximumFutureSkew) else {
            throw ClusterError.invalidTimestamp
        }
        guard timestamp >= now.addingTimeInterval(-Self.replayCacheWindow) else {
            throw ClusterError.invalidTimestamp
        }
    }

    private func rejectReplay(of fragment: JobFragment, now: Date) throws {
        pruneReplayCache(now: now)
        guard processedFragments[fragment.fragmentID] == nil else {
            throw ClusterError.replayedFragment
        }
    }

    private func recordProcessed(_ fragmentID: UUID, now: Date) throws {
        pruneReplayCache(now: now)
        processedFragments[fragmentID] = now
        try persistReplayCache()
    }

    private func pruneReplayCache(now: Date) {
        let cutoff = now.addingTimeInterval(-Self.replayCacheWindow)
        processedFragments = processedFragments.filter { _, seenAt in
            seenAt >= cutoff
        }
        guard processedFragments.count > Self.replayCacheLimit else {
            return
        }

        let overflow = processedFragments.count - Self.replayCacheLimit
        let oldest = processedFragments
            .sorted { lhs, rhs in lhs.value < rhs.value }
            .prefix(overflow)
        for entry in oldest {
            processedFragments.removeValue(forKey: entry.key)
        }
    }

    private func persistReplayCache() throws {
        let entries = processedFragments
            .sorted { lhs, rhs in lhs.value < rhs.value }
            .map { ClusterPersistedReplayEntry(fragmentID: $0.key, seenAt: $0.value) }
        let payload = ClusterPersistedReplayCache(entries: entries)
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys]
        do {
            let data = try encoder.encode(payload)
            try data.write(to: replayCacheURL, options: .atomic)
        } catch {
            throw ClusterError.replayCachePersistenceFailed
        }
    }

    private static func resolveReplayCacheURL(
        role: ClusterRole,
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
                throw ClusterError.replayCachePersistenceFailed
            }
            directory = appSupport.appendingPathComponent("NuMeQ/ClusterReplay", isDirectory: true)
        }
        do {
            try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        } catch {
            throw ClusterError.replayCachePersistenceFailed
        }

        let roleComponent: String
        switch role {
        case .principal:
            roleComponent = "principal"
        case .coProver:
            roleComponent = "co-prover"
        }
        return directory.appendingPathComponent("\(roleComponent).json")
    }

    private static func loadReplayCache(from url: URL) throws -> [UUID: Date] {
        guard FileManager.default.fileExists(atPath: url.path) else {
            return [:]
        }
        do {
            let data = try Data(contentsOf: url)
            let payload = try JSONDecoder().decode(ClusterPersistedReplayCache.self, from: data)
            return Dictionary(uniqueKeysWithValues: payload.entries.map { ($0.fragmentID, $0.seenAt) })
        } catch {
            throw ClusterError.replayCachePersistenceFailed
        }
    }
}

// MARK: - Job Fragment

/// A signed, encrypted work unit for cluster proving.
public struct JobFragment: Sendable {
    public let fragmentID: UUID
    public let sessionID: UUID
    public let kind: FragmentKind
    public let shapeDigest: ShapeDigest
    public let encryptedPayload: Data
    public let laneClasses: [String: WitnessClass]
    public let confinedIndices: [Int]
    public let attestation: Data?
    public var signature: Data?
    public let timestamp: Date

    public init(
        fragmentID: UUID,
        sessionID: UUID,
        kind: FragmentKind,
        shapeDigest: ShapeDigest,
        encryptedPayload: Data,
        laneClasses: [String: WitnessClass] = [:],
        confinedIndices: [Int] = [],
        attestation: Data? = nil,
        signature: Data? = nil,
        timestamp: Date
    ) {
        self.fragmentID = fragmentID
        self.sessionID = sessionID
        self.kind = kind
        self.shapeDigest = shapeDigest
        self.encryptedPayload = encryptedPayload
        self.laneClasses = laneClasses
        self.confinedIndices = confinedIndices
        self.attestation = attestation
        self.signature = signature
        self.timestamp = timestamp
    }

    public func signingPayload() -> Data {
        signingPayload(includeAttestation: true)
    }

    public func attestationBindingPayload() -> Data {
        signingPayload(includeAttestation: false)
    }

    private func signingPayload(includeAttestation: Bool) -> Data {
        var payload = Data()
        payload.append(contentsOf: withUnsafeBytes(of: fragmentID.uuid) { Array($0) })
        payload.append(contentsOf: withUnsafeBytes(of: sessionID.uuid) { Array($0) })
        payload.append(kindBytes())
        payload.append(contentsOf: shapeDigest.bytes)
        var laneCount = UInt32(clamping: laneClasses.count)
        payload.append(contentsOf: withUnsafeBytes(of: &laneCount) { Data($0) })
        for laneID in laneClasses.keys.sorted() {
            let laneIDData = Data(laneID.utf8)
            var laneIDLength = UInt16(clamping: laneIDData.count)
            payload.append(contentsOf: withUnsafeBytes(of: &laneIDLength) { Data($0) })
            payload.append(laneIDData)
            payload.append(laneClasses[laneID]!.rawValue)
        }
        var confinedCount = UInt32(clamping: confinedIndices.count)
        payload.append(contentsOf: withUnsafeBytes(of: &confinedCount) { Data($0) })
        for index in confinedIndices {
            var raw = Int64(index).littleEndian
            payload.append(contentsOf: withUnsafeBytes(of: &raw) { Data($0) })
        }
        var count = UInt32(clamping: encryptedPayload.count)
        payload.append(contentsOf: withUnsafeBytes(of: &count) { Data($0) })
        payload.append(encryptedPayload)
        if includeAttestation {
            if let attestation {
                var attestationCount = UInt32(clamping: attestation.count)
                payload.append(contentsOf: withUnsafeBytes(of: &attestationCount) { Data($0) })
                payload.append(attestation)
            } else {
                var attestationCount: UInt32 = 0
                payload.append(contentsOf: withUnsafeBytes(of: &attestationCount) { Data($0) })
            }
        }
        var ts = timestamp.timeIntervalSince1970
        payload.append(contentsOf: withUnsafeBytes(of: &ts) { Data($0) })
        return payload
    }

    private func kindBytes() -> Data {
        switch kind {
        case .fold(let arity):
            var value = Int64(arity).littleEndian
            return Data([0x01]) + withUnsafeBytes(of: &value) { Data($0) }
        case .seal:
            return Data([0x02])
        case .decompose:
            return Data([0x03])
        }
    }

    func validateSecurityInvariants() throws {
        if case .fold(let arity) = kind, arity <= 0 {
            throw ClusterError.invalidFragment
        }
        guard confinedIndices.allSatisfy({ $0 >= 0 }) else {
            throw ClusterError.invalidFragment
        }
        guard Set(confinedIndices).count == confinedIndices.count else {
            throw ClusterError.invalidFragment
        }
        let laneIDsAreEncodable = laneClasses.keys.allSatisfy { laneID in
            Data(laneID.utf8).count <= Int(UInt16.max)
        }
        guard laneIDsAreEncodable else {
            throw ClusterError.invalidFragment
        }
    }
}

/// Kind of cluster work to perform.
public enum FragmentKind: Sendable {
    case fold(arity: Int)
    case seal
    case decompose
}

/// Authenticated metadata passed to delegated co-prover handlers.
public struct ClusterWorkContext: Sendable {
    public let sessionID: UUID
    public let shapeDigest: ShapeDigest
    public let laneClasses: [String: WitnessClass]
    public let confinedIndices: [Int]
    public let attestation: Data

    public init(
        sessionID: UUID,
        shapeDigest: ShapeDigest,
        laneClasses: [String: WitnessClass],
        confinedIndices: [Int],
        attestation: Data
    ) {
        self.sessionID = sessionID
        self.shapeDigest = shapeDigest
        self.laneClasses = laneClasses
        self.confinedIndices = confinedIndices
        self.attestation = attestation
    }
}

/// Delegated cluster work handlers.
public struct ClusterWorkExecutor: Sendable {
    public typealias FoldHandler = @Sendable (Data, ClusterWorkContext, Int) async throws -> Data
    public typealias UnaryHandler = @Sendable (Data, ClusterWorkContext) async throws -> Data

    public let fold: FoldHandler?
    public let seal: UnaryHandler?
    public let decompose: UnaryHandler?

    public init(
        fold: FoldHandler? = nil,
        seal: UnaryHandler? = nil,
        decompose: UnaryHandler? = nil
    ) {
        self.fold = fold
        self.seal = seal
        self.decompose = decompose
    }
}

/// Result of a completed job fragment.
public struct FragmentResult: Sendable {
    public let fragmentID: UUID
    public let sessionID: UUID
    public let encryptedResult: Data
    public let signature: Data?
    public let timestamp: Date

    public func signingPayload() -> Data {
        var payload = Data()
        payload.append(contentsOf: withUnsafeBytes(of: fragmentID.uuid) { Array($0) })
        payload.append(contentsOf: withUnsafeBytes(of: sessionID.uuid) { Array($0) })
        var count = UInt32(clamping: encryptedResult.count)
        payload.append(contentsOf: withUnsafeBytes(of: &count) { Data($0) })
        payload.append(encryptedResult)
        var ts = timestamp.timeIntervalSince1970
        payload.append(contentsOf: withUnsafeBytes(of: &ts) { Data($0) })
        return payload
    }
}

public enum ClusterError: Error, Sendable {
    case wrongRole
    case notPaired
    case unknownFragment
    case signatureInvalid
    case invalidFragment
    case sessionExpired
    case attestationRequired
    case attestationVerifierMissing
    case attestationInvalid
    case executorUnavailable
    case invalidSharedSecret
    case invalidTimestamp
    case replayCachePersistenceFailed
    case replayedFragment
}

private struct ClusterPersistedReplayCache: Codable {
    let entries: [ClusterPersistedReplayEntry]
}

private struct ClusterPersistedReplayEntry: Codable {
    let fragmentID: UUID
    let seenAt: Date
}
