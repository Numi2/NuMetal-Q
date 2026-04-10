import Foundation
import CryptoKit

// MARK: - Fold Vault
// Encrypted storage for FoldState objects.
// FoldState is NEVER persisted unencrypted.
// Uses Secure Enclave MLKEM1024 to wrap vault keys,
// AES-GCM-256 for artifact encryption, HKDF for key derivation.

/// Encrypted, on-device vault for FoldState persistence.
///
/// All FoldState objects are encrypted at rest using AES-GCM-256.
/// The vault master key is wrapped by a Secure Enclave key.
/// No raw FoldState is ever written to disk or exported.
public actor FoldVault {
    /// Vault master key (unwrapped in memory, never persisted in cleartext).
    private var masterKey: SymmetricKey?

    /// Storage directory for encrypted vault files.
    private let storageURL: URL

    /// In-memory cache of decrypted states (cleared on lock).
    private var cache: [UUID: FoldState] = [:]

    public init(storageDirectory: URL? = nil) {
        if let dir = storageDirectory {
            self.storageURL = dir
        } else {
            let appSupport = FileManager.default.urls(
                for: .applicationSupportDirectory,
                in: .userDomainMask
            ).first!
            self.storageURL = appSupport.appendingPathComponent("NuMeQ/FoldVault", isDirectory: true)
        }
    }

    // MARK: - Vault Lifecycle

    /// Unlock the vault by deriving the master key.
    /// In production, this key comes from Secure Enclave MLKEM1024 unwrapping.
    public func unlock(with keyMaterial: Data) throws {
        guard !keyMaterial.isEmpty else {
            throw VaultError.invalidKeyMaterial
        }
        let salt = "NuMeQ.FoldVault.v1".data(using: .utf8)!
        let derived = HKDF<SHA256>.deriveKey(
            inputKeyMaterial: SymmetricKey(data: keyMaterial),
            salt: salt,
            info: Data(),
            outputByteCount: 32
        )
        try activateMasterKey(derived)
    }

    @available(iOS 26.0, macOS 26.0, watchOS 26.0, tvOS 26.0, macCatalyst 26.0, visionOS 26.0, *)
    public func unlock(
        wrappedMasterKey: Data,
        using privateKey: MLKEM1024.PrivateKey
    ) throws {
        let wrapped = try WrappedArtifactKey.deserialize(wrappedMasterKey)
        let unwrapped = try ApplePostQuantum.unwrapSessionKey(wrapped, using: privateKey)
        try activateMasterKey(unwrapped)
    }

    @available(iOS 26.0, macOS 26.0, watchOS 26.0, tvOS 26.0, macCatalyst 26.0, visionOS 26.0, *)
    public func unlock(
        wrappedMasterKey: Data,
        using privateKey: SecureEnclave.MLKEM1024.PrivateKey
    ) throws {
        let wrapped = try WrappedArtifactKey.deserialize(wrappedMasterKey)
        let unwrapped = try ApplePostQuantum.unwrapSessionKey(wrapped, using: privateKey)
        try activateMasterKey(unwrapped)
    }

    /// Lock the vault: clear all in-memory state.
    public func lock() {
        masterKey = nil
        cache.removeAll()
    }

    public var isUnlocked: Bool { masterKey != nil }

    private func activateMasterKey(_ key: SymmetricKey) throws {
        self.masterKey = key
        try FileManager.default.createDirectory(at: storageURL, withIntermediateDirectories: true)
    }

    // MARK: - Store / Retrieve

    /// Encrypt and persist a FoldState.
    internal func store(_ state: FoldState) throws {
        guard let key = masterKey else {
            throw VaultError.locked
        }

        let serialized = try serializeState(state)
        let nonce = AES.GCM.Nonce()
        let sealed = try AES.GCM.seal(
            serialized,
            using: key,
            nonce: nonce,
            authenticating: vaultAssociatedData(for: state.chainID)
        )

        let fileURL = storageURL.appendingPathComponent("\(state.chainID.uuidString).vault")
        try sealed.combined!.write(to: fileURL)

        cache[state.chainID] = state
    }

    /// Retrieve and decrypt a FoldState by chain ID.
    internal func retrieve(chainID: UUID) throws -> FoldState {
        if let cached = cache[chainID] { return cached }

        guard let key = masterKey else {
            throw VaultError.locked
        }

        let fileURL = storageURL.appendingPathComponent("\(chainID.uuidString).vault")
        let data = try Data(contentsOf: fileURL)
        let decrypted = try decryptVaultEntry(data, using: key, chainID: chainID)

        let state = try deserializeState(decrypted)
        guard state.chainID == chainID else {
            throw VaultError.corruptedData
        }
        cache[chainID] = state
        return state
    }

    /// Delete a vault entry.
    public func delete(chainID: UUID) throws {
        let fileURL = storageURL.appendingPathComponent("\(chainID.uuidString).vault")
        do {
            try FileManager.default.removeItem(at: fileURL)
        } catch let error as NSError
            where error.domain == NSCocoaErrorDomain && error.code == NSFileNoSuchFileError {
            // Missing files are already effectively deleted.
        }
        cache.removeValue(forKey: chainID)
    }

    /// List all stored chain IDs.
    public func listChains() throws -> [UUID] {
        let files = try FileManager.default.contentsOfDirectory(
            at: storageURL,
            includingPropertiesForKeys: nil
        )
        return files.compactMap { url -> UUID? in
            let name = url.deletingPathExtension().lastPathComponent
            return UUID(uuidString: name)
        }
    }

    // MARK: - Serialization

    private static let vaultHeader = Data("NuMeQFv6".utf8)

    private func vaultAssociatedData(for chainID: UUID) -> Data {
        var data = Data("NuMeQ.FoldVault.Entry.v1".utf8)
        data.append(contentsOf: withUnsafeBytes(of: chainID.uuid) { Array($0) })
        return data
    }

    private func decryptVaultEntry(
        _ data: Data,
        using key: SymmetricKey,
        chainID: UUID
    ) throws -> Data {
        let box: AES.GCM.SealedBox
        do {
            box = try AES.GCM.SealedBox(combined: data)
        } catch {
            throw VaultError.corruptedData
        }

        if let opened = try? AES.GCM.open(
            box,
            using: key,
            authenticating: vaultAssociatedData(for: chainID)
        ) {
            return opened
        }
        throw VaultError.corruptedData
    }

    private static func readFixedWidthInteger<T: FixedWidthInteger>(
        from data: Data,
        offset: inout Int,
        as type: T.Type
    ) throws -> T {
        let count = MemoryLayout<T>.size
        guard offset + count <= data.count else {
            throw VaultError.corruptedData
        }
        var value: T = 0
        withUnsafeMutableBytes(of: &value) { buffer in
            buffer.copyBytes(from: data[offset..<offset + count])
        }
        offset += count
        return T(littleEndian: value)
    }

    private static func readUUID(from data: Data, offset: inout Int) throws -> UUID {
        guard offset + 16 <= data.count else {
            throw VaultError.corruptedData
        }
        let bytes = Array(data[offset..<offset + 16])
        offset += 16
        return UUID(uuid: (
            bytes[0], bytes[1], bytes[2], bytes[3],
            bytes[4], bytes[5], bytes[6], bytes[7],
            bytes[8], bytes[9], bytes[10], bytes[11],
            bytes[12], bytes[13], bytes[14], bytes[15]
        ))
    }

    private func serializeState(_ state: FoldState) throws -> Data {
        var data = Data()
        data.append(Self.vaultHeader)

        // Chain ID
        data.append(contentsOf: withUnsafeBytes(of: state.chainID.uuid) { Array($0) })

        // Epoch
        var epoch = state.epoch
        data.append(contentsOf: withUnsafeBytes(of: &epoch) { Data($0) })

        // Shape digest
        data.append(contentsOf: state.shapeDigest.bytes)

        // Commitment
        data.append(contentsOf: state.commitment.value.toBytes())

        // Accumulated witness count + data
        let persistedWitness = state.kind == .recursiveAccumulator ? [RingElement]() : state.accumulatedWitness
        var witnessCount = UInt32(persistedWitness.count)
        data.append(contentsOf: withUnsafeBytes(of: &witnessCount) { Data($0) })
        for ring in persistedWitness {
            data.append(contentsOf: ring.toBytes())
        }

        // Public inputs
        var piCount = UInt32(state.publicInputs.count)
        data.append(contentsOf: withUnsafeBytes(of: &piCount) { Data($0) })
        for pi in state.publicInputs {
            data.append(contentsOf: pi.toBytes())
        }

        // Recursive state mode
        data.append(state.kind.rawValue)

        // Logical statement count
        var statementCount = state.statementCount
        data.append(contentsOf: withUnsafeBytes(of: &statementCount) { Data($0) })

        // Relaxation factor
        data.append(contentsOf: state.relaxationFactor.toBytes())

        // Norm budget
        var nbBound = state.normBudget.bound
        data.append(contentsOf: withUnsafeBytes(of: &nbBound) { Data($0) })
        var nbCurrent = state.normBudget.currentNorm
        data.append(contentsOf: withUnsafeBytes(of: &nbCurrent) { Data($0) })
        var nbFolds = state.normBudget.foldsSinceDecomp
        data.append(contentsOf: withUnsafeBytes(of: &nbFolds) { Data($0) })
        data.append(state.normBudget.decompBase)
        data.append(state.normBudget.decompLimbs)

        // Error terms
        var errCount = UInt32(state.errorTerms.count)
        data.append(contentsOf: withUnsafeBytes(of: &errCount) { Data($0) })
        for ring in state.errorTerms {
            data.append(contentsOf: ring.toBytes())
        }

        // Blinding mask
        data.append(contentsOf: state.blindingMask.toBytes())

        // Provenance
        data.append(state.maxWitnessClass.rawValue)

        // Optional typed trace payload
        let typedTraceData = try serializeTypedTrace(state.typedTrace)
        var typedTraceLength = UInt32(typedTraceData.count)
        data.append(contentsOf: withUnsafeBytes(of: &typedTraceLength) { Data($0) })
        data.append(typedTraceData)

        // Optional recursive accumulator payload
        let recursiveAccumulatorData = try serializeRecursiveAccumulator(state.recursiveAccumulator)
        var recursiveAccumulatorLength = UInt32(recursiveAccumulatorData.count)
        data.append(contentsOf: withUnsafeBytes(of: &recursiveAccumulatorLength) { Data($0) })
        data.append(recursiveAccumulatorData)

        // Stage audit trail
        var stageCount = UInt32(state.stageAudit.count)
        data.append(contentsOf: withUnsafeBytes(of: &stageCount) { Data($0) })
        for record in state.stageAudit {
            var epoch = record.epoch
            data.append(contentsOf: withUnsafeBytes(of: &epoch) { Data($0) })
            data.append(record.stage.rawValue)
            data.append(record.arity)
            var relationConstraintCount = record.relationConstraintCount
            data.append(contentsOf: withUnsafeBytes(of: &relationConstraintCount) { Data($0) })
            var witnessRingCount = record.witnessRingCount
            data.append(contentsOf: withUnsafeBytes(of: &witnessRingCount) { Data($0) })
            var normBefore = record.normBefore
            data.append(contentsOf: withUnsafeBytes(of: &normBefore) { Data($0) })
            var normAfter = record.normAfter
            data.append(contentsOf: withUnsafeBytes(of: &normAfter) { Data($0) })
        }

        return data
    }

    private func deserializeState(_ data: Data) throws -> FoldState {
        if data.starts(with: Self.vaultHeader) {
            return try deserializeCurrentState(data.dropFirst(Self.vaultHeader.count))
        }
        throw VaultError.corruptedData
    }

    private func deserializeCurrentState(_ data: Data.SubSequence) throws -> FoldState {
        let slice = Data(data)
        guard slice.count >= 16 + 8 + 32 + RingElement.degree * 8 else {
            throw VaultError.corruptedData
        }

        var offset = 0

        let chainID = try Self.readUUID(from: slice, offset: &offset)
        let epoch = try Self.readFixedWidthInteger(from: slice, offset: &offset, as: UInt64.self)

        let digestBytes = Array(slice[offset..<offset + 32])
        offset += 32
        let digest = ShapeDigest(bytes: digestBytes)

        let commitBytes = Array(slice[offset..<offset + RingElement.degree * 8])
        offset += RingElement.degree * 8
        guard let commitRing = RingElement.fromBytes(commitBytes) else {
            throw VaultError.corruptedData
        }
        let commitment = AjtaiCommitment(value: commitRing)

        let witnessCount = try Self.readFixedWidthInteger(from: slice, offset: &offset, as: UInt32.self)
        var witness = [RingElement]()
        for _ in 0..<witnessCount {
            guard offset + RingElement.degree * 8 <= slice.count else {
                throw VaultError.corruptedData
            }
            let ringBytes = Array(slice[offset..<offset + RingElement.degree * 8])
            offset += RingElement.degree * 8
            guard let ring = RingElement.fromBytes(ringBytes) else {
                throw VaultError.corruptedData
            }
            witness.append(ring)
        }

        let piCount = try Self.readFixedWidthInteger(from: slice, offset: &offset, as: UInt32.self)
        var publicInputs = [Fq]()
        for _ in 0..<piCount {
            guard offset + 8 <= slice.count else { throw VaultError.corruptedData }
            let fqBytes = Array(slice[offset..<offset + 8])
            offset += 8
            guard let fq = Fq.fromBytes(fqBytes) else { throw VaultError.corruptedData }
            publicInputs.append(fq)
        }

        guard offset + 1 <= slice.count else { throw VaultError.corruptedData }
        guard let kind = FoldStateKind(rawValue: slice[offset]) else {
            throw VaultError.corruptedData
        }
        offset += 1

        let statementCount = try Self.readFixedWidthInteger(
            from: slice,
            offset: &offset,
            as: UInt32.self
        )
        guard statementCount > 0 else {
            throw VaultError.corruptedData
        }

        guard offset + 8 <= slice.count else { throw VaultError.corruptedData }
        let relaxBytes = Array(slice[offset..<offset + 8])
        offset += 8
        guard let relaxation = Fq.fromBytes(relaxBytes) else {
            throw VaultError.corruptedData
        }

        guard offset + 8 + 8 + 4 + 1 + 1 <= slice.count else { throw VaultError.corruptedData }
        let nbBound = try Self.readFixedWidthInteger(from: slice, offset: &offset, as: UInt64.self)
        let nbCurrent = try Self.readFixedWidthInteger(from: slice, offset: &offset, as: UInt64.self)
        let nbFolds = try Self.readFixedWidthInteger(from: slice, offset: &offset, as: UInt32.self)
        let decompBase = slice[offset]
        offset += 1
        let decompLimbs = slice[offset]
        offset += 1

        var normBudget = NormBudget(bound: nbBound, decompBase: decompBase, decompLimbs: decompLimbs)
        normBudget.currentNorm = nbCurrent
        normBudget.foldsSinceDecomp = nbFolds

        let errCount = try Self.readFixedWidthInteger(from: slice, offset: &offset, as: UInt32.self)
        var errorTerms = [RingElement]()
        for _ in 0..<errCount {
            guard offset + RingElement.degree * 8 <= slice.count else {
                throw VaultError.corruptedData
            }
            let ringBytes = Array(slice[offset..<offset + RingElement.degree * 8])
            offset += RingElement.degree * 8
            guard let ring = RingElement.fromBytes(ringBytes) else {
                throw VaultError.corruptedData
            }
            errorTerms.append(ring)
        }

        guard offset + RingElement.degree * 8 <= slice.count else { throw VaultError.corruptedData }
        let blindBytes = Array(slice[offset..<offset + RingElement.degree * 8])
        offset += RingElement.degree * 8
        guard let blindingMask = RingElement.fromBytes(blindBytes) else {
            throw VaultError.corruptedData
        }

        guard offset + 1 <= slice.count,
              let witnessClass = WitnessClass(rawValue: slice[offset]) else {
            throw VaultError.corruptedData
        }
        offset += 1

        let typedTraceLength = try Self.readFixedWidthInteger(from: slice, offset: &offset, as: UInt32.self)
        guard offset + Int(typedTraceLength) <= slice.count else {
            throw VaultError.corruptedData
        }
        let typedTraceData = Data(slice[offset..<offset + Int(typedTraceLength)])
        offset += Int(typedTraceLength)
        let typedTrace = try deserializeTypedTrace(typedTraceData)

        let recursiveAccumulatorLength = try Self.readFixedWidthInteger(
            from: slice,
            offset: &offset,
            as: UInt32.self
        )
        guard offset + Int(recursiveAccumulatorLength) <= slice.count else {
            throw VaultError.corruptedData
        }
        let recursiveAccumulatorData = Data(
            slice[offset..<offset + Int(recursiveAccumulatorLength)]
        )
        offset += Int(recursiveAccumulatorLength)
        let recursiveAccumulator = try deserializeRecursiveAccumulator(recursiveAccumulatorData)

        let stageCount = try Self.readFixedWidthInteger(from: slice, offset: &offset, as: UInt32.self)
        var stageAudit = [FoldStageRecord]()
        stageAudit.reserveCapacity(Int(stageCount))
        for _ in 0..<stageCount {
            let recordEpoch = try Self.readFixedWidthInteger(from: slice, offset: &offset, as: UInt64.self)
            guard offset + 2 <= slice.count else { throw VaultError.corruptedData }
            guard let stage = FoldStageKind(rawValue: slice[offset]) else {
                throw VaultError.corruptedData
            }
            offset += 1
            let arity = slice[offset]
            offset += 1
            let relationConstraintCount = try Self.readFixedWidthInteger(
                from: slice,
                offset: &offset,
                as: UInt32.self
            )
            let witnessRingCount = try Self.readFixedWidthInteger(
                from: slice,
                offset: &offset,
                as: UInt32.self
            )
            let normBefore = try Self.readFixedWidthInteger(from: slice, offset: &offset, as: UInt64.self)
            let normAfter = try Self.readFixedWidthInteger(from: slice, offset: &offset, as: UInt64.self)
            stageAudit.append(
                FoldStageRecord(
                    epoch: recordEpoch,
                    stage: stage,
                    arity: arity,
                    relationConstraintCount: relationConstraintCount,
                    witnessRingCount: witnessRingCount,
                    normBefore: normBefore,
                    normAfter: normAfter
                )
            )
        }

        guard offset == slice.count else { throw VaultError.corruptedData }

        if kind == .typedTrace, typedTrace == nil {
            throw VaultError.corruptedData
        }
        if kind == .aggregateStatements, typedTrace != nil {
            throw VaultError.corruptedData
        }
        if kind == .aggregateStatements, recursiveAccumulator != nil {
            throw VaultError.corruptedData
        }
        if kind == .recursiveAccumulator, recursiveAccumulator == nil {
            throw VaultError.corruptedData
        }
        if kind == .recursiveAccumulator, witness.isEmpty == false {
            throw VaultError.corruptedData
        }
        if kind == .typedTrace, recursiveAccumulator != nil {
            throw VaultError.corruptedData
        }

        return FoldState(
            kind: kind,
            chainID: chainID,
            epoch: epoch,
            shapeDigest: digest,
            commitment: commitment,
            accumulatedWitness: witness,
            publicInputs: publicInputs,
            statementCount: statementCount,
            normBudget: normBudget,
            errorTerms: errorTerms,
            blindingMask: blindingMask,
            relaxationFactor: relaxation,
            maxWitnessClass: witnessClass,
            stageAudit: stageAudit,
            recursiveAccumulator: recursiveAccumulator,
            typedTrace: typedTrace
        )
    }

    private func serializeTypedTrace(_ trace: TypedPcdTrace?) throws -> Data {
        guard let trace else { return Data() }
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
        return try encoder.encode(trace)
    }

    private func deserializeTypedTrace(_ data: Data) throws -> TypedPcdTrace? {
        guard data.isEmpty == false else { return nil }
        let decoder = JSONDecoder()
        do {
            return try decoder.decode(TypedPcdTrace.self, from: data)
        } catch {
            throw VaultError.corruptedData
        }
    }

    private func serializeRecursiveAccumulator(_ accumulator: FoldAccumulator?) throws -> Data {
        guard let accumulator else { return Data() }
        return try RecursiveAccumulatorCodec.encode(accumulator)
    }

    private func deserializeRecursiveAccumulator(_ data: Data) throws -> FoldAccumulator? {
        guard data.isEmpty == false else { return nil }
        do {
            return try RecursiveAccumulatorCodec.decode(FoldAccumulator.self, from: data)
        } catch {
            throw VaultError.corruptedData
        }
    }

    internal func serializeStateForTesting(_ state: FoldState) throws -> Data {
        try serializeState(state)
    }

    internal func deserializeStateForTesting(_ data: Data) throws -> FoldState {
        try deserializeState(data)
    }
}

public enum VaultError: Error, Sendable, Equatable {
    case locked
    case corruptedData
    case keyDerivationFailed
    case secureEnclaveUnavailable
    case invalidWrappedKey
    case invalidKeyMaterial
}
