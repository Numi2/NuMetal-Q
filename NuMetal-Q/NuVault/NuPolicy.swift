import Foundation

// MARK: - NuPolicy: Witness Classification and Trust Model
// The iPhone is the root of trust. The MacBook is a co-prover, not a co-owner.
// WitnessClass controls what material may leave the device boundary,
// be synced to peers, or be delegated to cluster co-provers.
//
// This is a product requirement: NuMeQ is infrastructure for wallets and
// high-value apps. The trust model must be explicit from day one.

/// Classification of witness material by sensitivity and mobility.
///
/// Every witness lane, derived key, and intermediate value must be
/// tagged with a witness class. The class determines whether the
/// material can be synced, delegated, or confined to a single device.
public enum WitnessClass: UInt8, Sendable, Codable, CaseIterable {
    /// Public data: may appear in proof headers, public inputs, shape digests.
    /// Safe to share with any party including verifiers.
    case `public` = 0

    /// Encrypted at rest and in transit. May be synced between the user's
    /// own devices via HPKE/X-Wing encrypted channels.
    /// Never sent to a server in cleartext.
    case syncableEncrypted = 1

    /// Confined to a single device. Never leaves the originating device,
    /// not even to a paired MacBook in a cluster session.
    /// Backed by Secure Enclave when available.
    case deviceConfined = 2

    /// Ephemeral: derived from other material, used within a single
    /// proving session, and zeroed on session completion.
    /// Never persisted to disk.
    case ephemeralDerived = 3
}

/// Policy governing how witness material flows through the system.
///
/// `NuPolicy` is attached to a `ProofContext` and enforced at every
/// boundary: cluster delegation, vault persistence, sync, and export.
public struct NuPolicy: Sendable {
    /// Per-lane witness class assignments.
    /// Keys are lane descriptor identifiers; values are their classes.
    public let laneClasses: [String: WitnessClass]

    /// Default class for lanes not explicitly classified.
    public let defaultClass: WitnessClass

    /// Whether cluster delegation is permitted at all.
    public let clusterDelegationAllowed: Bool

    /// Maximum witness class that may be delegated to a co-prover.
    /// Material with a stricter class than this threshold is stripped
    /// or masked before delegation.
    public let maxDelegatableClass: WitnessClass

    /// Whether cluster delegation requires an attestation blob.
    public let delegationRequiresAttestation: Bool

    /// Whether sync/export requires an attestation blob.
    public let syncRequiresAttestation: Bool

    /// Standard policy: syncableEncrypted default, cluster allowed for public+syncable only.
    public static let standard = NuPolicy(
        laneClasses: [:],
        defaultClass: .syncableEncrypted,
        clusterDelegationAllowed: true,
        maxDelegatableClass: .syncableEncrypted,
        delegationRequiresAttestation: true,
        syncRequiresAttestation: true
    )

    /// Strict policy: deviceConfined default, no cluster delegation.
    public static let deviceOnly = NuPolicy(
        laneClasses: [:],
        defaultClass: .deviceConfined,
        clusterDelegationAllowed: false,
        maxDelegatableClass: .public,
        delegationRequiresAttestation: true,
        syncRequiresAttestation: true
    )

    public init(
        laneClasses: [String: WitnessClass],
        defaultClass: WitnessClass,
        clusterDelegationAllowed: Bool,
        maxDelegatableClass: WitnessClass,
        delegationRequiresAttestation: Bool = true,
        syncRequiresAttestation: Bool = true
    ) {
        self.laneClasses = laneClasses
        self.defaultClass = defaultClass
        self.clusterDelegationAllowed = clusterDelegationAllowed
        self.maxDelegatableClass = maxDelegatableClass
        self.delegationRequiresAttestation = delegationRequiresAttestation
        self.syncRequiresAttestation = syncRequiresAttestation
    }

    /// Resolve the witness class for a named lane.
    public func classForLane(_ laneID: String) -> WitnessClass {
        laneClasses[laneID] ?? defaultClass
    }

    /// Check whether a lane's material may be delegated to a co-prover.
    public func isDelegatable(_ laneID: String) -> Bool {
        guard clusterDelegationAllowed else { return false }
        let cls = classForLane(laneID)
        return cls.rawValue <= maxDelegatableClass.rawValue
    }

    /// Check whether a lane's material may be synced to another device.
    public func isSyncable(_ laneID: String) -> Bool {
        let cls = classForLane(laneID)
        switch cls {
        case .public, .syncableEncrypted:
            return true
        case .deviceConfined, .ephemeralDerived:
            return false
        }
    }

    /// Check whether a lane's material may be persisted to the vault.
    public func isPersistable(_ laneID: String) -> Bool {
        let cls = classForLane(laneID)
        switch cls {
        case .public, .syncableEncrypted, .deviceConfined:
            return true
        case .ephemeralDerived:
            return false
        }
    }

    /// Validate that a set of lanes complies with the policy for a given operation.
    public func validateForDelegation(laneIDs: [String], attestation: Data? = nil) -> PolicyViolation? {
        guard clusterDelegationAllowed else {
            return PolicyViolation(
                kind: .delegationDisabled,
                laneID: nil,
                message: "Cluster delegation is disabled by policy"
            )
        }
        if delegationRequiresAttestation && (attestation?.isEmpty != false) {
            return PolicyViolation(
                kind: .attestationRequired,
                laneID: nil,
                message: "Cluster delegation requires attestation"
            )
        }
        for laneID in laneIDs {
            if !isDelegatable(laneID) {
                let cls = classForLane(laneID)
                return PolicyViolation(
                    kind: .classExceedsDelegationThreshold,
                    laneID: laneID,
                    message: "Lane '\(laneID)' has class \(cls) which exceeds delegation threshold \(maxDelegatableClass)"
                )
            }
        }
        return nil
    }

    /// Validate that a set of lanes complies with the policy for sync.
    public func validateForSync(laneIDs: [String], attestation: Data? = nil) -> PolicyViolation? {
        if syncRequiresAttestation && (attestation?.isEmpty != false) {
            return PolicyViolation(
                kind: .attestationRequired,
                laneID: nil,
                message: "Sync requires attestation"
            )
        }
        for laneID in laneIDs {
            if !isSyncable(laneID) {
                let cls = classForLane(laneID)
                return PolicyViolation(
                    kind: .deviceConfinedCannotSync,
                    laneID: laneID,
                    message: "Lane '\(laneID)' has class \(cls) and cannot be synced"
                )
            }
        }
        return nil
    }
}

/// A policy violation detected during a boundary operation.
public struct PolicyViolation: Error, Sendable {
    public let kind: PolicyViolationKind
    public let laneID: String?
    public let message: String
}

public enum PolicyViolationKind: Sendable {
    case delegationDisabled
    case classExceedsDelegationThreshold
    case deviceConfinedCannotSync
    case ephemeralCannotPersist
    case attestationRequired
}

/// Authorized cluster-delegation payload with witness-class metadata.
public struct DelegationPayload: Sendable {
    public let payload: Data
    public let laneClasses: [String: WitnessClass]
    public let confinedIndices: [Int]
    public let attestation: Data

    public init(
        payload: Data,
        laneClasses: [String: WitnessClass],
        confinedIndices: [Int],
        attestation: Data
    ) {
        self.payload = payload
        self.laneClasses = laneClasses
        self.confinedIndices = confinedIndices
        self.attestation = attestation
    }
}

// MARK: - Cluster Fragment Stripping

extension NuPolicy {
    /// Strip device-confined material from witness data before cluster delegation.
    ///
    /// Returns a masked copy where device-confined lanes are replaced with
    /// zero-filled placeholders. The co-prover can perform partial evaluation
    /// on the non-confined lanes, and the principal completes the confined
    /// portions locally.
    public func stripForDelegation(
        lanes: [WitnessLane]
    ) -> (delegatable: [WitnessLane], confinedIndices: [Int]) {
        var delegatable = [WitnessLane]()
        var confined = [Int]()

        for (i, lane) in lanes.enumerated() {
            let cls = classForLane(lane.descriptor.name)
            if cls.rawValue > maxDelegatableClass.rawValue {
                confined.append(i)
                let zeroed = [Fq](repeating: .zero, count: lane.values.count)
                delegatable.append(WitnessLane(descriptor: lane.descriptor, values: zeroed))
            } else {
                delegatable.append(lane)
            }
        }

        return (delegatable, confined)
    }

    /// Prepare an authorized cluster delegation payload from witness lanes.
    ///
    /// Non-delegatable lanes are zero-masked and recorded in `confinedIndices`.
    public func authorizeDelegation(
        lanes: [WitnessLane],
        attestation: Data?,
        encode: ([WitnessLane]) throws -> Data
    ) throws -> DelegationPayload {
        guard clusterDelegationAllowed else {
            throw PolicyViolation(
                kind: .delegationDisabled,
                laneID: nil,
                message: "Cluster delegation is disabled by policy"
            )
        }
        guard let attestation, !attestation.isEmpty else {
            throw PolicyViolation(
                kind: .attestationRequired,
                laneID: nil,
                message: "Cluster delegation requires attestation"
            )
        }

        let stripped = stripForDelegation(lanes: lanes)
        let laneClassMap = Dictionary(uniqueKeysWithValues: lanes.map {
            ($0.descriptor.name, classForLane($0.descriptor.name))
        })

        return DelegationPayload(
            payload: try encode(stripped.delegatable),
            laneClasses: laneClassMap,
            confinedIndices: stripped.confinedIndices,
            attestation: attestation
        )
    }
}
