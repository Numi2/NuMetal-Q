import Foundation

extension ProofContext {
    // MARK: - Policy

    /// The active witness-class policy for this context.
    public var activePolicy: NuPolicy { policy }

    /// Validate witness lanes against the active policy for a given operation.
    public func validateForDelegation(laneIDs: [String], attestation: Data? = nil) -> PolicyViolation? {
        policy.validateForDelegation(laneIDs: laneIDs, attestation: attestation)
    }

    /// Current cluster-delegation eligibility for a handle.
    public func clusterEligibility(for handle: ProofHandle) throws -> ClusterExecutionEligibility {
        guard let state = activeStates[handle.chainID] else {
            throw ProofContextError.handleNotFound
        }
        try requireAggregateState(state)
        return eligibility(for: state)
    }

    func maxWitnessClass(for witness: Witness) -> WitnessClass {
        witness.lanes.reduce(.public) { current, lane in
            stricter(current, policy.classForLane(lane.descriptor.name))
        }
    }

    func requireAggregateState(_ state: FoldState) throws {
        guard state.typedTrace == nil,
              state.blindingMask == .zero,
              state.statementCount > 0 else {
            throw ProofContextError.unsupportedStoredState
        }

        switch state.kind {
        case .aggregateStatements:
            return
        case .recursiveAccumulator:
            guard state.recursiveAccumulator != nil else {
                throw ProofContextError.unsupportedStoredState
            }
        case .typedTrace:
            throw ProofContextError.unsupportedStoredState
        }
    }

    func validateSeedInputs(
        witness: Witness,
        publicInputs: [Fq],
        publicHeader: Data
    ) throws {
        try witness.validateSemanticIntegrity()

        let expectedLanes = compiledShape.shape.lanes
        guard witness.lanes.count == expectedLanes.count else {
            throw ProofContextError.witnessShapeMismatch
        }
        for (actual, expected) in zip(witness.lanes, expectedLanes) {
            guard actual.descriptor == expected else {
                throw ProofContextError.witnessShapeMismatch
            }
        }

        let expectedWitnessCount = compiledShape.shape.relation.n - compiledShape.shape.relation.nPublic
        let actualWitnessCount = witness.totalElements
        guard actualWitnessCount == expectedWitnessCount else {
            throw ProofContextError.invalidWitnessElementCount(
                expected: expectedWitnessCount,
                actual: actualWitnessCount
            )
        }

        let expectedPublicCount = compiledShape.shape.relation.nPublic
        guard publicInputs.count == expectedPublicCount else {
            throw ProofContextError.invalidPublicInputCount(
                expected: expectedPublicCount,
                actual: publicInputs.count
            )
        }
        guard publicHeader.count == compiledShape.shape.publicHeaderSize else {
            throw ProofContextError.invalidPublicHeaderSize(
                expected: compiledShape.shape.publicHeaderSize,
                actual: publicHeader.count
            )
        }

        let packedWitness = WitnessPacking.packWitnessToRings(lanes: witness.lanes)
        guard Decomposition.witnessFits(
            packedWitness,
            base: NuProfile.canonical.decompBase,
            numLimbs: NuProfile.canonical.decompLimbs
        ) else {
            throw ProofContextError.witnessExceedsPiDECRepresentability(
                maxMagnitude: Decomposition.maxCenteredMagnitude(in: packedWitness),
                base: NuProfile.canonical.decompBase,
                limbs: NuProfile.canonical.decompLimbs
            )
        }
    }

    func requirePersistenceEligibility(for state: FoldState) throws {
        guard state.maxWitnessClass != .ephemeralDerived else {
            throw ProofContextError.policyViolation(
                PolicyViolation(
                    kind: .ephemeralCannotPersist,
                    laneID: nil,
                    message: "ephemeralDerived witness material cannot be persisted"
                )
            )
        }
    }

    func requireExportEligibility(attestation: Data?) throws {
        let laneIDs = compiledShape.shape.lanes.map(\.name)
        if let violation = policy.validateForSync(laneIDs: laneIDs, attestation: attestation) {
            throw ProofContextError.policyViolation(violation)
        }
    }

    func combineAggregateStates(_ states: [FoldState]) async throws -> FoldState {
        guard states.isEmpty == false else {
            throw ProofContextError.insufficientInputs
        }
        try states.forEach(requireAggregateState)
        for state in states {
            try await ensureRecursiveStateIntegrity(state)
        }
        guard Set(states.map(\.shapeDigest)) == Set([compiledShape.shape.digest]) else {
            throw ProofContextError.shapeMismatch
        }
        do {
            return try await foldEngine.fold(
                states: states,
                relation: compiledShape.shape.relation
            )
        } catch FoldEngineError.witnessPackingExceedsKeySlots {
            throw ProofContextError.accumulatorTooLarge
        } catch FoldEngineError.witnessExceedsPiDECRepresentability(let maxMagnitude, let base, let limbs) {
            throw ProofContextError.witnessExceedsPiDECRepresentability(
                maxMagnitude: maxMagnitude,
                base: base,
                limbs: limbs
            )
        } catch FoldEngineError.invalidAggregateState,
                FoldEngineError.invalidRecursiveAccumulator,
                FoldEngineError.invalidPublicInputCount,
                FoldEngineError.recursiveStageVerificationFailed,
                FoldEngineError.shapeMismatch,
                FoldEngineError.unsupportedWitnessRepresentation {
            throw ProofContextError.unsupportedStoredState
        }
    }

    func ensureRecursiveStateIntegrity(_ state: FoldState) async throws {
        guard state.kind == .recursiveAccumulator else {
            return
        }
        guard try await foldEngine.verifyRecursiveState(
            state: state,
            relation: compiledShape.shape.relation
        ) else {
            throw ProofContextError.unsupportedStoredState
        }
    }

    func eligibility(for state: FoldState) -> ClusterExecutionEligibility {
        if state.maxWitnessClass.rawValue <= policy.maxDelegatableClass.rawValue {
            return .allowed
        }
        return .blocked(maxWitnessClass: state.maxWitnessClass)
    }

    func requireClusterEligibility(for state: FoldState, attestation: Data?) throws {
        if let violation = policy.validateForDelegation(laneIDs: [], attestation: attestation) {
            throw ProofContextError.policyViolation(violation)
        }
        switch eligibility(for: state) {
        case .allowed:
            return
        case .blocked(let witnessClass):
            throw ProofContextError.clusterDelegationProhibited(witnessClass)
        }
    }

    func stricter(_ lhs: WitnessClass, _ rhs: WitnessClass) -> WitnessClass {
        lhs.rawValue >= rhs.rawValue ? lhs : rhs
    }
}
