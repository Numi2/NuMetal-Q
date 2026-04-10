import Foundation

/// Metal-backed typed recursive prover with persistent local verification.
///
/// The typed API stores a full witness-carrying DAG in the encrypted vault.
/// Verification replays every registered step transition locally and checks
/// that the Ajtai commitment binds the entire typed trace.
public actor MetalFoldProver {
    private let profile: NuProfile
    private let policy: NuPolicy
    private let foldEngine: FoldEngine
    private let vault: FoldVault
    private let metalContext: MetalContext?

    private var compiledShapes: [ShapeDigest: CompiledShape] = [:]
    private var stepRegistrations: [String: AnyRegisteredStep] = [:]
    private var activeStates: [UUID: FoldState] = [:]

    public init(
        profile: NuProfile = .canonical,
        policy: NuPolicy = .standard,
        vaultDirectory: URL? = nil,
        vaultKeyMaterial: Data
    ) async throws {
        let validation = profile.validate()
        guard validation.isValid else {
            throw NuMeQError.invalidProfile(validation.errors)
        }

        self.profile = profile
        self.policy = policy
        self.foldEngine = FoldEngine(config: .canonical, seed: profile.foldParameterSeed)
        self.vault = FoldVault(storageDirectory: vaultDirectory)

        let context = try MetalContext()
        self.metalContext = context
        await foldEngine.setMetalContext(context)

        try await vault.unlock(with: vaultKeyMaterial)
    }

    public func register(_ compiledShape: CompiledShape) {
        compiledShapes[compiledShape.shape.digest] = compiledShape
    }

    public func register<S: NuStep>(_ step: S) {
        register(step.compiledShape)
        stepRegistrations[step.stepID] = AnyRegisteredStep(step: step)
    }

    public func seed<S: NuStep>(_ step: S, witness: S.Witness) async throws -> Pcd<S.Output> {
        register(step)
        let compiledShape = step.compiledShape
        let loweredWitness = try step.lowerWitness(witness)
        let header = try step.seedHeader(loweredWitness: loweredWitness)
        try validateHeader(header, compiledShape: compiledShape)
        guard relationIsSatisfied(
            witness: loweredWitness,
            publicInputs: header.publicInputs,
            shape: compiledShape.shape
        ) else {
            throw MetalFoldProverError.invalidWitness
        }

        let trace = TypedPcdTrace(
            nodes: [
                TypedPcdNode(
                    kind: .seed,
                    stepID: step.stepID,
                    witness: loweredWitness,
                    publicInputs: header.publicInputs,
                    headerBytes: Data(header.toBytes()),
                    childIndices: []
                )
            ],
            rootIndex: 0
        )
        let state = try await makeTypedState(shape: compiledShape.shape, trace: trace)
        activeStates[state.chainID] = state
        try await vault.store(state)

        return Pcd(
            chainID: state.chainID,
            header: header,
            shapeDigest: compiledShape.shape.digest
        )
    }

    public func fuse<S: NuStep>(
        _ step: S,
        witness: S.Witness,
        left: Pcd<S.Left>,
        right: Pcd<S.Right>
    ) async throws -> Pcd<S.Output> {
        register(step)
        let compiledShape = step.compiledShape
        guard left.shapeDigest == compiledShape.shape.digest,
              right.shapeDigest == compiledShape.shape.digest else {
            throw MetalFoldProverError.shapeMismatch
        }

        let leftState = try await validatedTypedState(for: left)
        let rightState = try await validatedTypedState(for: right)
        guard let leftTrace = leftState.typedTrace,
              let rightTrace = rightState.typedTrace else {
            throw MetalFoldProverError.unsupportedStoredState
        }

        let loweredWitness = try step.lowerWitness(witness)
        let outputHeader = try step.fuseHeader(
            loweredWitness: loweredWitness,
            left: left.header,
            right: right.header
        )
        try validateHeader(outputHeader, compiledShape: compiledShape)
        guard relationIsSatisfied(
            witness: loweredWitness,
            publicInputs: outputHeader.publicInputs,
            shape: compiledShape.shape
        ) else {
            throw MetalFoldProverError.invalidWitness
        }

        let mergedTrace = merge(
            left: leftTrace,
            right: rightTrace,
            stepID: step.stepID,
            witness: loweredWitness,
            publicInputs: outputHeader.publicInputs,
            headerBytes: Data(outputHeader.toBytes())
        )
        let state = try await makeTypedState(shape: compiledShape.shape, trace: mergedTrace)
        activeStates[state.chainID] = state
        try await vault.store(state)

        return Pcd(
            chainID: state.chainID,
            header: outputHeader,
            shapeDigest: compiledShape.shape.digest
        )
    }

    public func verify<H: NuHeader>(_ pcd: Pcd<H>) async throws -> Bool {
        do {
            _ = try await validatedTypedState(for: pcd)
            return true
        } catch {
            return false
        }
    }

    public func load<H: NuHeader>(_ pcd: Pcd<H>) async throws -> Pcd<H> {
        _ = try await validatedTypedState(for: pcd)
        return pcd
    }

    public var hasGPU: Bool {
        true
    }

    private func loadState(chainID: UUID) async throws -> FoldState {
        if let active = activeStates[chainID] {
            return active
        }
        let restored = try await vault.retrieve(chainID: chainID)
        activeStates[chainID] = restored
        return restored
    }

    private func validatedTypedState<H: NuHeader>(for pcd: Pcd<H>) async throws -> FoldState {
        let state = try await loadState(chainID: pcd.chainID)
        guard let compiledShape = compiledShapes[pcd.shapeDigest] else {
            throw MetalFoldProverError.shapeMismatch
        }
        try validateHeader(pcd.header, compiledShape: compiledShape)
        guard state.kind == .typedTrace,
              let trace = state.typedTrace,
              state.shapeDigest == pcd.shapeDigest,
              pcd.header.shapeDigest == pcd.shapeDigest else {
            throw MetalFoldProverError.unsupportedStoredState
        }
        guard trace.rootIndex < UInt32(trace.nodes.count),
              trace.nodes.count == Int(state.statementCount) else {
            throw MetalFoldProverError.unsupportedStoredState
        }

        let rootNode = trace.nodes[Int(trace.rootIndex)]
        guard rootNode.publicInputs == pcd.header.publicInputs,
              rootNode.headerBytes == Data(pcd.header.toBytes()),
              state.publicInputs == rootNode.publicInputs,
              state.publicHeader == rootNode.headerBytes else {
            throw MetalFoldProverError.unsupportedStoredState
        }

        try validateTrace(trace, compiledShape: compiledShape)
        let expectedWitnessClass = try maxPersistableWitnessClass(for: trace)
        guard state.maxWitnessClass == expectedWitnessClass else {
            throw MetalFoldProverError.unsupportedStoredState
        }
        let aggregateWitness = try aggregateTraceWitness(trace, shape: compiledShape.shape)
        guard aggregateWitness == state.accumulatedWitness else {
            throw MetalFoldProverError.unsupportedStoredState
        }

        let slotCount = await foldEngine.commitmentSlotCount()
        guard aggregateWitness.count <= slotCount else {
            throw MetalFoldProverError.accumulatorTooLarge
        }
        let recomputedCommitment = await foldEngine.commit(witness: aggregateWitness)
        guard recomputedCommitment == state.commitment else {
            throw MetalFoldProverError.unsupportedStoredState
        }

        return state
    }

    private func makeTypedState(shape: Shape, trace: TypedPcdTrace) async throws -> FoldState {
        guard trace.nodes.isEmpty == false,
              trace.rootIndex < UInt32(trace.nodes.count) else {
            throw MetalFoldProverError.unsupportedStoredState
        }

        let aggregateWitness = try aggregateTraceWitness(trace, shape: shape)
        let slotCount = await foldEngine.commitmentSlotCount()
        guard aggregateWitness.count <= slotCount else {
            throw MetalFoldProverError.accumulatorTooLarge
        }

        let commitment = await foldEngine.commit(witness: aggregateWitness)
        let root = trace.nodes[Int(trace.rootIndex)]
        let normBudget = NormBudget(
            bound: profile.normBound,
            decompBase: profile.decompBase,
            decompLimbs: profile.decompLimbs
        )
        let maxWitnessClass = try maxPersistableWitnessClass(for: trace)

        return FoldState(
            kind: .typedTrace,
            chainID: UUID(),
            epoch: UInt64(max(0, trace.nodes.count - 1)),
            shapeDigest: shape.digest,
            commitment: commitment,
            accumulatedWitness: aggregateWitness,
            publicInputs: root.publicInputs,
            publicHeader: root.headerBytes,
            statementCount: UInt32(clamping: trace.nodes.count),
            normBudget: normBudget,
            errorTerms: [],
            blindingMask: .zero,
            relaxationFactor: .one,
            maxWitnessClass: maxWitnessClass,
            stageAudit: [],
            recursiveAccumulator: nil,
            typedTrace: trace
        )
    }

    private func maxPersistableWitnessClass(for trace: TypedPcdTrace) throws -> WitnessClass {
        var maxWitnessClass = WitnessClass.public
        for node in trace.nodes {
            let nodeClass = try maxPersistableWitnessClass(for: node.witness)
            if nodeClass.rawValue > maxWitnessClass.rawValue {
                maxWitnessClass = nodeClass
            }
        }
        return maxWitnessClass
    }

    private func maxPersistableWitnessClass(for witness: Witness) throws -> WitnessClass {
        var maxWitnessClass = WitnessClass.public
        for lane in witness.lanes {
            let laneID = lane.descriptor.name
            guard policy.isPersistable(laneID) else {
                throw MetalFoldProverError.policyViolation(
                    PolicyViolation(
                        kind: .ephemeralCannotPersist,
                        laneID: laneID,
                        message: "Lane '\(laneID)' has class \(policy.classForLane(laneID)) and cannot be persisted"
                    )
                )
            }
            let witnessClass = policy.classForLane(laneID)
            if witnessClass.rawValue > maxWitnessClass.rawValue {
                maxWitnessClass = witnessClass
            }
        }
        return maxWitnessClass
    }

    private func validateTrace(
        _ trace: TypedPcdTrace,
        compiledShape: CompiledShape
    ) throws {
        for (index, node) in trace.nodes.enumerated() {
            guard node.publicInputs.count == compiledShape.shape.relation.nPublic,
                  node.headerBytes.count == compiledShape.shape.publicHeaderSize,
                  relationIsSatisfied(
                    witness: node.witness,
                    publicInputs: node.publicInputs,
                    shape: compiledShape.shape
                  ) else {
                throw MetalFoldProverError.unsupportedStoredState
            }

            guard let registration = stepRegistrations[node.stepID] else {
                throw MetalFoldProverError.stepNotRegistered(node.stepID)
            }
            guard registration.shapeDigest == compiledShape.shape.digest else {
                throw MetalFoldProverError.shapeMismatch
            }

            switch node.kind {
            case .seed:
                guard node.childIndices.isEmpty else {
                    throw MetalFoldProverError.unsupportedStoredState
                }
                guard try registration.validateSeed(node.witness, node.publicInputs, node.headerBytes) else {
                    throw MetalFoldProverError.unsupportedStoredState
                }
            case .fuse:
                guard node.childIndices.count == 2 else {
                    throw MetalFoldProverError.unsupportedStoredState
                }
                let leftIndex = Int(node.childIndices[0])
                let rightIndex = Int(node.childIndices[1])
                guard leftIndex < index, rightIndex < index else {
                    throw MetalFoldProverError.unsupportedStoredState
                }
                let left = trace.nodes[leftIndex]
                let right = trace.nodes[rightIndex]
                guard try registration.validateFuse(
                    node.witness,
                    left.publicInputs,
                    left.headerBytes,
                    right.publicInputs,
                    right.headerBytes,
                    node.publicInputs,
                    node.headerBytes
                ) else {
                    throw MetalFoldProverError.unsupportedStoredState
                }
            }
        }
    }

    private func aggregateTraceWitness(
        _ trace: TypedPcdTrace,
        shape: Shape
    ) throws -> [RingElement] {
        let witnessFieldCount = shape.relation.n - shape.relation.nPublic
        let witnessFields = try trace.nodes.flatMap { node -> [Fq] in
            let flattened = node.witness.flatten()
            guard flattened.count == witnessFieldCount else {
                throw MetalFoldProverError.invalidWitness
            }
            return flattened
        }
        return WitnessPacking.packFieldVectorToRings(witnessFields)
    }

    private func merge(
        left: TypedPcdTrace,
        right: TypedPcdTrace,
        stepID: String,
        witness: Witness,
        publicInputs: [Fq],
        headerBytes: Data
    ) -> TypedPcdTrace {
        let rightOffset = UInt32(left.nodes.count)
        let shiftedRightNodes = right.nodes.map { node in
            TypedPcdNode(
                kind: node.kind,
                stepID: node.stepID,
                witness: node.witness,
                publicInputs: node.publicInputs,
                headerBytes: node.headerBytes,
                childIndices: node.childIndices.map { $0 + rightOffset }
            )
        }

        var nodes = left.nodes
        nodes.append(contentsOf: shiftedRightNodes)
        nodes.append(
            TypedPcdNode(
                kind: .fuse,
                stepID: stepID,
                witness: witness,
                publicInputs: publicInputs,
                headerBytes: headerBytes,
                childIndices: [left.rootIndex, right.rootIndex + rightOffset]
            )
        )

        return TypedPcdTrace(
            nodes: nodes,
            rootIndex: UInt32(nodes.count - 1)
        )
    }

    private func relationIsSatisfied(
        witness: Witness,
        publicInputs: [Fq],
        shape: Shape
    ) -> Bool {
        let flattened = witness.flatten()
        guard flattened.count == shape.relation.n - shape.relation.nPublic,
              publicInputs.count == shape.relation.nPublic else {
            return false
        }
        return shape.relation.isSatisfied(by: publicInputs + flattened)
    }

    private func validateHeader<H: NuHeader>(
        _ header: H,
        compiledShape: CompiledShape
    ) throws {
        guard header.shapeDigest == compiledShape.shape.digest else {
            throw MetalFoldProverError.headerShapeMismatch
        }
        guard header.publicInputs.count == compiledShape.shape.relation.nPublic,
              header.toBytes().count == compiledShape.shape.publicHeaderSize else {
            throw MetalFoldProverError.invalidHeaderEncoding
        }
    }
}

public enum MetalFoldProverError: Error, Sendable {
    case shapeMismatch
    case headerShapeMismatch
    case invalidHeaderEncoding
    case invalidWitness
    case accumulatorTooLarge
    case policyViolation(PolicyViolation)
    case stepNotRegistered(String)
    case unsupportedStoredState
}

private struct AnyRegisteredStep: Sendable {
    let stepID: String
    let shapeDigest: ShapeDigest
    let validateSeed: @Sendable (Witness, [Fq], Data) throws -> Bool
    let validateFuse: @Sendable (Witness, [Fq], Data, [Fq], Data, [Fq], Data) throws -> Bool

    init<S: NuStep>(step: S) {
        self.stepID = step.stepID
        self.shapeDigest = step.compiledShape.shape.digest
        self.validateSeed = { loweredWitness, publicInputs, headerBytes in
            let decoded = try S.Output.decode(
                bytes: Array(headerBytes),
                publicInputs: publicInputs,
                shapeDigest: step.compiledShape.shape.digest
            )
            let expected = try step.seedHeader(loweredWitness: loweredWitness)
            return decoded.shapeDigest == step.compiledShape.shape.digest
                && decoded.publicInputs == publicInputs
                && Data(decoded.toBytes()) == headerBytes
                && expected.shapeDigest == step.compiledShape.shape.digest
                && expected.publicInputs == publicInputs
                && Data(expected.toBytes()) == headerBytes
        }
        self.validateFuse = { loweredWitness, leftInputs, leftBytes, rightInputs, rightBytes, outputInputs, outputBytes in
            let left = try S.Left.decode(
                bytes: Array(leftBytes),
                publicInputs: leftInputs,
                shapeDigest: step.compiledShape.shape.digest
            )
            let right = try S.Right.decode(
                bytes: Array(rightBytes),
                publicInputs: rightInputs,
                shapeDigest: step.compiledShape.shape.digest
            )
            let output = try S.Output.decode(
                bytes: Array(outputBytes),
                publicInputs: outputInputs,
                shapeDigest: step.compiledShape.shape.digest
            )
            let expected = try step.fuseHeader(
                loweredWitness: loweredWitness,
                left: left,
                right: right
            )
            return left.shapeDigest == step.compiledShape.shape.digest
                && left.publicInputs == leftInputs
                && Data(left.toBytes()) == leftBytes
                && right.shapeDigest == step.compiledShape.shape.digest
                && right.publicInputs == rightInputs
                && Data(right.toBytes()) == rightBytes
                && output.shapeDigest == step.compiledShape.shape.digest
                && output.publicInputs == outputInputs
                && Data(output.toBytes()) == outputBytes
                && expected.shapeDigest == step.compiledShape.shape.digest
                && expected.publicInputs == outputInputs
                && Data(expected.toBytes()) == outputBytes
        }
    }
}
