import Foundation
import CryptoKit
import Metal

internal struct HachiPCSBackend {
    let parameterBundle: HachiSealParameterBundle
    let codewordBlowup: Int

    init(
        parameterBundle: HachiSealParameterBundle = NuParams.derive(from: .canonical).seal,
        codewordBlowup: Int = 4
    ) {
        self.parameterBundle = parameterBundle
        self.codewordBlowup = codewordBlowup
    }

    func commit(
        label: SpartanOracleID,
        polynomial: MultilinearPoly,
        context: MetalContext? = nil,
        traceCollector: MetalTraceCollector? = nil
    ) throws -> HachiPCSCommitment {
        try buildOracleArtifact(
            label: label,
            polynomial: polynomial,
            context: context,
            traceCollector: traceCollector
        ).commitment
    }

    func openBatch(
        polynomials: [SpartanOracleID: MultilinearPoly],
        queries: [SpartanPCSQuery<Fq>],
        transcript: inout NuTranscriptSeal,
        context: MetalContext? = nil,
        traceCollector: MetalTraceCollector? = nil
    ) throws -> HachiPCSBatchOpeningProof {
        let batchSeedDigest = transcript.challengeBytes(
            label: "numeq.decider.hachi.batch.seed",
            count: 32
        )

        let artifacts = try Dictionary(
            uniqueKeysWithValues: polynomials.map { oracle, polynomial in
                (
                    oracle,
                    try buildOracleArtifact(
                        label: oracle,
                        polynomial: polynomial,
                        context: context,
                        traceCollector: traceCollector
                    )
                )
            }
        )

        let grouped = Dictionary(grouping: queries) { query in
            pointKey(query.point)
        }

        let classes = try grouped.keys.sorted().map { key -> HachiPCSBatchClassOpeningProof in
            let classQueries = grouped[key] ?? []
            guard let point = classQueries.first?.point else {
                throw SpartanSealError.invalidPCSBatchClassPoint
            }
            let scheduleDigest = scheduleDigest(
                point: point,
                oracles: classQueries.map(\.oracle),
                batchSeedDigest: batchSeedDigest
            )
            let pointDigest = digest(
                point.flatMap { $0.toBytes() },
                domain: "NuMeQ.Decider.Hachi.Point"
            )
            let openings = try classQueries.map { query in
                guard let polynomial = polynomials[query.oracle] else {
                    throw SpartanSealError.missingPCSOracle(query.oracle)
                }
                guard let artifact = artifacts[query.oracle] else {
                    throw SpartanSealError.missingPCSOracle(query.oracle)
                }
                let evaluation = polynomial.evaluate(at: query.point)
                let evaluationDigest = digest(
                    evaluation.toBytes(),
                    domain: "NuMeQ.Decider.Hachi.Eval"
                )
                let codewordIndex = queryIndex(
                    point: query.point,
                    oracle: query.oracle,
                    codewordLength: artifact.codeword.count
                )
                return HachiPCSOpening(
                    oracle: query.oracle,
                    evaluation: evaluation,
                    scheduleDigest: scheduleDigest,
                    evaluationDigest: evaluationDigest,
                    codewordIndex: UInt32(codewordIndex),
                    codewordValue: artifact.codeword[codewordIndex],
                    merkleAuthenticationPath: artifact.authenticationPath(for: codewordIndex)
                )
            }
            return HachiPCSBatchClassOpeningProof(
                point: point,
                pointDigest: pointDigest,
                scheduleDigest: scheduleDigest,
                openings: openings.sorted { lhs, rhs in
                    pointKey(lhs.oracle) < pointKey(rhs.oracle)
                }
            )
        }

        return HachiPCSBatchOpeningProof(
            batchSeedDigest: batchSeedDigest,
            classes: classes
        )
    }

    func verifyBatch(
        commitments: [SpartanOracleID: HachiPCSCommitment],
        queries: [SpartanPCSQuery<Fq>],
        proof: HachiPCSBatchOpeningProof,
        transcript: inout NuTranscriptSeal,
        context: MetalContext? = nil,
        traceCollector: MetalTraceCollector? = nil,
        diagnostics: inout HachiVerificationDiagnostics
    ) throws -> Bool {
        let batchSeedDigest = transcript.challengeBytes(
            label: "numeq.decider.hachi.batch.seed",
            count: 32
        )
        guard proof.batchSeedDigest == batchSeedDigest else {
            diagnostics.recordFailure("invalid hachi pcs batch seed")
            return false
        }

        let expectedClassOrder = proof.classes.map { pointKey($0.point) }.sorted()
        guard proof.classes.map({ pointKey($0.point) }) == expectedClassOrder else {
            diagnostics.recordFailure("non-canonical hachi pcs class ordering")
            return false
        }

        var seenClassKeys = Set<String>()
        _ = context
        _ = traceCollector
        let expectedQueries = Dictionary(
            uniqueKeysWithValues: queries.map { query in
                (
                    "\(pointKey(query.point))::\(pointKey(query.oracle))",
                    query
                )
            }
        )
        let openingCount = proof.classes.reduce(0) { partial, classProof in
            partial + classProof.openings.count
        }
        guard openingCount == queries.count else {
            diagnostics.recordFailure("invalid hachi pcs opening count")
            return false
        }

        for classProof in proof.classes {
            let classKey = pointKey(classProof.point)
            guard seenClassKeys.insert(classKey).inserted else {
                diagnostics.recordFailure("duplicate hachi pcs class point \(classKey)")
                return false
            }

            let expectedPointDigest = pointDigest(classProof.point)
            guard classProof.pointDigest == expectedPointDigest else {
                diagnostics.recordFailure("invalid hachi pcs point digest for \(classKey)")
                return false
            }

            let expectedOpeningOrder = classProof.openings.map(\.oracle).map(pointKey).sorted()
            guard classProof.openings.map({ pointKey($0.oracle) }) == expectedOpeningOrder else {
                diagnostics.recordFailure("non-canonical hachi pcs oracle ordering for \(classKey)")
                return false
            }

            var seenOracles = Set<SpartanOracleID>()
            let expectedScheduleDigest = scheduleDigest(
                point: classProof.point,
                oracles: classProof.openings.map(\.oracle),
                batchSeedDigest: batchSeedDigest
            )
            guard classProof.scheduleDigest == expectedScheduleDigest else {
                diagnostics.recordFailure("invalid hachi pcs schedule digest for \(classKey)")
                return false
            }

            for opening in classProof.openings {
                guard seenOracles.insert(opening.oracle).inserted else {
                    diagnostics.recordFailure("duplicate hachi pcs oracle \(pointKey(opening.oracle))")
                    return false
                }
                guard let commitment = commitments[opening.oracle] else {
                    diagnostics.recordFailure("missing hachi pcs commitment \(pointKey(opening.oracle))")
                    return false
                }
                guard commitment.oracle == opening.oracle else {
                    diagnostics.recordFailure("commitment oracle mismatch for \(pointKey(opening.oracle))")
                    return false
                }
                guard commitment.parameterDigest == parameterBundle.parameterDigest else {
                    diagnostics.recordFailure("invalid hachi pcs parameter digest for \(pointKey(opening.oracle))")
                    return false
                }
                guard opening.scheduleDigest == classProof.scheduleDigest else {
                    diagnostics.recordFailure("opening schedule digest mismatch for \(pointKey(opening.oracle))")
                    return false
                }

                let queryKey = "\(classKey)::\(pointKey(opening.oracle))"
                guard let query = expectedQueries[queryKey] else {
                    diagnostics.recordFailure("missing hachi pcs query \(pointKey(opening.oracle)) at \(classKey)")
                    return false
                }
                guard query.point == classProof.point else {
                    diagnostics.recordFailure("query point mismatch for \(pointKey(opening.oracle))")
                    return false
                }
                guard opening.evaluation == query.value else {
                    diagnostics.recordFailure("invalid blinded evaluation for \(pointKey(opening.oracle))")
                    return false
                }
                guard opening.evaluationDigest == evaluationDigest(query.value) else {
                    diagnostics.recordFailure("invalid evaluation digest for \(pointKey(opening.oracle))")
                    return false
                }

                let expectedIndex = queryIndex(
                    point: classProof.point,
                    oracle: opening.oracle,
                    codewordLength: Int(commitment.codewordLength)
                )
                guard Int(opening.codewordIndex) == expectedIndex else {
                    diagnostics.recordArtifactDiff(
                        oracle: opening.oracle,
                        component: "codewordIndex",
                        detail: "expected \(expectedIndex), got \(opening.codewordIndex)"
                    )
                    return false
                }
                guard verifyAuthenticationPath(
                    opening: opening,
                    commitment: commitment
                ) else {
                    diagnostics.recordArtifactDiff(
                        oracle: opening.oracle,
                        component: "merkleRoot",
                        detail: "authentication path does not reconstruct commitment root"
                    )
                    return false
                }
            }
        }

        return true
    }

    func compareCPUAndMetalArtifacts(
        label: SpartanOracleID,
        polynomial: MultilinearPoly,
        context: MetalContext
    ) throws -> [HachiPCSArtifactDiff] {
        let cpuArtifact = try buildOracleArtifact(
            label: label,
            polynomial: polynomial,
            context: nil,
            traceCollector: nil
        )
        let metalArtifact = try buildOracleArtifact(
            label: label,
            polynomial: polynomial,
            context: context,
            traceCollector: nil
        )
        return diffArtifacts(
            expected: cpuArtifact,
            actual: metalArtifact
        )
    }

    private func buildOracleArtifact(
        label: SpartanOracleID,
        polynomial: MultilinearPoly,
        context: MetalContext?,
        traceCollector: MetalTraceCollector?
    ) throws -> HachiPCSOracleArtifact {
        if let context {
            return try buildOracleArtifactMetal(
                label: label,
                polynomial: polynomial,
                context: context,
                traceCollector: traceCollector
            )
        }

        let codeword = try buildCodeword(
            polynomial: polynomial,
            context: context,
            traceCollector: traceCollector,
            label: label
        )
        let merkleLevels = try buildMerkleLevels(
            codeword: codeword,
            context: context,
            traceCollector: traceCollector,
            label: label
        )
        let packed = WitnessPacking.packFieldVectorToRings(polynomial.evals)
        let key = AjtaiKey.expand(
            seed: parameterBundle.seed,
            slotCount: max(1, packed.count)
        )
        let tableCommitment = AjtaiCommitter.commit(key: key, witness: packed)
        let tableDigest = digest(
            polynomial.evals.flatMap { $0.toBytes() },
            domain: "NuMeQ.Decider.Hachi.Table"
        )

        return HachiPCSOracleArtifact(
            commitment: HachiPCSCommitment(
                oracle: label,
                tableCommitment: tableCommitment,
                tableDigest: tableDigest,
                merkleRoot: merkleLevels.last?.first ?? digest([], domain: "NuMeQ.Decider.Hachi.Empty"),
                parameterDigest: parameterBundle.parameterDigest,
                valueCount: UInt32(clamping: polynomial.evals.count),
                codewordLength: UInt32(clamping: codeword.count)
            ),
            codeword: codeword,
            merkleLevels: merkleLevels
        )
    }

    private func buildOracleArtifactMetal(
        label: SpartanOracleID,
        polynomial: MultilinearPoly,
        context: MetalContext,
        traceCollector: MetalTraceCollector?
    ) throws -> HachiPCSOracleArtifact {
        let base = polynomial.evals.isEmpty ? [Fq.zero] : polynomial.evals
        let codewordLength = max(1, base.count * codewordBlowup)

        let (codeword, firstLevel) = try autoreleasepool { () throws -> ([Fq], [[UInt8]]) in
            guard let evalBuffer = context.uploadFieldElements(base),
                  let codewordBuffer = context.makeSharedBuffer(
                    length: codewordLength * MemoryLayout<UInt32>.size * 2
                  ),
                  let leafBuffer = context.makeSharedBuffer(length: codewordLength * 32) else {
                throw NuMetalError.heapCreationFailed
            }

            let dispatcher = KernelDispatcher(context: context)
            if let traceCollector {
                let encodeTiming = try dispatcher.dispatchSealEncodeTimed(
                    evalBuffer: evalBuffer,
                    codewordBuffer: codewordBuffer,
                    n: base.count,
                    blowup: codewordBlowup
                )
                traceCollector.append(
                    stage: "seal.verify.assisted",
                    iteration: traceCollector.defaultIteration,
                    dispatchLabel: "\(oracleTracePrefix(for: label)).encode",
                    kernelFamily: .sealEncode,
                    timing: encodeTiming
                )
                let leafTiming = try dispatcher.dispatchMerkleHashTimed(
                    leavesBuffer: codewordBuffer,
                    nodesBuffer: leafBuffer,
                    numLeaves: codewordLength
                )
                traceCollector.append(
                    stage: "seal.verify.assisted",
                    iteration: traceCollector.defaultIteration,
                    dispatchLabel: "\(oracleTracePrefix(for: label)).leaf_hash",
                    kernelFamily: .merkleHash,
                    timing: leafTiming
                )
            } else {
                let stage = try dispatcher.makeStage(label: "NuMeQ.PCS.\(String(describing: label)).Commit")
                var nU32 = UInt32(base.count)
                var blowupU32 = UInt32(codewordBlowup)
                _ = try withUnsafeBytes(of: &nU32) { nBytes in
                    try withUnsafeBytes(of: &blowupU32) { blowupBytes in
                        try stage.encode(
                            family: .sealEncode,
                            buffers: [
                                (evalBuffer, 0, 0),
                                (codewordBuffer, 0, 1),
                            ],
                            bytes: [
                                (UnsafeRawPointer(nBytes.baseAddress!), nBytes.count, 2),
                                (UnsafeRawPointer(blowupBytes.baseAddress!), blowupBytes.count, 3),
                            ],
                            threadsPerGrid: MTLSize(width: codewordLength, height: 1, depth: 1),
                            requestedThreadgroupWidth: Int(MetalStorageLayout.defaultSealChunkSize)
                        )
                    }
                }

                var leafCount = UInt32(codewordLength)
                _ = try withUnsafeBytes(of: &leafCount) { countBytes in
                    try stage.encode(
                        family: .merkleHash,
                        buffers: [
                            (codewordBuffer, 0, 0),
                            (leafBuffer, 0, 1),
                        ],
                        bytes: [
                            (UnsafeRawPointer(countBytes.baseAddress!), countBytes.count, 2),
                        ],
                        threadsPerGrid: MTLSize(width: codewordLength, height: 1, depth: 1),
                        requestedThreadgroupWidth: Int(MetalStorageLayout.defaultMerkleChunkSize)
                    )
                }

                stage.commit()
                try stage.waitUntilCompleted()
            }

            let codewordPointer = codewordBuffer.contents().bindMemory(
                to: UInt32.self,
                capacity: codewordLength * 2
            )
            let packedCodeword = Array(
                UnsafeBufferPointer(start: codewordPointer, count: codewordLength * 2)
            )
            return (
                MetalFieldPacking.unpackFieldElementsSoA(packedCodeword, count: codewordLength),
                readHashLevel(from: leafBuffer, count: codewordLength)
            )
        }

        var merkleLevels = [firstLevel]
        var currentLevel = firstLevel
        while currentLevel.count > 1 {
            if currentLevel.count % 2 != 0, let last = currentLevel.last {
                currentLevel.append(last)
            }
            let parentCount = currentLevel.count / 2
            currentLevel = try autoreleasepool { () throws -> [[UInt8]] in
                guard let childBuffer = context.makeSharedBuffer(length: currentLevel.count * 32),
                      let parentBuffer = context.makeSharedBuffer(length: parentCount * 32) else {
                    throw NuMetalError.heapCreationFailed
                }
                writeHashLevel(currentLevel, to: childBuffer)
                let dispatcher = KernelDispatcher(context: context)
                if let traceCollector {
                    let timing = try dispatcher.dispatchMerkleParentTimed(
                        childBuffer: childBuffer,
                        parentBuffer: parentBuffer,
                        numParents: parentCount
                    )
                    traceCollector.append(
                        stage: "seal.verify.assisted",
                        iteration: traceCollector.defaultIteration,
                        dispatchLabel: "\(oracleTracePrefix(for: label)).merkle_parent[level=\(merkleLevels.count)]",
                        kernelFamily: .merkleParent,
                        timing: timing
                    )
                } else {
                    try dispatcher.dispatchMerkleParent(
                        childBuffer: childBuffer,
                        parentBuffer: parentBuffer,
                        numParents: parentCount
                    )
                }
                return readHashLevel(from: parentBuffer, count: parentCount)
            }
            merkleLevels.append(currentLevel)
        }

        let packed = WitnessPacking.packFieldVectorToRings(polynomial.evals)
        let key = AjtaiKey.expand(
            seed: parameterBundle.seed,
            slotCount: max(1, packed.count)
        )
        let tableCommitment = AjtaiCommitter.commit(key: key, witness: packed)
        let tableDigest = digest(
            polynomial.evals.flatMap { $0.toBytes() },
            domain: "NuMeQ.Decider.Hachi.Table"
        )

        return HachiPCSOracleArtifact(
            commitment: HachiPCSCommitment(
                oracle: label,
                tableCommitment: tableCommitment,
                tableDigest: tableDigest,
                merkleRoot: merkleLevels.last?.first ?? digest([], domain: "NuMeQ.Decider.Hachi.Empty"),
                parameterDigest: parameterBundle.parameterDigest,
                valueCount: UInt32(clamping: polynomial.evals.count),
                codewordLength: UInt32(clamping: codeword.count)
            ),
            codeword: codeword,
            merkleLevels: merkleLevels
        )
    }

    private func buildCodeword(
        polynomial: MultilinearPoly,
        context: MetalContext?,
        traceCollector: MetalTraceCollector?,
        label: SpartanOracleID
    ) throws -> [Fq] {
        _ = traceCollector
        _ = label
        let base = polynomial.evals.isEmpty ? [Fq.zero] : polynomial.evals
        let codewordLength = max(1, base.count * codewordBlowup)

        guard let context else {
            return (0..<codewordLength).map { base[$0 % base.count] }
        }

        return try autoreleasepool {
            guard let evalBuffer = context.uploadFieldElements(base),
                  let codewordBuffer = context.makeSharedBuffer(
                    length: codewordLength * MemoryLayout<UInt32>.size * 2
                  ) else {
                throw NuMetalError.heapCreationFailed
            }

            let dispatcher = KernelDispatcher(context: context)
            try dispatcher.dispatchSealEncode(
                evalBuffer: evalBuffer,
                codewordBuffer: codewordBuffer,
                n: base.count,
                blowup: codewordBlowup
            )

            let pointer = codewordBuffer.contents().bindMemory(to: UInt32.self, capacity: codewordLength * 2)
            let packed = Array(UnsafeBufferPointer(start: pointer, count: codewordLength * 2))
            return MetalFieldPacking.unpackFieldElementsSoA(packed, count: codewordLength)
        }
    }

    private func buildMerkleLevels(
        codeword: [Fq],
        context: MetalContext?,
        traceCollector: MetalTraceCollector?,
        label: SpartanOracleID
    ) throws -> [[[UInt8]]] {
        _ = traceCollector
        _ = label
        guard let context else {
            return cpuMerkleLevels(codeword: codeword)
        }

        let codewordLength = max(1, codeword.count)
        var levels = [[[UInt8]]]()
        var currentLevel = try autoreleasepool { () throws -> [[UInt8]] in
            guard let codewordBuffer = context.uploadFieldElements(codeword),
                  let leafBuffer = context.makeSharedBuffer(length: codewordLength * 32) else {
                throw NuMetalError.heapCreationFailed
            }

            let dispatcher = KernelDispatcher(context: context)
            try dispatcher.dispatchMerkleHash(
                leavesBuffer: codewordBuffer,
                nodesBuffer: leafBuffer,
                numLeaves: codewordLength
            )

            return readHashLevel(from: leafBuffer, count: codewordLength)
        }
        levels.append(currentLevel)

        while currentLevel.count > 1 {
            if currentLevel.count % 2 != 0, let last = currentLevel.last {
                currentLevel.append(last)
            }
            let parentCount = currentLevel.count / 2
            currentLevel = try autoreleasepool { () throws -> [[UInt8]] in
                guard let childBuffer = context.makeSharedBuffer(length: currentLevel.count * 32),
                      let parentBuffer = context.makeSharedBuffer(length: parentCount * 32) else {
                    throw NuMetalError.heapCreationFailed
                }
                writeHashLevel(currentLevel, to: childBuffer)
                let dispatcher = KernelDispatcher(context: context)
                try dispatcher.dispatchMerkleParent(
                    childBuffer: childBuffer,
                    parentBuffer: parentBuffer,
                    numParents: parentCount
                )
                return readHashLevel(from: parentBuffer, count: parentCount)
            }
            levels.append(currentLevel)
        }

        return levels
    }

    private func cpuMerkleLevels(codeword: [Fq]) -> [[[UInt8]]] {
        var levels = [codeword.map(leafHash)]
        var current = levels[0]
        while current.count > 1 {
            if current.count % 2 != 0, let last = current.last {
                current.append(last)
            }
            current = stride(from: 0, to: current.count, by: 2).map {
                parentHash(left: current[$0], right: current[$0 + 1])
            }
            levels.append(current)
        }
        return levels
    }

    private func readHashLevel(from buffer: MTLBuffer, count: Int) -> [[UInt8]] {
        let pointer = buffer.contents().bindMemory(to: UInt32.self, capacity: count * 8)
        return (0..<count).map { hashIndex in
            var bytes = [UInt8]()
            bytes.reserveCapacity(32)
            let base = hashIndex * 8
            for wordOffset in 0..<8 {
                let word = pointer[base + wordOffset].bigEndian
                withUnsafeBytes(of: word) { bytes.append(contentsOf: $0) }
            }
            return bytes
        }
    }

    private func writeHashLevel(_ hashes: [[UInt8]], to buffer: MTLBuffer) {
        let pointer = buffer.contents().bindMemory(to: UInt32.self, capacity: hashes.count * 8)
        for (hashIndex, hash) in hashes.enumerated() {
            precondition(hash.count == 32)
            for wordOffset in 0..<8 {
                let start = wordOffset * 4
                let word = hash[start..<(start + 4)].withUnsafeBytes { raw -> UInt32 in
                    raw.load(as: UInt32.self).bigEndian
                }
                pointer[hashIndex * 8 + wordOffset] = word
            }
        }
    }

    private func leafHash(_ value: Fq) -> [UInt8] {
        let payload = Data([0x00] + value.toBytes())
        return Array(SHA256.hash(data: payload))
    }

    private func parentHash(left: [UInt8], right: [UInt8]) -> [UInt8] {
        Array(SHA256.hash(data: Data(left + right)))
    }

    private func queryIndex(
        point: [Fq],
        oracle: SpartanOracleID,
        codewordLength: Int
    ) -> Int {
        precondition(codewordLength > 0)
        let bytes = point.flatMap { $0.toBytes() } + Array(pointKey(oracle).utf8)
        let digestBytes = digest(bytes, domain: "NuMeQ.Decider.Hachi.QueryIndex")
        let value = digestBytes.prefix(8).enumerated().reduce(UInt64(0)) { partial, pair in
            partial | (UInt64(pair.element) << (UInt64(pair.offset) * 8))
        }
        return Int(value % UInt64(codewordLength))
    }

    func scheduleDigest(
        point: [Fq],
        oracles: [SpartanOracleID],
        batchSeedDigest: [UInt8]
    ) -> [UInt8] {
        var bytes = batchSeedDigest
        bytes.append(contentsOf: point.flatMap { $0.toBytes() })
        for oracle in oracles.sorted(by: { pointKey($0) < pointKey($1) }) {
            bytes.append(contentsOf: pointKey(oracle).utf8)
        }
        return digest(bytes, domain: "NuMeQ.Decider.Hachi.Schedule")
    }

    func pointDigest(_ point: [Fq]) -> [UInt8] {
        digest(
            point.flatMap { $0.toBytes() },
            domain: "NuMeQ.Decider.Hachi.Point"
        )
    }

    func evaluationDigest(_ evaluation: Fq) -> [UInt8] {
        digest(
            evaluation.toBytes(),
            domain: "NuMeQ.Decider.Hachi.Eval"
        )
    }

    func tableDigest(_ polynomial: MultilinearPoly) -> [UInt8] {
        digest(
            polynomial.evals.flatMap { $0.toBytes() },
            domain: "NuMeQ.Decider.Hachi.Table"
        )
    }

    private func digest(_ bytes: [UInt8], domain: String) -> [UInt8] {
        NuSealCShake256.cshake256(
            data: Data(bytes),
            domain: domain,
            count: 32
        )
    }

    func pointKey(_ point: [Fq]) -> String {
        point.map { String($0.v) }.joined(separator: ":")
    }

    func pointKey(_ oracle: SpartanOracleID) -> String {
        "\(oracle.kind.rawValue):\(oracle.index ?? -1)"
    }

    private func oracleTracePrefix(for oracle: SpartanOracleID) -> String {
        "seal.verify.oracle[\(pointKey(oracle))]"
    }

    private func compareCommitment(
        provided: HachiPCSCommitment,
        expected: HachiPCSCommitment,
        diagnostics: inout HachiVerificationDiagnostics
    ) -> Bool {
        for diff in diffCommitments(expected: expected, actual: provided) {
            diagnostics.recordArtifactDiff(
                oracle: diff.oracle,
                component: diff.component,
                detail: diff.detail
            )
            return false
        }
        return true
    }

    private func diffArtifacts(
        expected: HachiPCSOracleArtifact,
        actual: HachiPCSOracleArtifact
    ) -> [HachiPCSArtifactDiff] {
        let commitmentDiffs = diffCommitments(
            expected: expected.commitment,
            actual: actual.commitment
        )
        if commitmentDiffs.isEmpty == false {
            return commitmentDiffs
        }
        if expected.codeword != actual.codeword {
            return [
                HachiPCSArtifactDiff(
                    oracle: expected.commitment.oracle,
                    component: "codeword",
                    detail: "CPU and Metal codewords diverged"
                )
            ]
        }
        if expected.merkleLevels != actual.merkleLevels {
            return [
                HachiPCSArtifactDiff(
                    oracle: expected.commitment.oracle,
                    component: "merkleLevels",
                    detail: "CPU and Metal Merkle levels diverged"
                )
            ]
        }
        return []
    }

    private func diffCommitments(
        expected: HachiPCSCommitment,
        actual: HachiPCSCommitment
    ) -> [HachiPCSArtifactDiff] {
        let oracle = expected.oracle
        guard actual.oracle == expected.oracle else {
            return [
                HachiPCSArtifactDiff(
                    oracle: oracle,
                    component: "oracle",
                    detail: "expected \(pointKey(expected.oracle)), got \(pointKey(actual.oracle))"
                )
            ]
        }
        if actual.tableCommitment != expected.tableCommitment {
            return [HachiPCSArtifactDiff(oracle: oracle, component: "tableCommitment", detail: "commitment mismatch")]
        }
        if actual.tableDigest != expected.tableDigest {
            return [HachiPCSArtifactDiff(oracle: oracle, component: "tableDigest", detail: "digest mismatch")]
        }
        if actual.merkleRoot != expected.merkleRoot {
            return [HachiPCSArtifactDiff(oracle: oracle, component: "merkleRoot", detail: "root mismatch")]
        }
        if actual.parameterDigest != expected.parameterDigest {
            return [HachiPCSArtifactDiff(oracle: oracle, component: "parameterDigest", detail: "parameter digest mismatch")]
        }
        if actual.valueCount != expected.valueCount {
            return [HachiPCSArtifactDiff(oracle: oracle, component: "valueCount", detail: "expected \(expected.valueCount), got \(actual.valueCount)")]
        }
        if actual.codewordLength != expected.codewordLength {
            return [HachiPCSArtifactDiff(oracle: oracle, component: "codewordLength", detail: "expected \(expected.codewordLength), got \(actual.codewordLength)")]
        }
        return []
    }

    private func verifyAuthenticationPath(
        opening: HachiPCSOpening,
        commitment: HachiPCSCommitment
    ) -> Bool {
        var current = leafHash(opening.codewordValue)
        var index = Int(opening.codewordIndex)
        for sibling in opening.merkleAuthenticationPath {
            if index % 2 == 0 {
                current = parentHash(left: current, right: sibling)
            } else {
                current = parentHash(left: sibling, right: current)
            }
            index /= 2
        }
        return current == commitment.merkleRoot
    }
}

private struct HachiPCSOracleArtifact {
    let commitment: HachiPCSCommitment
    let codeword: [Fq]
    let merkleLevels: [[[UInt8]]]

    func authenticationPath(for leafIndex: Int) -> [[UInt8]] {
        guard merkleLevels.isEmpty == false else { return [] }
        var index = leafIndex
        var path = [[UInt8]]()
        for level in merkleLevels.dropLast() {
            let siblingIndex = index ^ 1
            let safeIndex = siblingIndex < level.count ? siblingIndex : index
            path.append(level[safeIndex])
            index /= 2
        }
        return path
    }
}
