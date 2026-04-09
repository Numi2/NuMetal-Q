import Foundation

// MARK: - NuSeal Backend
// Production NuMeQ exports one public-verifier terminal proof over the
// terminal SuperNeo accumulator. Hachi remains only the multilinear PCS
// substrate behind the exported seal relation.

internal protocol NuSealBackend: Sendable {
    var backendID: String { get }
    func verify(
        proof: PublicSealProof,
        shape: Shape,
        publicHeader: Data
    ) async -> Bool
    func verify(
        proof: PublicSealProof,
        shape: Shape,
        publicHeader: Data,
        executionMode: VerificationExecutionMode,
        traceCollector: MetalTraceCollector?
    ) async -> Bool
}

internal protocol NuSealCompiler: NuSealBackend {
    func seal(
        state: FoldState,
        shape: Shape,
        publicHeader: Data
    ) async throws -> PublicSealProof

    func sealUsingCluster(
        state: FoldState,
        shape: Shape,
        publicHeader: Data,
        clusterSession: ClusterSession,
        attestation: Data,
        dispatchFragment: @Sendable (JobFragment) async throws -> FragmentResult
    ) async throws -> PublicSealProof

    func setMetalContext(_ context: MetalContext) async
}
