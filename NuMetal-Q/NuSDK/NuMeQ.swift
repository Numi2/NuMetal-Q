import Foundation
import CryptoKit

// MARK: - NuMeQ Public SDK
// The public API surface for NuMeQ.
// Idiomatic Swift. Zero-knowledge by default.
// Seed, fuse, seal, verify, and resume operations over the canonical proving stack.

/// NuMeQ: Post-quantum zero-knowledge proof-carrying data engine.
///
/// Entry point for all NuMeQ operations. Manages the fold engine,
/// compiled terminal decider, cluster connectivity, and policy enforcement.
///
/// ## Usage
///
/// ```swift
/// let engine = try await NuMeQ()
/// let ctx = engine.createContext(compiledShape: compiledShape)
/// let handle = await ctx.seed(witness: myWitness, publicInputs: inputs)
/// let export = try await ctx.seal(
///     handle,
///     sessionKey: sessionKey,
///     signEnvelope: { try mldsa87.sign($0) }
/// )
/// ```
public actor NuMeQ {
    private let profile: NuProfile
    private let params: NuParams
    private let foldEngine: FoldEngine
    private let sealBackend: any NuSealCompiler
    private let scheduler: ProverScheduler
    private var metalContext: MetalContext?

    /// Create a new NuMeQ engine instance bound to the canonical searched one-stack AG64 profile.
    public init() async throws {
        let profile = NuProfile.canonical
        let config = FoldConfig.canonical

        // Validate profile before proceeding
        let validation = profile.validate()
        guard validation.isValid else {
            throw NuMeQError.invalidProfile(validation.errors)
        }

        self.profile = profile
        self.params = NuParams.derive(from: profile)
        self.foldEngine = FoldEngine(config: config, seed: profile.foldParameterSeed)
        self.sealBackend = SealEngine()
        self.scheduler = ProverScheduler()

        let ctx = try MetalContext()
        self.metalContext = ctx
        await foldEngine.setMetalContext(ctx)
        await sealBackend.setMetalContext(ctx)
    }

    // MARK: - Context Creation

    /// Create a proof context from a verified signed ShapePack bundle.
    public func createContext(
        compiledShape: CompiledShape,
        policy: NuPolicy = .standard,
        appID: String = Bundle.main.bundleIdentifier ?? "numeq",
        teamID: String = "numeq.team",
        attestationVerifier: AttestationVerifier? = nil
    ) -> ProofContext {
        ProofContext(
            compiledShape: compiledShape,
            foldEngine: foldEngine,
            sealBackend: sealBackend,
            vault: FoldVault(),
            profile: profile,
            policy: policy,
            appID: appID,
            teamID: teamID,
            attestationVerifier: attestationVerifier
        )
    }

    // MARK: - Top-Level Verify

    /// Verify a ProofEnvelope against a compiled shape.
    ///
    /// This is a standalone verification entry point that does not
    /// require a ProofContext or any prover state.
    public func verify(
        envelope: ProofEnvelope,
        compiledShape: CompiledShape,
        verifySignature: PQKeyedVerifyClosure,
        attestationVerifier: AttestationVerifier? = nil,
        requireAttestation: Bool = false,
        sessionKey: SymmetricKey? = nil
    ) async throws -> VerificationResult {
        try await verify(
            envelope: envelope,
            compiledShape: compiledShape,
            verifySignature: verifySignature,
            attestationVerifier: attestationVerifier,
            requireAttestation: requireAttestation,
            sessionKey: sessionKey,
            executionMode: .automatic,
            traceCollector: nil
        )
    }

    package func verify(
        envelope: ProofEnvelope,
        compiledShape: CompiledShape,
        verifySignature: PQKeyedVerifyClosure,
        attestationVerifier: AttestationVerifier? = nil,
        requireAttestation: Bool = false,
        sessionKey: SymmetricKey? = nil,
        executionMode: VerificationExecutionMode,
        traceCollector: MetalTraceCollector?
    ) async throws -> VerificationResult {
        do {
            try envelope.validateCryptographicFormat()
        } catch let error as ProofEnvelopeValidationError {
            return VerificationResult(
                isValid: false,
                reason: verificationFailure(for: error)
            )
        }

        // Signature check
        guard try envelope.isSignatureValid(verify: verifySignature) else {
            return VerificationResult(isValid: false, reason: .signatureInvalid)
        }

        // Shape binding
        guard envelope.shapeDigest == compiledShape.shape.digest else {
            return VerificationResult(isValid: false, reason: .shapeMismatch)
        }

        // Profile binding
        guard envelope.profileID == profile.profileID else {
            return VerificationResult(isValid: false, reason: .profileMismatch)
        }

        // Backend binding
        guard envelope.sealBackendID == sealBackend.backendID else {
            return VerificationResult(isValid: false, reason: .backendMismatch)
        }
        guard envelope.sealParamDigest == Data(params.seal.parameterDigest) else {
            return VerificationResult(isValid: false, reason: .proofInvalid)
        }

        if requireAttestation || (attestationVerifier != nil && envelope.attestation != nil) {
            guard let attestation = envelope.attestation, attestation.isEmpty == false else {
                return VerificationResult(isValid: false, reason: .attestationRequired)
            }
            guard let attestationVerifier else {
                return VerificationResult(isValid: false, reason: .attestationVerifierMissing)
            }
            let context = AttestationContext(
                purpose: .envelopeVerification,
                appID: envelope.appID,
                shapeDigest: envelope.shapeDigest,
                signerKeyID: envelope.signerKeyID,
                timestamp: envelope.timestamp,
                payloadDigest: NuSecurityDigest.sha256(envelope.attestationBindingPayload())
            )
            do {
                guard try attestationVerifier(attestation, context) else {
                    return VerificationResult(isValid: false, reason: .attestationInvalid)
                }
            } catch {
                return VerificationResult(isValid: false, reason: .attestationInvalid)
            }
        }

        _ = sessionKey

        let proof: PublicSealProof
        do {
            proof = try envelope.proof()
        } catch {
            return VerificationResult(isValid: false, reason: .proofInvalid)
        }
        guard publicStatementMatchesHeader(
            publicHeader: envelope.publicHeaderBytes,
            publicInputs: proof.statement.publicInputs,
            shape: compiledShape.shape
        ) else {
            return VerificationResult(isValid: false, reason: .proofInvalid)
        }
        guard await sealBackend.verify(
            proof: proof,
            shape: compiledShape.shape,
            publicHeader: envelope.publicHeaderBytes,
            executionMode: executionMode,
            traceCollector: traceCollector
        ) else {
            return VerificationResult(isValid: false, reason: .proofInvalid)
        }

        return VerificationResult(isValid: true, reason: nil)
    }

    public func verify(
        envelope: ProofEnvelope,
        compiledShape: CompiledShape,
        verifySignature: PQVerifyClosure,
        attestationVerifier: AttestationVerifier? = nil,
        requireAttestation: Bool = false,
        sessionKey: SymmetricKey? = nil
    ) async throws -> VerificationResult {
        try await verify(
            envelope: envelope,
            compiledShape: compiledShape,
            verifySignature: { message, signature, _ in
                try verifySignature(message, signature)
            },
            attestationVerifier: attestationVerifier,
            requireAttestation: requireAttestation,
            sessionKey: sessionKey
        )
    }

    // MARK: - Profile & Params

    /// The active cryptographic profile.
    public var activeProfile: NuProfile { profile }

    /// The derived public parameters.
    public var publicParams: NuParams { params }

    /// Generate the machine-checkable profile certificate that freezes the
    /// AG64 field tower, decider contract, schedule invariants, and release gate.
    public func generateCertificate() -> ProfileCertificate {
        ProfileCertificate.generate(for: profile)
    }

    // MARK: - Cluster

    /// Start a cluster session as the principal (iPhone).
    public func startClusterAsPrincipal(
        fragmentSigner: @escaping @Sendable (Data) throws -> Data,
        peerVerifier: @escaping PQVerifyClosure,
        attestationVerifier: AttestationVerifier? = nil
    ) -> ClusterSession {
        ClusterSession(
            role: .principal,
            fragmentSigner: fragmentSigner,
            peerVerifier: peerVerifier,
            attestationVerifier: attestationVerifier
        )
    }

    /// Start a cluster session as a co-prover (MacBook).
    public func startClusterAsCoProver(
        fragmentSigner: @escaping @Sendable (Data) throws -> Data,
        peerVerifier: @escaping PQVerifyClosure,
        attestationVerifier: AttestationVerifier? = nil
    ) -> ClusterSession {
        ClusterSession(
            role: .coProver,
            fragmentSigner: fragmentSigner,
            peerVerifier: peerVerifier,
            attestationVerifier: attestationVerifier
        )
    }

    /// Standard typed cluster executor bound to this engine's Metal context.
    ///
    /// This executor handles:
    /// - sanitized witness packing and Ajtai commitments for delegated fold input preparation
    /// - PiDEC decomposition work packets
    /// - Lightning PCS commit/open work packets
    public func clusterWorkExecutor() -> ClusterWorkExecutor {
        ClusterWorkExecutor.standard(metalContext: metalContext)
    }

    // MARK: - Device Info

    /// Canonical scheduler parameters for the production proving pipeline.
    public var schedulerParams: SchedulerParams {
        scheduler.productionParams()
    }

    /// Whether GPU acceleration is available.
    public var hasGPU: Bool { metalContext != nil }
}

public enum NuMeQError: Error, Sendable {
    case invalidProfile([String])
    case metalInitFailed
    case vaultLocked
}
