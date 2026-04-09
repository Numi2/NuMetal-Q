import Foundation

// MARK: - Header / Step Typed Transitions
// Frozen style public API: typed headers, typed steps, logical seed/fuse,
// and a typed PCD handle backed by an internal FoldState.

public typealias NuWitness = Witness

/// Protocol for typed public headers.
///
/// Headers are the public boundary object for an in-flight recursive proof.
/// They must serialize deterministically because the CPU transcript and the
/// persisted `FoldState` both bind against these bytes.
public protocol NuHeader: Sendable {
    /// Canonical public bytes for transcript binding and CPU-side verification.
    func toBytes() -> [UInt8]

    /// Public inputs for the CCS relation associated with this header.
    var publicInputs: [Fq] { get }

    /// The compiled shape digest this header belongs to.
    var shapeDigest: ShapeDigest { get }

    /// Reconstruct a header from persisted bytes and public inputs.
    static func decode(
        bytes: [UInt8],
        publicInputs: [Fq],
        shapeDigest: ShapeDigest
    ) throws -> Self
}

/// Protocol for a typed recursive step.
///
/// `seed` creates a leaf PCD for the step. `fuse` combines two child PCDs while
/// preserving the public binary API and allowing the prover to batch work
/// internally into larger physical fold epochs.
public protocol NuStep: Sendable {
    associatedtype Witness: Sendable
    associatedtype Left: NuHeader
    associatedtype Right: NuHeader
    associatedtype Output: NuHeader

    /// Stable identifier used to recover a registered step verifier after vault resume.
    var stepID: String { get }

    /// Verified compiled shape bundle used for this step's fold path.
    var compiledShape: CompiledShape { get }

    /// Materialize the public header for a seed node.
    func seedHeader(loweredWitness: NuWitness) throws -> Output

    /// Materialize the public header for a fused node.
    func fuseHeader(
        loweredWitness: NuWitness,
        left: Left,
        right: Right
    ) throws -> Output

    /// Lower a typed step witness into normalized lane data.
    ///
    /// The result must already respect the lane-width contract from `numeqc`.
    func lowerWitness(_ witness: Witness) throws -> NuWitness
}

public extension NuStep {
    var stepID: String { String(reflecting: Self.self) }
}

/// Typed handle to a vault-backed recursive fold state.
///
/// This is not a seal proof. It is a typed reference to the internal
/// accumulator state owned by `MetalFoldProver`.
public struct Pcd<Header: NuHeader>: Sendable, Hashable {
    public let chainID: UUID
    public let header: Header
    public let shapeDigest: ShapeDigest

    public init(chainID: UUID, header: Header, shapeDigest: ShapeDigest) {
        self.chainID = chainID
        self.header = header
        self.shapeDigest = shapeDigest
    }

    public static func == (lhs: Pcd<Header>, rhs: Pcd<Header>) -> Bool {
        lhs.chainID == rhs.chainID && lhs.shapeDigest == rhs.shapeDigest
    }

    public func hash(into hasher: inout Hasher) {
        hasher.combine(chainID)
        hasher.combine(shapeDigest)
    }
}

// MARK: - DAG Metadata

/// A node in the non-uniform proof DAG.
public enum DAGNode: Sendable {
    case seed(shapeDigest: ShapeDigest, headerBytes: [UInt8])
    case step(shapeDigest: ShapeDigest, headerBytes: [UInt8], inputs: [DAGNodeRef])
}

/// Reference to a DAG node by index.
public struct DAGNodeRef: Sendable, Hashable {
    public let index: UInt32

    public init(_ index: UInt32) {
        self.index = index
    }
}

/// The full computation DAG for a typed PCD build.
public struct ProofDAG: Sendable {
    public var nodes: [DAGNode]

    public init() {
        self.nodes = []
    }

    @discardableResult
    public mutating func addSeed(shapeDigest: ShapeDigest, headerBytes: [UInt8]) -> DAGNodeRef {
        let ref = DAGNodeRef(UInt32(nodes.count))
        nodes.append(.seed(shapeDigest: shapeDigest, headerBytes: headerBytes))
        return ref
    }

    @discardableResult
    public mutating func addStep(
        shapeDigest: ShapeDigest,
        headerBytes: [UInt8],
        inputs: [DAGNodeRef]
    ) -> DAGNodeRef {
        let ref = DAGNodeRef(UInt32(nodes.count))
        nodes.append(.step(shapeDigest: shapeDigest, headerBytes: headerBytes, inputs: inputs))
        return ref
    }

    public func topologicalOrder() -> [DAGNodeRef] {
        var visited = Set<UInt32>()
        var order = [DAGNodeRef]()

        func visit(_ ref: DAGNodeRef) {
            guard visited.insert(ref.index).inserted else {
                return
            }

            if case .step(_, _, let inputs) = nodes[Int(ref.index)] {
                for input in inputs {
                    visit(input)
                }
            }
            order.append(ref)
        }

        for index in 0..<UInt32(nodes.count) {
            visit(DAGNodeRef(index))
        }
        return order
    }
}
