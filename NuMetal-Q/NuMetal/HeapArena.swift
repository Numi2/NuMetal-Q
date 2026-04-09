import Foundation
@preconcurrency import Metal

/// A typed slice into an arena-backed Metal buffer.
public struct MetalBufferSlice: @unchecked Sendable {
    public let buffer: MTLBuffer
    public let offset: Int
    public let length: Int

    public init(buffer: MTLBuffer, offset: Int, length: Int) {
        self.buffer = buffer
        self.offset = offset
        self.length = length
    }

    public func typedContents<T>(as type: T.Type, capacity: Int) -> UnsafeMutablePointer<T> {
        buffer.contents()
            .advanced(by: offset)
            .bindMemory(to: T.self, capacity: capacity)
    }
}

/// Persistent heap-backed linear allocator.
///
/// Chunks come from a Metal heap. Individual proving passes suballocate slices
/// from those chunks and then reset the cursors, so the heap footprint
/// stabilizes after warmup instead of growing with every proof round.
public final class HeapArena: @unchecked Sendable {
    private struct Chunk {
        let buffer: MTLBuffer
        var cursor: Int
    }

    private let heap: MTLHeap
    private let device: MTLDevice
    private let options: MTLResourceOptions
    private let defaultChunkSize: Int
    private var chunks: [Chunk] = []

    public init(
        heap: MTLHeap,
        device: MTLDevice,
        options: MTLResourceOptions,
        defaultChunkSize: Int
    ) {
        self.heap = heap
        self.device = device
        self.options = options
        self.defaultChunkSize = defaultChunkSize
    }

    public func allocate(length: Int, alignment: Int = 256) -> MetalBufferSlice? {
        let alignedLength = Self.align(length, to: alignment)
        guard alignedLength > 0 else {
            return nil
        }

        for index in chunks.indices {
            let start = Self.align(chunks[index].cursor, to: alignment)
            if start + alignedLength <= chunks[index].buffer.length {
                chunks[index].cursor = start + alignedLength
                return MetalBufferSlice(
                    buffer: chunks[index].buffer,
                    offset: start,
                    length: alignedLength
                )
            }
        }

        let chunkLength = max(defaultChunkSize, alignedLength)
        guard let buffer = heap.makeBuffer(length: chunkLength, options: options)
            ?? device.makeBuffer(length: chunkLength, options: options) else {
            return nil
        }
        chunks.append(Chunk(buffer: buffer, cursor: alignedLength))
        return MetalBufferSlice(buffer: buffer, offset: 0, length: alignedLength)
    }

    public func reset() {
        for index in chunks.indices {
            chunks[index].cursor = 0
        }
    }

    public var allocatedChunkCount: Int {
        chunks.count
    }

    private static func align(_ value: Int, to alignment: Int) -> Int {
        let mask = alignment - 1
        return (value + mask) & ~mask
    }
}

/// Shared view over the persistent shared/private arenas for one proving pass.
public struct MetalTransientArena: @unchecked Sendable {
    private let sharedArena: HeapArena
    private let privateArena: HeapArena

    init(sharedArena: HeapArena, privateArena: HeapArena) {
        self.sharedArena = sharedArena
        self.privateArena = privateArena
    }

    public func makeSharedSlice(length: Int, alignment: Int = 256) -> MetalBufferSlice? {
        sharedArena.allocate(length: length, alignment: alignment)
    }

    public func makePrivateSlice(length: Int, alignment: Int = 256) -> MetalBufferSlice? {
        privateArena.allocate(length: length, alignment: alignment)
    }

    public func uploadFieldElements(_ elements: [Fq]) -> MetalBufferSlice? {
        uploadFieldElementsSoA(elements)
    }

    public func uploadFieldElementsSoA(_ elements: [Fq], paddedTo count: Int? = nil) -> MetalBufferSlice? {
        let storage = MetalFieldPacking.packFieldElementsSoA(elements, paddedTo: count)
        guard let slice = makeSharedSlice(length: storage.count * MemoryLayout<UInt32>.size) else {
            return nil
        }
        let pointer = slice.typedContents(as: UInt32.self, capacity: storage.count)
        for (index, value) in storage.enumerated() {
            pointer[index] = value
        }
        return slice
    }

    public func uploadAjtaiKeyRingCoefficients(_ key: AjtaiKey) -> MetalBufferSlice? {
        let count = key.keys.count * RingElement.degree
        guard let slice = makeSharedSlice(length: count * MemoryLayout<UInt64>.size) else {
            return nil
        }
        let pointer = slice.typedContents(as: UInt64.self, capacity: count)
        for (ringIndex, ring) in key.keys.enumerated() {
            for coeffIndex in 0..<RingElement.degree {
                pointer[ringIndex * RingElement.degree + coeffIndex] = ring.coeffs[coeffIndex].v
            }
        }
        return slice
    }

    public func uploadAjtaiRotationRowsSoA(_ key: AjtaiKey) -> MetalBufferSlice? {
        let storage = MetalFieldPacking.packDenseRotationRowsSoA(for: key)
        guard let slice = makeSharedSlice(length: storage.count * MemoryLayout<UInt32>.size) else {
            return nil
        }
        let pointer = slice.typedContents(as: UInt32.self, capacity: storage.count)
        for (index, value) in storage.enumerated() {
            pointer[index] = value
        }
        return slice
    }

    public func uploadRingElements(_ rings: [RingElement], paddedTo count: Int? = nil) -> MetalBufferSlice? {
        uploadRingElementsSoA(rings, paddedTo: count)
    }

    public func uploadRingElementsSoA(_ rings: [RingElement], paddedTo count: Int? = nil) -> MetalBufferSlice? {
        let storage = MetalFieldPacking.packRingElementsSoA(rings, paddedTo: count)
        guard let slice = makeSharedSlice(length: storage.count * MemoryLayout<UInt32>.size) else {
            return nil
        }
        let pointer = slice.typedContents(as: UInt32.self, capacity: storage.count)
        for (index, value) in storage.enumerated() {
            pointer[index] = value
        }
        return slice
    }

    public func uploadRingBatchSoA(
        _ batches: [[RingElement]],
        paddedInnerCount: Int? = nil
    ) -> MetalBufferSlice? {
        let storage = MetalFieldPacking.packRingBatchSoA(batches, paddedInnerCount: paddedInnerCount)
        guard let slice = makeSharedSlice(length: storage.count * MemoryLayout<UInt32>.size) else {
            return nil
        }
        let pointer = slice.typedContents(as: UInt32.self, capacity: storage.count)
        for (index, value) in storage.enumerated() {
            pointer[index] = value
        }
        return slice
    }
}
