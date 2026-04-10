import Foundation

// MARK: - Canonical Metal ABI
// Versioned host/device layout for the Metal-first proving path.

public enum MetalABI {
    public static let currentVersion: UInt16 = 1
}

public enum MetalStorageLayout {
    public static let currentVersion: UInt16 = 3
    public static let threadExecutionWidthMultiple: UInt8 = 1
    public static let laneTile: UInt16 = UInt16(RingElement.degree)
    public static let matrixRowTile: UInt16 = UInt16(RingElement.degree)
    public static let defaultSealChunkSize: UInt32 = 1024
    public static let defaultMerkleChunkSize: UInt32 = 256
}

public struct PackedFqLimbPair: Sendable, Equatable {
    public let lo: UInt32
    public let hi: UInt32

    public init(lo: UInt32, hi: UInt32) {
        self.lo = lo
        self.hi = hi
    }
}

public struct PackedFq2LimbPairs: Sendable, Equatable {
    public let a: PackedFqLimbPair
    public let b: PackedFqLimbPair

    public init(a: PackedFqLimbPair, b: PackedFqLimbPair) {
        self.a = a
        self.b = b
    }
}

public enum MetalFieldPacking {
    public static func pack(_ value: Fq) -> PackedFqLimbPair {
        PackedFqLimbPair(
            lo: UInt32(truncatingIfNeeded: value.v),
            hi: UInt32(truncatingIfNeeded: value.v >> 32)
        )
    }

    public static func unpack(_ value: PackedFqLimbPair) -> Fq {
        Fq(raw: (UInt64(value.hi) << 32) | UInt64(value.lo))
    }

    public static func pack(_ value: Fq2) -> PackedFq2LimbPairs {
        PackedFq2LimbPairs(a: pack(value.a), b: pack(value.b))
    }

    public static func packFieldElementsSoA(
        _ values: [Fq],
        paddedTo paddedCount: Int? = nil
    ) -> [UInt32] {
        let count = paddedCount ?? values.count
        var output = [UInt32](repeating: 0, count: max(0, count) * 2)
        for index in 0..<min(values.count, count) {
            let packed = pack(values[index])
            output[index] = packed.lo
            output[count + index] = packed.hi
        }
        return output
    }

    public static func unpackFieldElementsSoA(
        _ storage: [UInt32],
        count: Int
    ) -> [Fq] {
        guard count > 0 else { return [] }
        precondition(storage.count >= count * 2)
        return (0..<count).map { index in
            unpack(PackedFqLimbPair(lo: storage[index], hi: storage[count + index]))
        }
    }

    public static func packFq2SoA(
        _ values: [Fq2],
        paddedTo paddedCount: Int? = nil
    ) -> [UInt32] {
        let count = paddedCount ?? values.count
        var output = [UInt32](repeating: 0, count: max(0, count) * 4)
        for index in 0..<min(values.count, count) {
            let packed = pack(values[index])
            output[index] = packed.a.lo
            output[count + index] = packed.a.hi
            output[(2 * count) + index] = packed.b.lo
            output[(3 * count) + index] = packed.b.hi
        }
        return output
    }

    public static func packRingElementsSoA(
        _ rings: [RingElement],
        paddedTo paddedCount: Int? = nil
    ) -> [UInt32] {
        let ringCount = paddedCount ?? rings.count
        let tile = RingElement.degree
        let valueCount = max(0, ringCount) * tile
        var output = [UInt32](repeating: 0, count: valueCount * 2)
        for ringIndex in 0..<min(rings.count, ringCount) {
            for lane in 0..<tile {
                let linearIndex = ringIndex * tile + lane
                let packed = pack(rings[ringIndex].coeffs[lane])
                output[linearIndex] = packed.lo
                output[valueCount + linearIndex] = packed.hi
            }
        }
        return output
    }

    public static func unpackRingElementsSoA(
        _ storage: [UInt32],
        ringCount: Int
    ) -> [RingElement] {
        guard ringCount > 0 else { return [] }
        let tile = RingElement.degree
        let valueCount = ringCount * tile
        precondition(storage.count >= valueCount * 2)
        return (0..<ringCount).map { ringIndex in
            let coeffs = (0..<tile).map { lane in
                let linearIndex = ringIndex * tile + lane
                return unpack(
                    PackedFqLimbPair(
                        lo: storage[linearIndex],
                        hi: storage[valueCount + linearIndex]
                    )
                )
            }
            return RingElement(coeffs: coeffs)
        }
    }

    public static func packRingBatchSoA(
        _ batches: [[RingElement]],
        paddedInnerCount: Int? = nil
    ) -> [UInt32] {
        let innerCount = paddedInnerCount ?? (batches.map(\.count).max() ?? 0)
        let flattened = batches.flatMap { batch in
            batch + [RingElement](repeating: .zero, count: max(0, innerCount - batch.count))
        }
        return packRingElementsSoA(flattened, paddedTo: batches.count * innerCount)
    }

    public static func packDenseRotationRowsSoA(for key: AjtaiKey) -> [UInt32] {
        let rowCount = key.slotCount * RingElement.degree * RingElement.degree
        var output = [UInt32](repeating: 0, count: rowCount * 2)
        var cursor = 0
        for ring in key.keys {
            let rotation = RotationMatrix(element: ring)
            for row in rotation.rows {
                for value in row {
                    let packed = pack(value)
                    output[cursor] = packed.lo
                    output[rowCount + cursor] = packed.hi
                    cursor += 1
                }
            }
        }
        return output
    }
}

internal enum TiledMatrixPacking {
    static func packRowTiledCSR(_ matrix: SparseMatrix) -> Data {
        let tileHeight = Int(MetalStorageLayout.matrixRowTile)
        let tileCount = matrix.rows == 0 ? 0 : (matrix.rows + tileHeight - 1) / tileHeight
        var writer = BinaryWriter()
        writer.append(UInt32(clamping: matrix.rows))
        writer.append(UInt32(clamping: matrix.cols))
        writer.append(UInt32(clamping: tileCount))

        for tileIndex in 0..<tileCount {
            let rowStart = tileIndex * tileHeight
            let rowEnd = min(rowStart + tileHeight, matrix.rows)
            let tileRowCount = rowEnd - rowStart
            let tileNNZStart = Int(matrix.rowPtr[rowStart])
            let tileNNZEnd = Int(matrix.rowPtr[rowEnd])
            writer.append(UInt32(clamping: rowStart))
            writer.append(UInt32(clamping: tileRowCount))
            writer.append(UInt32(clamping: tileNNZEnd - tileNNZStart))

            for row in rowStart...rowEnd {
                writer.append(matrix.rowPtr[row] &- UInt32(tileNNZStart))
            }
            for index in tileNNZStart..<tileNNZEnd {
                writer.append(matrix.colIdx[index])
            }
            for index in tileNNZStart..<tileNNZEnd {
                writer.append(Data(matrix.values[index].toBytes()))
            }
        }

        return writer.data
    }
}
