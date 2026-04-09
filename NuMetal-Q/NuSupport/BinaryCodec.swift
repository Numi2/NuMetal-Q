import Foundation

// MARK: - Binary Codec Helpers
// Little-endian helper utilities shared by proof and envelope codecs.

internal enum LittleEndianCodec {
    static func uint64<C: Collection>(from bytes: C) -> UInt64 where C.Element == UInt8 {
        precondition(bytes.count == MemoryLayout<UInt64>.size)
        var value: UInt64 = 0
        var shift: UInt64 = 0
        for byte in bytes {
            value |= UInt64(byte) << shift
            shift &+= 8
        }
        return value
    }
}

internal struct BinaryWriter {
    private(set) var data = Data()

    mutating func append(_ value: UInt8) {
        data.append(value)
    }

    mutating func append(_ value: UInt16) {
        var le = value.littleEndian
        data.append(contentsOf: withUnsafeBytes(of: &le) { Data($0) })
    }

    mutating func append(_ value: UInt32) {
        var le = value.littleEndian
        data.append(contentsOf: withUnsafeBytes(of: &le) { Data($0) })
    }

    mutating func append(_ value: UInt64) {
        var le = value.littleEndian
        data.append(contentsOf: withUnsafeBytes(of: &le) { Data($0) })
    }

    mutating func append(_ value: Double) {
        append(value.bitPattern)
    }

    mutating func append(_ value: Data) {
        data.append(value)
    }

    mutating func appendLengthPrefixed(_ value: [UInt8]) {
        append(UInt32(value.count))
        data.append(contentsOf: value)
    }

    mutating func appendLengthPrefixed(_ value: Data) {
        append(UInt32(value.count))
        data.append(value)
    }
}

internal struct BinaryReader {
    enum Error: Swift.Error, Sendable {
        case truncated
        case invalidData
    }

    private let data: Data
    private var offset: Int = 0

    init(_ data: Data) {
        self.data = data
    }

    var isAtEnd: Bool {
        offset == data.count
    }

    mutating func readUInt8() throws -> UInt8 {
        guard offset + 1 <= data.count else { throw Error.truncated }
        let value = data[offset]
        offset += 1
        return value
    }

    mutating func readUInt16() throws -> UInt16 {
        try readFixedWidthInteger()
    }

    mutating func readUInt32() throws -> UInt32 {
        try readFixedWidthInteger()
    }

    mutating func readUInt64() throws -> UInt64 {
        try readFixedWidthInteger()
    }

    mutating func readDouble() throws -> Double {
        Double(bitPattern: try readUInt64())
    }

    mutating func readData(count: Int) throws -> Data {
        guard offset + count <= data.count else { throw Error.truncated }
        let out = data[offset..<offset + count]
        offset += count
        return Data(out)
    }

    mutating func readLengthPrefixedData() throws -> Data {
        let count = try Int(readUInt32())
        return try readData(count: count)
    }

    mutating func readLengthPrefixedBytes() throws -> [UInt8] {
        Array(try readLengthPrefixedData())
    }

    private mutating func readFixedWidthInteger<T: FixedWidthInteger>() throws -> T {
        let count = MemoryLayout<T>.size
        guard offset + count <= data.count else { throw Error.truncated }
        let value = data[offset..<offset + count].withUnsafeBytes { raw -> T in
            raw.loadUnaligned(as: T.self)
        }
        offset += count
        return T(littleEndian: value)
    }
}
