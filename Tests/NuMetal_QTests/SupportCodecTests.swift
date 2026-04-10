import XCTest
@testable import NuMetal_Q

final class SupportCodecTests: XCTestCase {
    func testBinaryWriterReaderRoundTripsPrimitiveAndLengthPrefixedValues() throws {
        var writer = BinaryWriter()
        writer.append(UInt8(0xA5))
        writer.append(UInt16(0x1234))
        writer.append(UInt32(0x89AB_CDEF))
        writer.append(UInt64(0x0123_4567_89AB_CDEF))
        writer.append(Double(42.5))
        writer.appendLengthPrefixed(Data("NuMetalQ".utf8))
        writer.appendLengthPrefixed([0x01, 0x02, 0x03, 0x04])

        var reader = BinaryReader(writer.data)
        XCTAssertEqual(try reader.readUInt8(), 0xA5)
        XCTAssertEqual(try reader.readUInt16(), 0x1234)
        XCTAssertEqual(try reader.readUInt32(), 0x89AB_CDEF)
        XCTAssertEqual(try reader.readUInt64(), 0x0123_4567_89AB_CDEF)
        XCTAssertEqual(try reader.readDouble(), 42.5)
        XCTAssertEqual(try reader.readLengthPrefixedData(), Data("NuMetalQ".utf8))
        XCTAssertEqual(try reader.readLengthPrefixedBytes(), [0x01, 0x02, 0x03, 0x04])
        XCTAssertTrue(reader.isAtEnd)
    }

    func testBinaryReaderRejectsOversizedLengthPrefixedData() {
        var writer = BinaryWriter()
        writer.append(UInt32(16))
        writer.append(Data(repeating: 0x5A, count: 16))

        var reader = BinaryReader(writer.data)
        XCTAssertThrowsError(
            try reader.readLengthPrefixedData(maxCount: 8)
        ) { error in
            guard let readerError = error as? BinaryReader.Error else {
                return XCTFail("Unexpected error: \(error)")
            }
            XCTAssertEqual(readerError, .invalidData)
        }
    }

    func testLittleEndianCodecMatchesKnownValue() {
        let bytes: [UInt8] = [0xEF, 0xCD, 0xAB, 0x89, 0x67, 0x45, 0x23, 0x01]
        XCTAssertEqual(
            LittleEndianCodec.uint64(from: bytes),
            0x0123_4567_89AB_CDEF
        )
    }

    func testSealCShake256IsDeterministicAndDomainSeparated() {
        let message = Data("NuMetalQ.SupportCodecTests".utf8)
        let a = NuSealCShake256.cshake256(data: message, domain: "NuMetalQ.Tests.A", count: 32)
        let b = NuSealCShake256.cshake256(data: message, domain: "NuMetalQ.Tests.A", count: 32)
        let c = NuSealCShake256.cshake256(data: message, domain: "NuMetalQ.Tests.B", count: 32)

        XCTAssertEqual(a, b)
        XCTAssertNotEqual(a, c)
        XCTAssertEqual(a.count, 32)
    }
}
