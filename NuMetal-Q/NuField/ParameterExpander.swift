import Foundation
import CryptoKit

// MARK: - NuParameterExpander
// Artifact-layer SHA-256 expander for public parameters, certificates, and
// deterministic bundles. This never participates in proof Fiat-Shamir.

internal enum NuParameterExpander {
    static func expandBytes(
        domain: String,
        seed: [UInt8],
        label: String = "",
        count: Int
    ) -> [UInt8] {
        precondition(count >= 0)

        var output = [UInt8]()
        output.reserveCapacity(count)

        var counter: UInt32 = 0
        while output.count < count {
            let digest = blockDigest(
                domain: domain,
                seed: seed,
                label: label,
                counter: counter
            )
            let take = min(digest.count, count - output.count)
            output.append(contentsOf: digest.prefix(take))
            counter &+= 1
        }

        return output
    }

    static func expandFieldElements(
        domain: String,
        seed: [UInt8],
        label: String = "",
        count: Int
    ) -> [Fq] {
        let bytes = expandBytes(
            domain: domain,
            seed: seed,
            label: label,
            count: count * 16
        )

        return (0..<count).map { index in
            let start = index * 16
            let lo = UInt64(littleEndianBytes: Array(bytes[start..<start + 8]))
            let hi = UInt64(littleEndianBytes: Array(bytes[start + 8..<start + 16]))
            return Fq.reduceFull(hi: hi, lo: lo)
        }
    }

    private static func blockDigest(
        domain: String,
        seed: [UInt8],
        label: String,
        counter: UInt32
    ) -> [UInt8] {
        var data = Data()
        appendLengthPrefixed(Data(domain.utf8), to: &data)
        appendLengthPrefixed(Data(seed), to: &data)
        appendLengthPrefixed(Data(label.utf8), to: &data)

        var ctr = counter.littleEndian
        data.append(withUnsafeBytes(of: &ctr) { Data($0) })

        return Array(SHA256.hash(data: data))
    }

    private static func appendLengthPrefixed(_ value: Data, to data: inout Data) {
        var length = UInt32(value.count).littleEndian
        data.append(withUnsafeBytes(of: &length) { Data($0) })
        data.append(value)
    }
}

private extension UInt64 {
    init(littleEndianBytes bytes: [UInt8]) {
        precondition(bytes.count == 8)
        self = LittleEndianCodec.uint64(from: bytes)
    }
}
