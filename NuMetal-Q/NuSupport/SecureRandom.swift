import Foundation
import Security

internal enum NuSecureRandomError: Error, Sendable {
    case generationFailed(OSStatus)
}

internal enum NuSecureRandom {
    static func bytes(count: Int) throws -> [UInt8] {
        guard count > 0 else { return [] }
        var bytes = [UInt8](repeating: 0, count: count)
        let status = bytes.withUnsafeMutableBytes { buffer in
            SecRandomCopyBytes(kSecRandomDefault, count, buffer.baseAddress!)
        }
        guard status == errSecSuccess else {
            throw NuSecureRandomError.generationFailed(status)
        }
        return bytes
    }
}
