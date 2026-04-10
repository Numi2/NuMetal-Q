import Foundation
import CryptoKit
import Metal

internal enum MetalArtifactBundle {
    static let manifestVersion = 1
    static let shaderNames = [
        "NuAG64Common",
        "NuFieldKernels",
        "NuCommitKernels",
        "NuDirectPackedKernels",
        "NuDecompKernels",
        "NuMatrixKernels",
        "NuSumCheckKernels",
    ]

    static func combinedSource() throws -> String {
        try shaderURLs().map { url in
            try String(contentsOf: url, encoding: .utf8)
        }.joined(separator: "\n\n")
    }

    static func manifestData() throws -> Data {
        let manifest = ArtifactManifest(
            version: manifestVersion,
            storageLayoutVersion: Int(MetalStorageLayout.currentVersion),
            shaders: shaderNames
        )
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys]
        return try encoder.encode(manifest)
    }

    static func artifactDigest() throws -> [UInt8] {
        var payload = Data("NuMeQ.MetalArtifact.v1".utf8)
        payload.append(try manifestData())
        var abiVersion = MetalABI.currentVersion.littleEndian
        payload.append(contentsOf: withUnsafeBytes(of: &abiVersion) { Data($0) })
        payload.append(Data(try combinedSource().utf8))
        return Array(SHA256.hash(data: payload))
    }

    static func artifactDigestHex() throws -> String {
        try artifactDigest().map { String(format: "%02x", $0) }.joined()
    }

    static func makeLibrary(device: MTLDevice) throws -> MTLLibrary {
        if let metallibURL = compiledMetallibURL() {
            return try device.makeLibrary(URL: metallibURL)
        }
        guard allowSourceFallback else {
            throw NuMetalError.libraryNotFound
        }
        return try device.makeLibrary(source: try combinedSource(), options: nil)
    }

    static func compiledMetallibURL() -> URL? {
        #if SWIFT_PACKAGE
        if let bundled = Bundle.module.url(
            forResource: "NuMetal",
            withExtension: "metallib",
            subdirectory: "Compiled"
        ) {
            return bundled
        }
        #endif
        let compiledDirectory = sourceRootDirectory()
            .appendingPathComponent("Compiled", isDirectory: true)
        let local = compiledDirectory.appendingPathComponent("NuMetal.metallib")
        return FileManager.default.fileExists(atPath: local.path) ? local : nil
    }

    private static func shaderURLs() -> [URL] {
        #if SWIFT_PACKAGE
        let bundle = Bundle.module
        let bundled = shaderNames.compactMap {
            bundle.url(forResource: $0, withExtension: "metal", subdirectory: "Shaders")
        }
        if bundled.count == shaderNames.count {
            return bundled
        }
        #endif
        let shaderDirectory = sourceRootDirectory()
            .appendingPathComponent("Shaders", isDirectory: true)
        return shaderNames.map {
            shaderDirectory.appendingPathComponent("\($0).metal")
        }
    }

    private static func sourceRootDirectory() -> URL {
        URL(fileURLWithPath: #filePath).deletingLastPathComponent()
    }

    private static var allowSourceFallback: Bool {
        #if DEBUG
        return true
        #else
        ProcessInfo.processInfo.environment["XCTestConfigurationFilePath"] != nil
        #endif
    }
}

private struct ArtifactManifest: Codable {
    let version: Int
    let storageLayoutVersion: Int
    let shaders: [String]
}
