import XCTest
@testable import NuMetal_Q

final class BackgroundAuthorizationTests: XCTestCase {
    func testBackgroundAuthorizationRequiresExplicitOptIn() {
        XCTAssertThrowsError(
            try ProverBackgroundAuthorization.validate(
                infoDictionary: [
                    ProverBackgroundRequirements.permittedIdentifiersInfoKey: [
                        ProverBackgroundRequirements.sealTaskIdentifier
                    ]
                ]
            )
        ) { error in
            XCTAssertEqual(
                error as? ProverBackgroundAuthorizationError,
                .missingBackgroundGPUOptIn(ProverBackgroundRequirements.backgroundGPUOptInInfoKey)
            )
        }
    }

    func testBackgroundAuthorizationRequiresPermittedTaskIdentifier() {
        XCTAssertThrowsError(
            try ProverBackgroundAuthorization.validate(
                infoDictionary: [
                    ProverBackgroundRequirements.backgroundGPUOptInInfoKey: true,
                    ProverBackgroundRequirements.permittedIdentifiersInfoKey: []
                ]
            )
        ) { error in
            XCTAssertEqual(
                error as? ProverBackgroundAuthorizationError,
                .missingPermittedTaskIdentifier(ProverBackgroundRequirements.sealTaskIdentifier)
            )
        }
    }

    func testBackgroundAuthorizationAcceptsDocumentedConfiguration() throws {
        let authorization = try ProverBackgroundAuthorization.validate(
            infoDictionary: [
                ProverBackgroundRequirements.backgroundGPUOptInInfoKey: true,
                ProverBackgroundRequirements.permittedIdentifiersInfoKey: [
                    ProverBackgroundRequirements.sealTaskIdentifier
                ]
            ]
        )

        XCTAssertEqual(authorization.taskIdentifier, ProverBackgroundRequirements.sealTaskIdentifier)
    }
}
