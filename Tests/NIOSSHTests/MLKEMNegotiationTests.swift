import XCTest

@testable import NIOSSH

final class MLKEMNegotiationTests: XCTestCase {
    func testHybridPreferredWhenAvailable() throws {
        XCTAssertEqual(SSHKeyExchangeStateMachine.supportedKeyExchangeAlgorithms.first, "mlkem768x25519-sha256")
        XCTAssertTrue(SSHKeyExchangeStateMachine.supportedKeyExchangeAlgorithms.contains("curve25519-sha256"))
    }
}
