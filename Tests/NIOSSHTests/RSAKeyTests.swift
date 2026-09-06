import Crypto
import NIOCore
import XCTest
import _CryptoExtras

@testable import NIOSSH

final class RSAKeyTests: XCTestCase {
    func testRSAPublicKeyUsesSSHRSABlobAndOnlySHA2Algorithms() throws {
        let key = NIOSSHPrivateKey(rsaKey: try _RSA.Signing.PrivateKey(keySize: .bits2048))
        XCTAssertEqual(String(key.publicKey.keyPrefix), "ssh-rsa")
        XCTAssertEqual(key.hostKeyAlgorithms, ["rsa-sha2-512", "rsa-sha2-256"])
        var buffer = ByteBufferAllocator().buffer(capacity: 512)
        buffer.writeSSHHostKey(key.publicKey)
        XCTAssertEqual(try buffer.readSSHHostKey(), key.publicKey)
    }

    func testRSAAuthenticationUsesSelectedSHA2Algorithm() throws {
        let key = NIOSSHPrivateKey(rsaKey: try _RSA.Signing.PrivateKey(keySize: .bits2048))
        for algorithm in [RSASignatureAlgorithm.sha512, .sha256] {
            let payload = UserAuthSignablePayload(
                sessionIdentifier: ByteBuffer(bytes: [1, 2, 3]),
                userName: "user",
                serviceName: "ssh-connection",
                publicKey: key.publicKey,
                rsaSignatureAlgorithm: algorithm
            )
            let signature = try key.sign(payload, rsaSignatureAlgorithm: algorithm)
            XCTAssertTrue(key.publicKey.isValidSignature(signature, for: payload))
            var buffer = ByteBufferAllocator().buffer(capacity: 512)
            buffer.writeSSHSignature(signature)
            XCTAssertEqual(
                buffer.getSSHString(at: buffer.readerIndex)?.readableBytesView.map { $0 },
                Array(algorithm.algorithmName.utf8)
            )
            XCTAssertTrue(key.publicKey.isValidSignature(try XCTUnwrap(buffer.readSSHSignature()), for: payload))
        }
    }

    func testSHA1SignatureAlgorithmIsRejected() throws {
        XCTAssertNil(RSASignatureAlgorithm(algorithmName: "ssh-rsa".utf8))
        var buffer = ByteBufferAllocator().buffer(capacity: 64)
        buffer.writeSSHString("ssh-rsa".utf8)
        buffer.writeSSHString([UInt8](repeating: 0, count: 32))
        XCTAssertThrowsError(try buffer.readSSHSignature())
    }
    func testHostSignatureHashesExchangeHashWithNegotiatedAlgorithm() throws {
        let rsa = try _RSA.Signing.PrivateKey(keySize: .bits2048)
        let key = NIOSSHPrivateKey(rsaKey: rsa)
        let exchangeHash = SHA384.hash(data: [1, 2, 3])
        for algorithm in [RSASignatureAlgorithm.sha512, .sha256] {
            let signature = try key.sign(digest: exchangeHash, rsaSignatureAlgorithm: algorithm)
            XCTAssertEqual(signature.rsaSignatureAlgorithm, algorithm)
            switch signature.backingSignature {
            case .rsaSHA512(let raw):
                XCTAssertTrue(
                    rsa.publicKey.isValidSignature(
                        raw,
                        for: SHA512.hash(data: Array(exchangeHash)),
                        padding: .insecurePKCS1v1_5
                    )
                )
            case .rsaSHA256(let raw):
                XCTAssertTrue(
                    rsa.publicKey.isValidSignature(
                        raw,
                        for: SHA256.hash(data: Array(exchangeHash)),
                        padding: .insecurePKCS1v1_5
                    )
                )
            default: XCTFail("Expected RSA signature")
            }
            XCTAssertTrue(key.publicKey.isValidSignature(signature, for: exchangeHash))
            XCTAssertFalse(key.publicKey.isValidSignature(signature, for: SHA384.hash(data: [4, 5, 6])))
        }
    }

    func testRSAAuthenticationMessagesRoundTripAndRejectAlgorithmMismatch() throws {
        let key = NIOSSHPrivateKey(rsaKey: try _RSA.Signing.PrivateKey(keySize: .bits2048))
        for algorithm in [RSASignatureAlgorithm.sha512, .sha256] {
            let payload = UserAuthSignablePayload(
                sessionIdentifier: ByteBuffer(bytes: [1]),
                userName: "user",
                serviceName: "ssh-connection",
                publicKey: key.publicKey,
                rsaSignatureAlgorithm: algorithm
            )
            let signature = try key.sign(payload, rsaSignatureAlgorithm: algorithm)
            for sig in [nil, signature] {
                let message = SSHMessage.userAuthRequest(
                    .init(
                        username: "user",
                        service: "ssh-connection",
                        method: .publicKey(.known(key: key.publicKey, signature: sig, rsaSignatureAlgorithm: algorithm))
                    )
                )
                var buffer = ByteBufferAllocator().buffer(capacity: 1024)
                buffer.writeSSHMessage(message)
                XCTAssertEqual(try buffer.readSSHMessage(), message)
            }
            let ok = SSHMessage.userAuthPKOK(.init(key: key.publicKey, rsaSignatureAlgorithm: algorithm))
            var okBuffer = ByteBufferAllocator().buffer(capacity: 512)
            okBuffer.writeSSHMessage(ok)
            XCTAssertEqual(try okBuffer.readSSHMessage(), ok)
            let mismatched = SSHMessage.userAuthRequest(
                .init(
                    username: "user",
                    service: "ssh-connection",
                    method: .publicKey(
                        .known(
                            key: key.publicKey,
                            signature: signature,
                            rsaSignatureAlgorithm: algorithm == .sha512 ? .sha256 : .sha512
                        )
                    )
                )
            )
            var badBuffer = ByteBufferAllocator().buffer(capacity: 1024)
            badBuffer.writeSSHMessage(mismatched)
            XCTAssertThrowsError(try badBuffer.readSSHMessage())
        }
    }

    func testRSAHostAndUserAuthenticationEndToEnd() throws {
        let key = NIOSSHPrivateKey(rsaKey: try _RSA.Signing.PrivateKey(keySize: .bits2048))
        var harness = TestHarness()
        harness.serverHostKeys = [key]
        harness.clientAuthDelegate = PrivateKeyClientAuth(key)
        harness.serverAuthDelegate = ExpectPublicKeyAuth(key.publicKey)
        let channel = BackToBackEmbeddedChannel()
        defer { XCTAssertNoThrow(try channel.finish()) }
        try channel.configureWithHarness(harness)
        try channel.activate()
        try channel.interactInMemory()
        _ = try channel.createNewChannel()
        try channel.interactInMemory()
        XCTAssertEqual(channel.activeServerChannels.count, 1)
    }

    func testNegativeRSAMPIntIsRejected() throws {
        var buffer = ByteBufferAllocator().buffer(capacity: 512)
        buffer.writeSSHString("ssh-rsa".utf8)
        buffer.writeSSHString([UInt8](arrayLiteral: 1, 0, 1))
        buffer.writeSSHString([UInt8](repeating: 255, count: 256))
        XCTAssertThrowsError(try buffer.readSSHHostKey())
    }

}
