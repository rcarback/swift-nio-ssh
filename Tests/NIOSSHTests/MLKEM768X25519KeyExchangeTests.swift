import Crypto
import NIOCore
import XCTest

@testable import NIOSSH

final class MLKEM768X25519KeyExchangeTests: XCTestCase {
    let allocator = ByteBufferAllocator()
    let hostKey = NIOSSHPrivateKey(ed25519Key: .init())
    var clientRole: SSHConnectionRole {
        .client(.init(userAuthDelegate: ExplodingAuthDelegate(), serverAuthDelegate: AcceptAllHostKeysDelegate()))
    }
    var serverRole: SSHConnectionRole {
        .server(.init(hostKeys: [hostKey], userAuthDelegate: DenyAllServerAuthDelegate()))
    }
    func testRoundTripAndRekey() throws {
        var sessionID: ByteBuffer?
        var previousInit: ByteBuffer?
        var previousKey: SymmetricKey?
        for _ in 0..<3 {
            var client = MLKEM768X25519KeyExchange(ourRole: clientRole, previousSessionIdentifier: sessionID)
            var server = MLKEM768X25519KeyExchange(ourRole: serverRole, previousSessionIdentifier: sessionID)
            let request = try client.initiateKeyExchangeClientSide(allocator: allocator)
            XCTAssertEqual(request.publicKey.readableBytes, 1216)
            XCTAssertNotEqual(request.publicKey, previousInit)
            previousInit = request.publicKey
            var serverTranscript = allocator.buffer(capacity: 4096)
            let (serverKeys, reply) = try server.completeKeyExchangeServerSide(
                clientKeyExchangeMessage: request,
                serverHostKey: hostKey,
                initialExchangeBytes: &serverTranscript,
                allocator: allocator,
                expectedKeySizes: AES256GCMOpenSSHTransportProtection.keySizes
            )
            XCTAssertEqual(reply.publicKey.readableBytes, 1120)
            var clientTranscript = allocator.buffer(capacity: 4096)
            let clientKeys = try client.receiveServerKeyExchangePayload(
                serverKeyExchangeMessage: reply,
                initialExchangeBytes: &clientTranscript,
                allocator: allocator,
                expectedKeySizes: AES256GCMOpenSSHTransportProtection.keySizes
            )
            XCTAssertEqual(serverKeys.sessionID, clientKeys.sessionID)
            if let sessionID { XCTAssertEqual(clientKeys.sessionID, sessionID) }
            sessionID = clientKeys.sessionID
            XCTAssertEqual(clientKeys.keys.outboundEncryptionKey, serverKeys.keys.inboundEncryptionKey)
            XCTAssertEqual(clientKeys.keys.inboundEncryptionKey, serverKeys.keys.outboundEncryptionKey)
            XCTAssertEqual(clientKeys.keys.initialOutboundIV, serverKeys.keys.initialInboundIV)
            XCTAssertEqual(clientKeys.keys.initialInboundIV, serverKeys.keys.initialOutboundIV)
            XCTAssertEqual(clientKeys.keys.outboundMACKey, serverKeys.keys.inboundMACKey)
            XCTAssertNotEqual(clientKeys.keys.outboundEncryptionKey, previousKey)
            previousKey = clientKeys.keys.outboundEncryptionKey
            XCTAssertThrowsError(
                try client.receiveServerKeyExchangePayload(
                    serverKeyExchangeMessage: reply,
                    initialExchangeBytes: &clientTranscript,
                    allocator: allocator,
                    expectedKeySizes: AES256GCMOpenSSHTransportProtection.keySizes
                )
            )
        }
    }
    func testRejectsMalformedClientPayloads() throws {
        var client = MLKEM768X25519KeyExchange(ourRole: clientRole, previousSessionIdentifier: nil)
        let valid = try client.initiateKeyExchangeClientSide(allocator: allocator).publicKey
        var lowOrder = valid
        lowOrder.setBytes(Array(repeating: UInt8(0), count: 32), at: 1184)
        var invalidKEM = valid
        invalidKEM.setBytes([0xff, 0xff, 0xff], at: 0)
        var extra = valid
        extra.writeInteger(UInt8(0))
        for payload in [
            allocator.buffer(capacity: 0), valid.getSlice(at: 0, length: 1215)!, extra, lowOrder, invalidKEM,
        ] {
            var server = MLKEM768X25519KeyExchange(ourRole: serverRole, previousSessionIdentifier: nil)
            var transcript = allocator.buffer(capacity: 4096)
            XCTAssertThrowsError(
                try server.completeKeyExchangeServerSide(
                    clientKeyExchangeMessage: .init(publicKey: payload),
                    serverHostKey: hostKey,
                    initialExchangeBytes: &transcript,
                    allocator: allocator,
                    expectedKeySizes: AES128GCMOpenSSHTransportProtection.keySizes
                )
            )
        }
    }
    func testRejectsMalformedServerPayloadsAndTampering() throws {
        for mode in 0..<5 {
            var client = MLKEM768X25519KeyExchange(ourRole: clientRole, previousSessionIdentifier: nil)
            var server = MLKEM768X25519KeyExchange(ourRole: serverRole, previousSessionIdentifier: nil)
            let request = try client.initiateKeyExchangeClientSide(allocator: allocator)
            var transcript = allocator.buffer(capacity: 4096)
            var (_, reply) = try server.completeKeyExchangeServerSide(
                clientKeyExchangeMessage: request,
                serverHostKey: hostKey,
                initialExchangeBytes: &transcript,
                allocator: allocator,
                expectedKeySizes: AES128GCMOpenSSHTransportProtection.keySizes
            )
            switch mode {
            case 0: reply.publicKey.moveWriterIndex(to: 1119)
            case 1: reply.publicKey.writeInteger(UInt8(0))
            case 2: reply.publicKey.setBytes(Array(repeating: UInt8(0), count: 32), at: 1088)
            case 3: reply.publicKey.setInteger(reply.publicKey.getInteger(at: 0, as: UInt8.self)! ^ 1, at: 0)
            default: reply.hostKey = NIOSSHPrivateKey(ed25519Key: .init()).publicKey
            }
            transcript.clear()
            XCTAssertThrowsError(
                try client.receiveServerKeyExchangePayload(
                    serverKeyExchangeMessage: reply,
                    initialExchangeBytes: &transcript,
                    allocator: allocator,
                    expectedKeySizes: AES128GCMOpenSSHTransportProtection.keySizes
                )
            )
        }
    }
    func testSecretEncodingRetainsLeadingZeroAndHighBit() {
        for leading: UInt8 in [0, 0x80, 0xff] {
            let secret = [leading] + Array(repeating: UInt8(0x12), count: 31)
            var actual = SHA256()
            actual.updateHybridSSHSecret(SymmetricKey(data: secret))
            XCTAssertEqual(actual.finalize(), SHA256.hash(data: [0, 0, 0, 32] + secret))
        }
    }
}
