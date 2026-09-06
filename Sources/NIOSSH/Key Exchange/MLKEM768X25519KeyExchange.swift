// SPDX-License-Identifier: Apache-2.0

import Crypto
import NIOCore

/// RFC 10042: ML-KEM-768 followed by X25519 on the wire and in the
/// hybrid-secret hash. The resulting K is an SSH string, never an mpint.
struct MLKEM768X25519KeyExchange: EllipticCurveKeyExchangeProtocol {
    private let ourRole: SSHConnectionRole
    private let previousSessionIdentifier: ByteBuffer?
    private var clientState: ClientState?
    private var started = false

    private struct ClientState {
        var mlkem: PortableMLKEM768.PrivateKey
        var x25519: Curve25519.KeyAgreement.PrivateKey
        var payload: ByteBuffer
    }

    init(ourRole: SSHConnectionRole, previousSessionIdentifier: ByteBuffer?) {
        self.ourRole = ourRole
        self.previousSessionIdentifier = previousSessionIdentifier
    }

    static var keyExchangeAlgorithmNames: [Substring] { ["mlkem768x25519-sha256"] }

    private static var invalidPayload: NIOSSHError {
        .protocolViolation(
            protocolName: "mlkem768x25519-sha256",
            violation: "Invalid hybrid key exchange payload or state"
        )
    }

    mutating func initiateKeyExchangeClientSide(
        allocator: ByteBufferAllocator
    ) throws -> SSHMessage.KeyExchangeECDHInitMessage {
        guard self.ourRole.isClient, !self.started else { throw Self.invalidPayload }
        self.started = true
        let mlkem = PortableMLKEM768.PrivateKey()
        let x25519 = Curve25519.KeyAgreement.PrivateKey()
        var payload = allocator.buffer(capacity: 1216)
        payload.writeBytes(mlkem.publicKey)
        payload.writeBytes(x25519.publicKey.rawRepresentation)
        self.clientState = ClientState(mlkem: mlkem, x25519: x25519, payload: payload)
        return .init(publicKey: payload)
    }

    mutating func completeKeyExchangeServerSide(
        clientKeyExchangeMessage message: SSHMessage.KeyExchangeECDHInitMessage,
        serverHostKey: NIOSSHPrivateKey,
        initialExchangeBytes: inout ByteBuffer,
        allocator: ByteBufferAllocator,
        expectedKeySizes: ExpectedKeySizes
    ) throws -> (KeyExchangeResult, SSHMessage.KeyExchangeECDHReplyMessage) {
        guard self.ourRole.isServer, !self.started else { throw Self.invalidPayload }
        self.started = true
        var input = message.publicKey
        guard input.readableBytes == 1216,
            let kemBytes = input.readBytes(length: 1184), let curveBytes = input.readBytes(length: 32)
        else { throw Self.invalidPayload }
        let x25519 = Curve25519.KeyAgreement.PrivateKey()
        let curveSecret = try x25519.sharedSecretFromKeyAgreement(with: .init(rawRepresentation: curveBytes))
        let encapsulated = try PortableMLKEM768.encapsulate(to: kemBytes)
        var payload = allocator.buffer(capacity: 1120)
        payload.writeBytes(encapsulated.ciphertext)
        payload.writeBytes(x25519.publicKey.rawRepresentation)
        let secret = Self.hybridSecret(kem: encapsulated.sharedSecret, curve: curveSecret)
        let (result, hash) = self.finalize(
            secret: secret,
            client: message.publicKey,
            server: payload,
            hostKey: serverHostKey.publicKey,
            transcript: &initialExchangeBytes,
            allocator: allocator,
            sizes: expectedKeySizes
        )
        return (
            result,
            .init(hostKey: serverHostKey.publicKey, publicKey: payload, signature: try serverHostKey.sign(digest: hash))
        )
    }

    mutating func receiveServerKeyExchangePayload(
        serverKeyExchangeMessage message: SSHMessage.KeyExchangeECDHReplyMessage,
        initialExchangeBytes: inout ByteBuffer,
        allocator: ByteBufferAllocator,
        expectedKeySizes: ExpectedKeySizes
    ) throws -> KeyExchangeResult {
        guard self.ourRole.isClient, let state = self.clientState else { throw Self.invalidPayload }
        // Consume ephemeral state even on a malformed reply; no second decapsulation.
        self.clientState = nil
        var input = message.publicKey
        guard input.readableBytes == 1120,
            let ciphertext = input.readBytes(length: 1088), let curveBytes = input.readBytes(length: 32)
        else { throw Self.invalidPayload }
        let curveSecret = try state.x25519.sharedSecretFromKeyAgreement(with: .init(rawRepresentation: curveBytes))
        let kemSecret = try state.mlkem.decapsulate(ciphertext)
        let secret = Self.hybridSecret(kem: kemSecret, curve: curveSecret)
        let (result, hash) = self.finalize(
            secret: secret,
            client: state.payload,
            server: message.publicKey,
            hostKey: message.hostKey,
            transcript: &initialExchangeBytes,
            allocator: allocator,
            sizes: expectedKeySizes
        )
        guard message.hostKey.isValidSignature(message.signature, for: hash) else {
            throw NIOSSHError.invalidExchangeHashSignature
        }
        return result
    }

    private static func hybridSecret(kem: SymmetricKey, curve: SharedSecret) -> SymmetricKey {
        var hash = SHA256()
        kem.withUnsafeBytes { hash.update(bufferPointer: $0) }
        curve.withUnsafeBytes { hash.update(bufferPointer: $0) }
        return SymmetricKey(data: hash.finalize())
    }

    private func finalize(
        secret: SymmetricKey,
        client: ByteBuffer,
        server: ByteBuffer,
        hostKey: NIOSSHPublicKey,
        transcript: inout ByteBuffer,
        allocator: ByteBufferAllocator,
        sizes: ExpectedKeySizes
    ) -> (KeyExchangeResult, SHA256.Digest) {
        transcript.writeCompositeSSHString { $0.writeSSHHostKey(hostKey) }
        transcript.writeSSHString(client.readableBytesView)
        transcript.writeSSHString(server.readableBytesView)
        var hash = SHA256()
        hash.update(data: transcript.readableBytesView)
        hash.updateHybridSSHSecret(secret)
        let exchangeHash = hash.finalize()
        var newSession = allocator.buffer(capacity: 32)
        newSession.writeBytes(exchangeHash)
        let sessionID = self.previousSessionIdentifier ?? newSession
        var base = SHA256()
        base.updateHybridSSHSecret(secret)
        exchangeHash.withUnsafeBytes { base.update(bufferPointer: $0) }
        func derive(_ discriminator: UInt8, _ count: Int) -> [UInt8] {
            var hash = base
            hash.update(data: [discriminator])
            hash.update(data: sessionID.readableBytesView)
            var bytes = Array(hash.finalize())
            while bytes.count < count {
                var next = base
                next.update(data: bytes)
                bytes.append(contentsOf: next.finalize())
            }
            return Array(bytes.prefix(count))
        }
        let inbound: UInt8 = self.ourRole.isClient ? 66 : 65
        let outbound: UInt8 = self.ourRole.isClient ? 65 : 66
        let keys = NIOSSHSessionKeys(
            initialInboundIV: derive(inbound, sizes.ivSize),
            initialOutboundIV: derive(outbound, sizes.ivSize),
            inboundEncryptionKey: SymmetricKey(data: derive(inbound + 2, sizes.encryptionKeySize)),
            outboundEncryptionKey: SymmetricKey(data: derive(outbound + 2, sizes.encryptionKeySize)),
            inboundMACKey: SymmetricKey(data: derive(inbound + 4, sizes.macKeySize)),
            outboundMACKey: SymmetricKey(data: derive(outbound + 4, sizes.macKeySize))
        )
        return (KeyExchangeResult(sessionID: sessionID, keys: keys), exchangeHash)
    }
}

extension SHA256 {
    /// RFC 10042 section 2.5: retain every secret byte, with a uint32 length.
    mutating func updateHybridSSHSecret(_ secret: SymmetricKey) {
        secret.withUnsafeBytes { bytes in
            var length = UInt32(bytes.count).bigEndian
            withUnsafeBytes(of: &length) { self.update(bufferPointer: $0) }
            self.update(bufferPointer: bytes)
        }
    }
}
