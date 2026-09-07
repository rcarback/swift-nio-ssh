// SPDX-License-Identifier: Apache-2.0

import CCryptoBoringSSL
import Crypto

/// Adapter to swift-crypto's vendored FIPS 203 implementation. CryptoExtras
/// links this backend on Apple platforms too, where Crypto's public MLKEM API
/// otherwise requires iOS 26. Package.swift pins the internal C ABI to 4.5.2.
/// No primitive or random-number generator is implemented here.
enum PortableMLKEM768 {
    final class PrivateKey {
        private let key: UnsafeMutablePointer<MLKEM768_private_key>
        let publicKey: [UInt8]

        init() {
            self.key = .allocate(capacity: 1)
            self.key.initialize(to: .init())
            var publicKey = [UInt8](repeating: 0, count: 1184)
            CCryptoBoringSSL_MLKEM768_generate_key(&publicKey, nil, self.key)
            self.publicKey = publicKey
        }

        deinit {
            CCryptoBoringSSL_OPENSSL_cleanse(self.key, MemoryLayout<MLKEM768_private_key>.size)
            self.key.deinitialize(count: 1)
            self.key.deallocate()
        }

        func decapsulate(_ ciphertext: [UInt8]) throws -> SymmetricKey {
            var secret = [UInt8](repeating: 0, count: 32)
            defer { secret.withUnsafeMutableBytes { CCryptoBoringSSL_OPENSSL_cleanse($0.baseAddress, $0.count) } }
            guard CCryptoBoringSSL_MLKEM768_decap(&secret, ciphertext, ciphertext.count, self.key) == 1 else {
                throw CryptoKitError.incorrectParameterSize
            }
            return SymmetricKey(data: secret)
        }
    }

    static func encapsulate(to publicKey: [UInt8]) throws -> (ciphertext: [UInt8], sharedSecret: SymmetricKey) {
        var key = MLKEM768_public_key()
        try publicKey.withUnsafeBufferPointer { bytes in
            var input = CBS(data: bytes.baseAddress, len: bytes.count)
            guard CCryptoBoringSSL_MLKEM768_parse_public_key(&key, &input) == 1 else {
                throw CryptoKitError.incorrectParameterSize
            }
        }
        var ciphertext = [UInt8](repeating: 0, count: 1088)
        var secret = [UInt8](repeating: 0, count: 32)
        defer { secret.withUnsafeMutableBytes { CCryptoBoringSSL_OPENSSL_cleanse($0.baseAddress, $0.count) } }
        CCryptoBoringSSL_MLKEM768_encap(&ciphertext, &secret, &key)
        return (ciphertext, SymmetricKey(data: secret))
    }
}
