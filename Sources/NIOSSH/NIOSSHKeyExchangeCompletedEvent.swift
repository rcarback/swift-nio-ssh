// SPDX-License-Identifier: Apache-2.0

/// Fired through the parent channel pipeline when the peer's NEWKEYS message
/// installs negotiated inbound keys, after host signature validation on clients.
/// A fresh event is emitted for each rekey. This does not indicate that user
/// authentication has completed.
public struct NIOSSHKeyExchangeCompletedEvent: Sendable, Equatable {
    public let keyExchangeAlgorithm: String

    public init(keyExchangeAlgorithm: String) {
        self.keyExchangeAlgorithm = keyExchangeAlgorithm
    }
}
