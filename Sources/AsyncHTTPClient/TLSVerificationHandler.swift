//===----------------------------------------------------------------------===//
//
// This source file is part of the AsyncHTTPClient open source project
//
// Copyright (c) 2026 Apple Inc. and the AsyncHTTPClient project authors
// Licensed under Apache License v2.0
//
// See LICENSE.txt for license information
// See CONTRIBUTORS.txt for the list of AsyncHTTPClient project authors
//
// SPDX-License-Identifier: Apache-2.0
//
//===----------------------------------------------------------------------===//

import NIOCore
import NIOSSL

/// A per-request hook that replaces the default TLS certificate verification on the connection
/// a request is executed on.
///
/// Because verification logic applies to a whole connection rather than a single request,
/// requests carrying different handlers never share a connection: ``identity`` participates in
/// the connection pool key. Requests carrying equal identities may share a connection, so the
/// identity must capture everything that makes two verification policies behave differently.
///
/// Setting a handler overrides *all* verification logic that BoringSSL would otherwise perform,
/// so the handler is solely responsible for deciding whether the peer is trusted.
///
/// - Warning: This API is not guaranteed to be stable and is likely to change without further
///   notice, hence the underscore prefix.
public struct _TLSVerificationHandler: Sendable {
    /// A value identifying this verification logic, used to partition the connection pool.
    public var identity: any Hashable & Sendable

    /// Verifies the certificate chain presented by the peer.
    ///
    /// The certificates are exactly as presented by the peer: NIOSSL has not pre-processed or
    /// validated them in any way.
    public var verify: @Sendable ([NIOSSLCertificate]) async throws -> NIOSSLVerificationResult

    public init(
        identity: any Hashable & Sendable,
        verify: @escaping @Sendable ([NIOSSLCertificate]) async throws -> NIOSSLVerificationResult
    ) {
        self.identity = identity
        self.verify = verify
    }
}

extension _TLSVerificationHandler: Hashable {
    public static func == (lhs: _TLSVerificationHandler, rhs: _TLSVerificationHandler) -> Bool {
        eraseToAnyHashable(lhs.identity) == eraseToAnyHashable(rhs.identity)
    }

    public func hash(into hasher: inout Hasher) {
        hasher.combine(eraseToAnyHashable(self.identity))
    }
}

/// Erases a `Hashable` existential without storing an `AnyHashable`, which is not `Sendable`.
private func eraseToAnyHashable(_ value: some Hashable) -> AnyHashable {
    AnyHashable(value)
}

extension _TLSVerificationHandler {
    /// Adapts ``verify`` to the callback shape NIOSSL expects.
    func makeCustomVerificationCallback() -> NIOSSLCustomVerificationCallback {
        let verify = self.verify
        return { certificates, promise in
            promise.completeWithTask {
                try await verify(certificates)
            }
        }
    }
}
