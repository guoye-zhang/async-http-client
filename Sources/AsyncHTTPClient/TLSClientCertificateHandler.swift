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

#if canImport(Security)
import Security
#endif

/// A per-request hook that supplies a client certificate when the server asks for one during
/// the TLS handshake.
///
/// The handler is only consulted if the server sends a `CertificateRequest`, so a server that
/// does not ask for client authentication never triggers it. Because the certificate applies to
/// a whole connection rather than a single request, requests carrying different handlers never
/// share a connection: ``identity`` participates in the connection pool key.
///
/// The two transports take different identity forms, so ``provide`` is told which transport is
/// asking through ``Challenge/transport`` and must answer with an ``Identity`` of the matching
/// form. On NIOSSL, throwing or a mismatched identity fails the handshake. Network.framework
/// cannot fail the handshake from this point, so there both continue without a certificate.
///
/// - Warning: This API is not guaranteed to be stable and is likely to change without further
///   notice, hence the underscore prefix.
public struct _TLSClientCertificateHandler: Sendable {
    /// Describes a server's request for a client certificate.
    public struct Challenge: Sendable {
        /// The TLS implementation performing the handshake.
        public enum Transport: Hashable, Sendable {
            /// SwiftNIO SSL on top of BoringSSL. It takes ``Identity/init(certificateChain:privateKey:)``.
            case nioSSL
            /// Network.framework. It takes ``Identity/init(secIdentity:certificateChain:)``.
            case networkFramework
        }

        /// The TLS implementation performing the handshake.
        public var transport: Transport

        /// The DER-encoded distinguished names of the certificate authorities the server accepts.
        ///
        /// NIOSSL does not expose them, so this is always empty on ``Transport/nioSSL``.
        public var distinguishedNames: [[UInt8]]
    }

    /// A client certificate chain together with the private key matching its leaf, in the form a
    /// particular transport consumes.
    public struct Identity: Sendable {
        enum Storage: @unchecked Sendable {
            case nioSSL(certificateChain: [NIOSSLCertificate], privateKey: NIOSSLPrivateKey)
            #if canImport(Security)
            // Security objects are immutable once created and safe to use from any thread.
            case secIdentity(SecIdentity, certificateChain: [SecCertificate])
            #endif
        }

        let storage: Storage

        /// An identity for the NIOSSL transport.
        ///
        /// - Parameters:
        ///   - certificateChain: The certificate chain, starting with the leaf certificate.
        ///   - privateKey: The private key matching the leaf certificate.
        public init(certificateChain: [NIOSSLCertificate], privateKey: NIOSSLPrivateKey) {
            self.storage = .nioSSL(certificateChain: certificateChain, privateKey: privateKey)
        }

        #if canImport(Security)
        /// An identity for the Network.framework transport.
        ///
        /// - Parameters:
        ///   - secIdentity: The identity holding the leaf certificate and its private key.
        ///   - certificateChain: The certificate chain to send, starting with the leaf certificate.
        public init(secIdentity: SecIdentity, certificateChain: [SecCertificate]) {
            self.storage = .secIdentity(secIdentity, certificateChain: certificateChain)
        }
        #endif
    }

    /// The error a NIOSSL handshake fails with when ``provide`` answers with an ``Identity`` the
    /// transport cannot use.
    public struct IdentityTransportMismatchError: Error, Hashable, CustomStringConvertible {
        public var transport: Challenge.Transport

        public var description: String {
            "_TLSClientCertificateHandler provided an identity that the \(self.transport) transport cannot use."
        }
    }

    /// A value identifying this certificate selection logic, used to partition the connection
    /// pool.
    public var identity: any Hashable & Sendable

    /// Provides the client identity to present, or `nil` to continue without one.
    public var provide: @Sendable (Challenge) async throws -> Identity?

    public init(
        identity: any Hashable & Sendable,
        provide: @escaping @Sendable (Challenge) async throws -> Identity?
    ) {
        self.identity = identity
        self.provide = provide
    }
}

extension _TLSClientCertificateHandler: Hashable {
    public static func == (lhs: _TLSClientCertificateHandler, rhs: _TLSClientCertificateHandler) -> Bool {
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

extension _TLSClientCertificateHandler {
    /// Adapts ``provide`` to NIOSSL's context callback.
    ///
    /// NIOSSL installs the callback with `SSL_CTX_set_cert_cb`, which BoringSSL only invokes on a
    /// client once the server has requested a certificate.
    func makeSSLContextCallback() -> NIOSSLContextCallback {
        let provide = self.provide
        return { _, promise in
            promise.completeWithTask {
                var override = NIOSSLContextConfigurationOverride()
                let challenge = Challenge(transport: .nioSSL, distinguishedNames: [])
                switch try await provide(challenge)?.storage {
                case .nioSSL(let certificateChain, let privateKey):
                    override.certificateChain = certificateChain.map { .certificate($0) }
                    override.privateKey = .privateKey(privateKey)
                #if canImport(Security)
                case .secIdentity:
                    throw IdentityTransportMismatchError(transport: .nioSSL)
                #endif
                case nil:
                    break
                }
                return override
            }
        }
    }
}
