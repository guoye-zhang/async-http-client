//===----------------------------------------------------------------------===//
//
// This source file is part of the AsyncHTTPClient open source project
//
// Copyright (c) 2020 Apple Inc. and the AsyncHTTPClient project authors
// Licensed under Apache License v2.0
//
// See LICENSE.txt for license information
// See CONTRIBUTORS.txt for the list of AsyncHTTPClient project authors
//
// SPDX-License-Identifier: Apache-2.0
//
//===----------------------------------------------------------------------===//

#if canImport(Network)

#if canImport(FoundationEssentials)
import FoundationEssentials
#else
import Foundation
#endif
import Dispatch
import Network
import NIOCore
import NIOSSL
import NIOTransportServices

extension TLSVersion {
    /// return Network framework TLS protocol version
    @available(macOS 10.15, iOS 13.0, tvOS 13.0, watchOS 6.0, *)
    var nwTLSProtocolVersion: tls_protocol_version_t {
        switch self {
        case .tlsv1:
            return .TLSv10
        case .tlsv11:
            return .TLSv11
        case .tlsv12:
            return .TLSv12
        case .tlsv13:
            return .TLSv13
        }
    }
}

extension TLSVersion {
    /// return as SSL protocol
    @available(macOS, deprecated: 10.15, message: "legacy functionality")
    @available(iOS, deprecated: 13.0, message: "legacy functionality")
    @available(tvOS, deprecated: 13.0, message: "legacy functionality")
    @available(watchOS, deprecated: 6.0, message: "legacy functionality")
    var sslProtocol: SSLProtocol {
        switch self {
        case .tlsv1:
            return .tlsProtocol1
        case .tlsv11:
            return .tlsProtocol11
        case .tlsv12:
            return .tlsProtocol12
        case .tlsv13:
            return .tlsProtocol13
        }
    }
}

@available(macOS 10.14, iOS 12.0, tvOS 12.0, watchOS 5.0, *)
extension TLSConfiguration {
    /// Dispatch queue used by Network framework TLS to control certificate verification
    static let tlsDispatchQueue = DispatchQueue(label: "TLSDispatch")

    /// create NWProtocolTLS.Options for use with NIOTransportServices from the NIOSSL TLSConfiguration
    ///
    /// - Parameter eventLoop: EventLoop to wait for creation of options on
    /// - Returns: Future holding NWProtocolTLS Options
    func getNWProtocolTLSOptions(
        on eventLoop: EventLoop,
        serverNameIndicatorOverride: String?,
        tlsVerificationHandler: _TLSVerificationHandler? = nil
    ) -> EventLoopFuture<NWProtocolTLS.Options> {
        let promise = eventLoop.makePromise(of: NWProtocolTLS.Options.self)
        Self.tlsDispatchQueue.async {
            do {
                let options = try self.getNWProtocolTLSOptions(
                    serverNameIndicatorOverride: serverNameIndicatorOverride,
                    tlsVerificationHandler: tlsVerificationHandler
                )
                promise.succeed(options)
            } catch {
                promise.fail(error)
            }
        }
        return promise.futureResult
    }

    /// create NWProtocolTLS.Options for use with NIOTransportServices from the NIOSSL TLSConfiguration
    ///
    /// - Returns: Equivalent NWProtocolTLS Options
    func getNWProtocolTLSOptions(
        serverNameIndicatorOverride: String?,
        tlsVerificationHandler: _TLSVerificationHandler? = nil
    ) throws -> NWProtocolTLS.Options {
        let options = NWProtocolTLS.Options()

        let useMTELGExplainer = """
            You can still use this configuration option on macOS if you initialize HTTPClient \
            with a MultiThreadedEventLoopGroup. Please note that using MultiThreadedEventLoopGroup \
            will make AsyncHTTPClient use NIO on BSD Sockets and not Network.framework (which is the preferred \
            platform networking stack).
            """

        if let serverNameIndicatorOverride = serverNameIndicatorOverride {
            serverNameIndicatorOverride.withCString { serverNameIndicatorOverride in
                sec_protocol_options_set_tls_server_name(options.securityProtocolOptions, serverNameIndicatorOverride)
            }
        }

        // minimum TLS protocol
        if #available(macOS 10.15, iOS 13.0, tvOS 13.0, watchOS 6.0, *) {
            sec_protocol_options_set_min_tls_protocol_version(
                options.securityProtocolOptions,
                self.minimumTLSVersion.nwTLSProtocolVersion
            )
        } else {
            sec_protocol_options_set_tls_min_version(
                options.securityProtocolOptions,
                self.minimumTLSVersion.sslProtocol
            )
        }

        // maximum TLS protocol
        if let maximumTLSVersion = self.maximumTLSVersion {
            if #available(macOS 10.15, iOS 13.0, tvOS 13.0, watchOS 6.0, *) {
                sec_protocol_options_set_max_tls_protocol_version(
                    options.securityProtocolOptions,
                    maximumTLSVersion.nwTLSProtocolVersion
                )
            } else {
                sec_protocol_options_set_tls_max_version(options.securityProtocolOptions, maximumTLSVersion.sslProtocol)
            }
        }

        // application protocols
        for applicationProtocol in self.applicationProtocols {
            applicationProtocol.withCString { buffer in
                sec_protocol_options_add_tls_application_protocol(options.securityProtocolOptions, buffer)
            }
        }

        // cipher suites
        if self.cipherSuites.count > 0 {
            // TODO: Requires NIOSSL to provide list of cipher values before we can continue
            // https://github.com/apple/swift-nio-ssl/issues/207
        }

        // key log callback
        if self.keyLogCallback != nil {
            preconditionFailure("TLSConfiguration.keyLogCallback is not supported. \(useMTELGExplainer)")
        }

        // the certificate chain
        if self.certificateChain.count > 0 {
            preconditionFailure("TLSConfiguration.certificateChain is not supported. \(useMTELGExplainer)")
        }

        // private key
        if self.privateKey != nil {
            preconditionFailure("TLSConfiguration.privateKey is not supported. \(useMTELGExplainer)")
        }

        // renegotiation support key is unsupported

        // trust roots
        var secTrustRoots: [SecCertificate]?
        switch trustRoots {
        case .some(.certificates(let certificates)):
            secTrustRoots = try certificates.compactMap { certificate in
                try SecCertificateCreateWithData(nil, Data(certificate.toDERBytes()) as CFData)
            }
        case .some(.file(let file)):
            let certificates = try NIOSSLCertificate.fromPEMFile(file)
            secTrustRoots = try certificates.compactMap { certificate in
                try SecCertificateCreateWithData(nil, Data(certificate.toDERBytes()) as CFData)
            }

        case .some(.default), .none:
            break
        }

        if certificateVerification != .fullVerification || trustRoots != nil || tlsVerificationHandler != nil {
            // add verify block to control certificate verification
            sec_protocol_options_set_verify_block(
                options.securityProtocolOptions,
                { _, sec_trust, sec_protocol_verify_complete in
                    let trust = sec_trust_copy_ref(sec_trust).takeRetainedValue()

                    // A caller-supplied handler replaces verification outright, exactly as a
                    // NIOSSL custom verification callback does on the BoringSSL transport.
                    if let tlsVerificationHandler {
                        do {
                            let certificates = try Self.presentedCertificates(of: trust)
                            // `sec_protocol_verify_complete_t` is a plain Objective-C block, so it
                            // carries no `Sendable` annotation. Network.framework allows completing
                            // it from any context.
                            let complete = UncheckedSendableBox(sec_protocol_verify_complete)
                            Task {
                                do {
                                    let result = try await tlsVerificationHandler.verify(certificates)
                                    complete.value(result == .certificateVerified)
                                } catch {
                                    complete.value(false)
                                }
                            }
                        } catch {
                            sec_protocol_verify_complete(false)
                        }
                        return
                    }

                    guard self.certificateVerification != .none else {
                        sec_protocol_verify_complete(true)
                        return
                    }

                    if let trustRootCertificates = secTrustRoots {
                        SecTrustSetAnchorCertificates(trust, trustRootCertificates as CFArray)
                    }
                    if self.certificateVerification == .noHostnameVerification {
                        // A hostname-less SSL policy validates the chain but not the identity.
                        SecTrustSetPolicies(trust, SecPolicyCreateSSL(true, nil))
                    }
                    if #available(macOS 10.15, iOS 13.0, tvOS 13.0, watchOS 6.0, *) {
                        dispatchPrecondition(condition: .onQueue(Self.tlsDispatchQueue))
                        SecTrustEvaluateAsyncWithError(trust, Self.tlsDispatchQueue) { _, result, error in
                            if let error = error {
                                print("Trust failed: \(error.localizedDescription)")
                            }
                            sec_protocol_verify_complete(result)
                        }
                    } else {
                        SecTrustEvaluateAsync(trust, Self.tlsDispatchQueue) { _, result in
                            switch result {
                            case .proceed, .unspecified:
                                sec_protocol_verify_complete(true)
                            default:
                                sec_protocol_verify_complete(false)
                            }
                        }
                    }
                },
                Self.tlsDispatchQueue
            )
        }
        return options
    }

    /// The certificates the peer presented, in the order it presented them.
    private static func presentedCertificates(of trust: SecTrust) throws -> [NIOSSLCertificate] {
        guard let secCertificates = SecTrustCopyCertificateChain(trust) as? [SecCertificate] else {
            throw NIOSSLError.noCertificateToValidate
        }
        return try secCertificates.map { secCertificate in
            let derBytes = SecCertificateCopyData(secCertificate) as Data
            return try NIOSSLCertificate(bytes: Array(derBytes), format: .der)
        }
    }
}

/// Carries a value that is known-safe to use concurrently but is not statically `Sendable`.
private struct UncheckedSendableBox<Value>: @unchecked Sendable {
    let value: Value

    init(_ value: Value) {
        self.value = value
    }
}

#endif
