//
//  L2PlusSdk.swift
//  Reads the L2+ evidence from a CIE over NFC (CoreNFC).
//
//  The app collects the CAN or the MRZ data, gets the challenge from its backend and sends the result.
//  The SDK makes no network calls and keeps nothing after the completion.
//
//  The app Info.plist must list these AIDs under com.apple.developer.nfc.readersession.iso7816.select-identifiers:
//  A0000002471001 (eMRTD), A0000000308000000009816001 (IAS), A00000000039 (DF CIE).
//

import Foundation
import CoreNFC

/// Texts shown in the system NFC sheet. Defaults are in Italian.
public struct L2PlusNfcMessages {
    public var waitingForCard = "Avvicina la CIE alla parte alta del telefono"
    public var reading = "Carta rilevata, non muoverla"
    public var readingDocument = "Lettura dei dati del documento…"
    public var checkingCard = "Verifica della carta…"
    public var verifying = "Verifica delle firme…"
    public var completed = "Lettura completata"
    public var failed = "Lettura non riuscita"

    public init() {}
}

public final class L2PlusSdk: NSObject {

    public typealias Completion = (Result<L2PlusResult, L2PlusError>) -> Void

    private let trust: L2PlusTrustConfig
    private let messages: L2PlusNfcMessages
    private let lock = NSLock()
    private var session: Session?

    public init(trust: L2PlusTrustConfig, messages: L2PlusNfcMessages = L2PlusNfcMessages()) {
        self.trust = trust
        self.messages = messages
    }

    /// Starts a read. Inputs are checked before the NFC session is opened.
    /// The completion is called exactly once, on the main thread.
    /// A call made while another read is running gets ALREADY_RUNNING; the running read is not affected.
    public func start(access: L2PlusAccess, challenge: Data,
                      onStep: ((L2PlusStep) -> Void)? = nil,
                      completion: @escaping Completion) {
        func fail(_ e: L2PlusError) { DispatchQueue.main.async { completion(.failure(e)) } }

        let request: L2PlusRequest
        do {
            guard !trust.mrtdTrustAnchors.isEmpty else {
                throw L2PlusError(.MISSING_TRUST_ANCHORS, "No trust anchors configured")
            }
            request = try L2PlusRequest.validate(access, challenge: challenge)
        } catch let e as L2PlusError {
            return fail(e)
        } catch {
            return fail(L2PlusError(.INTERNAL_ERROR, "Unexpected error"))
        }
        guard NFCTagReaderSession.readingAvailable else {
            return fail(L2PlusError(.NFC_NOT_AVAILABLE, "NFC not available"))
        }

        lock.lock()
        guard session == nil else {
            lock.unlock()
            return fail(L2PlusError(.ALREADY_RUNNING, "A read is already running"))
        }
        let s = Session(owner: self, request: request, trust: trust, messages: messages, onStep: onStep, completion: completion)
        session = s
        lock.unlock()
        s.begin()
    }

    /// Stops the running read; the completion gets CANCELLED.
    public func cancel() {
        lock.lock(); let s = session; lock.unlock()
        s?.finish(.failure(L2PlusError(.CANCELLED, "Read cancelled")))
    }

    fileprivate func ended(_ s: Session) {
        lock.lock(); if session === s { session = nil }; lock.unlock()
    }

    fileprivate final class Session: NSObject, NFCTagReaderSessionDelegate {
        private weak var owner: L2PlusSdk?
        private let request: L2PlusRequest
        private let trust: L2PlusTrustConfig
        private let messages: L2PlusNfcMessages
        private let onStep: ((L2PlusStep) -> Void)?
        private let completion: Completion
        private var nfc: NFCTagReaderSession?
        private let finished = NSLock()
        private var isFinished = false

        init(owner: L2PlusSdk, request: L2PlusRequest, trust: L2PlusTrustConfig, messages: L2PlusNfcMessages,
             onStep: ((L2PlusStep) -> Void)?, completion: @escaping Completion) {
            self.owner = owner
            self.request = request
            self.trust = trust
            self.messages = messages
            self.onStep = onStep
            self.completion = completion
        }

        func begin() {
            nfc = NFCTagReaderSession(pollingOption: [.iso14443], delegate: self, queue: nil)
            nfc?.alertMessage = messages.waitingForCard
            step(.waitingForCard)
            nfc?.begin()
        }

        var cancelled: Bool { finished.lock(); defer { finished.unlock() }; return isFinished }

        func step(_ s: L2PlusStep) {
            guard !cancelled else { return }
            nfc?.alertMessage = message(for: s)
            if let onStep = onStep { DispatchQueue.main.async { onStep(s) } }
        }

        func finish(_ result: Result<L2PlusResult, L2PlusError>) {
            finished.lock()
            if isFinished { finished.unlock(); return }
            isFinished = true
            finished.unlock()
            switch result {
            case .success:
                nfc?.alertMessage = messages.completed
                nfc?.invalidate()
            case .failure(let e):
                if e.code == .CANCELLED { nfc?.invalidate() } else { nfc?.invalidate(errorMessage: messages.failed) }
            }
            owner?.ended(self)
            let completion = self.completion
            DispatchQueue.main.async { completion(result) }
        }

        func tagReaderSessionDidBecomeActive(_ session: NFCTagReaderSession) {}

        func tagReaderSession(_ session: NFCTagReaderSession, didInvalidateWithError error: Error) {
            let userCancelled = (error as? NFCReaderError)?.code == .readerSessionInvalidationErrorUserCanceled
            finish(.failure(L2PlusError(userCancelled ? .CANCELLED : .TAG_LOST, "NFC session ended")))
        }

        func tagReaderSession(_ session: NFCTagReaderSession, didDetect tags: [NFCTag]) {
            guard let first = tags.first, case let .iso7816(tag) = first else {
                finish(.failure(L2PlusError(.TAG_NOT_SUPPORTED, "Tag does not support ISO 7816")))
                return
            }
            step(.cardDetected)
            Task {
                do {
                    try await session.connect(to: first)
                    let result = try await L2PlusReader(trust: trust).read(
                        transport: NfcTransport(tag: tag), request: request,
                        isCancelled: { self.cancelled },
                        onStep: { s in self.step(s) })
                    finish(.success(result))
                } catch let e as L2PlusError {
                    finish(.failure(e))
                } catch {
                    finish(.failure(L2PlusError(.TAG_LOST, "Card communication lost")))
                }
            }
        }

        private func message(for s: L2PlusStep) -> String {
            switch s {
            case .waitingForCard: return messages.waitingForCard
            case .cardDetected, .pace: return messages.reading
            case .readingMrtd: return messages.readingDocument
            case .readingIas, .signingChallenge: return messages.checkingCard
            case .verifying: return messages.verifying
            }
        }
    }

    private final class NfcTransport: L2PlusTransport {
        private let tag: NFCISO7816Tag
        init(tag: NFCISO7816Tag) { self.tag = tag }

        func transceive(_ apdu: [UInt8]) async throws -> [UInt8] {
            guard let command = NFCISO7816APDU(data: Data(apdu)) else {
                throw L2PlusError(.INTERNAL_ERROR, "Invalid APDU")
            }
            do {
                let (data, sw1, sw2) = try await tag.sendCommand(apdu: command)
                return [UInt8](data) + [sw1, sw2]
            } catch {
                throw L2PlusError(.TAG_LOST, "Card removed")
            }
        }
    }
}

public extension L2PlusTrustConfig {
    /// CSCA certificates shipped with the package. Handy for testing;
    /// a production app should supply up-to-date trust material.
    static func bundledCscaCertificates() -> [Data] {
        let urls = Bundle.module.urls(forResourcesWithExtension: "cer", subdirectory: "CSCA") ?? []
        return urls.sorted { $0.lastPathComponent < $1.lastPathComponent }.compactMap { try? Data(contentsOf: $0) }
    }
}
