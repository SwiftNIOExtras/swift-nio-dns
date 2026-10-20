//
//  QueryResponder.swift
//  NIODNSServer
//
//  Created by Helge Hess.
//  Copyright © 2026 ZeeZide GmbH. All rights reserved.
//

import NIOCore
import NIOConcurrencyHelpers
import NIODNS

/// Helper that wraps around the ``DNSServer/Responder`` closure.
final class QueryResponder: Sendable {

  let responder : DNSServer.Responder // the closure
  let counts    = NIOLockedValueBox( ( udp: 0, tcp: 0 ) )

  init(responder: @escaping DNSServer.Responder) {
    self.responder = responder
  }

  func respond(to bytes : ByteBuffer, from remoteAddress : SocketAddress,
               useTCP   : Bool,       on            loop : EventLoop)
       -> EventLoopFuture<ByteBuffer?>
  {
    counts.withLockedValue {
      if useTCP { $0.tcp += 1 } else { $0.udp += 1 }
    }

    guard let message = try? DNSMessage(bytes: bytes) else {
      return loop.makeSucceededFuture(formatError(for: bytes))
    }
    guard !message.isResponse else { // never answer a response
      return loop.makeSucceededFuture(nil)
    }

    let query = DNSServer.Query(message : message, remoteAddress: remoteAddress,
                                tcp     : useTCP,  eventLoop    : loop)

    @Sendable
    func send(_ response: DNSServer.Response) -> EventLoopFuture<ByteBuffer?> {
      switch response {
        case .drop             : loop.makeSucceededFuture(nil)
        case .raw     (let raw): loop.makeSucceededFuture(raw)
        case .message (let r)  : loop.makeSucceededFuture(encode(r, for: query))
        case .deferred(let fut): fut.hop(to: loop).flatMap(send)
      }
    }
    return send(responder(query))
  }

  private func encode(_ response: DNSMessage, for query: DNSServer.Query)
               -> ByteBuffer?
  {
    // If too large for UDP, replaced w/ question and truncation flag.
    let limit = query.tcp ? Int(UInt16.max)
                          : max(DNSMessage.maxUDPPayloadSize,
                                Int(query.message.ednsPayloadSize ?? 0))

    // An EDNS client gets an OPT record back, unless the responder added one.
    func withEDNS(_ message: DNSMessage) -> DNSMessage {
      guard query.message.ednsPayloadSize != nil,
            message.ednsPayloadSize == nil else { return message }
      var message = message
      message.additionals
        .append(.edns(payloadSize: DNSMessage.defaultEDNSPayloadSize))
      return message
    }

    let response = withEDNS(response)
    lazy var fallback = withEDNS(
      DNSMessage(responseTo: query.message, responseCode: .serverFailure))

    if let bytes = try? response.toByteBuffer() {
      guard bytes.readableBytes > limit else { return bytes }
      if !query.tcp {
        fallback.responseCode = response.responseCode
        fallback.flags.insert(.truncated)
      }
    }
    return try? fallback.toByteBuffer()
  }

  private func formatError(for bb: ByteBuffer) -> ByteBuffer? {
    guard let id  = bb.getInteger(at: bb.readerIndex,     as: UInt16.self),
          let raw = bb.getInteger(at: bb.readerIndex + 2, as: UInt16.self),
          !DNSMessage.Flags(rawValue: raw).contains(.response) else
    {
      return nil
    }

    var error = DNSMessage(id: id, flags: .response)
    error.responseCode = .formatError
    return try? error.toByteBuffer()
  }
}
