//
//  ResponseCollector.swift
//  NIODNSServer
//
//  Created by Helge Hess.
//  Copyright © 2026 ZeeZide GmbH. All rights reserved.
//

import NIOCore
import NIODNS

/// Collects the DNS responses arriving on a client channel.
final class ResponseCollector<InboundIn>: ChannelInboundHandler,
                                          @unchecked Sendable
{
  // @unchecked: only used on the event loop of the channel.

  let done : EventLoopPromise<[ DNSMessage ]>

  private let expected  : Int
  private let bytes     : ( InboundIn ) -> ByteBuffer
  private var responses = [ DNSMessage ]()

  init(expected : Int, eventLoop: EventLoop,
       bytes    : @escaping ( InboundIn ) -> ByteBuffer)
  {
    self.expected = expected
    self.done     = eventLoop.makePromise()
    self.bytes    = bytes
  }

  func channelRead(context: ChannelHandlerContext, data: NIOAny) {
    guard let message = try? DNSMessage(bytes: bytes(unwrapInboundIn(data)))
     else { return }
    responses.append(message)
    if responses.count == expected { done.succeed(responses) }
  }
}

extension ResponseCollector where InboundIn == ByteBuffer {

  convenience init(stream eventLoop: EventLoop, expected: Int) {
    self.init(expected: expected, eventLoop: eventLoop) { $0 }
  }
}

extension ResponseCollector where InboundIn == AddressedEnvelope<ByteBuffer> {
  convenience init(datagrams eventLoop: EventLoop, expected: Int) {
    self.init(expected: expected, eventLoop: eventLoop) { $0.data }
  }
}
