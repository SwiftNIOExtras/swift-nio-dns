//
//  NIOHandlers.swift
//  NIODNSServer
//
//  Created by Helge Hess.
//  Copyright © 2026 ZeeZide GmbH. All rights reserved.
//

import NIOCore

/// UDP socket handler of ``DNSServer``.
final class DatagramQueryHandler: ChannelInboundHandler {

  typealias InboundIn   = AddressedEnvelope<ByteBuffer>
  typealias OutboundOut = AddressedEnvelope<ByteBuffer>

  let responder : QueryResponder

  init(responder: QueryResponder) { self.responder = responder }

  func channelRead(context: ChannelHandlerContext, data: NIOAny) {
    let envelope = unwrapInboundIn(data)
    let channel  = context.channel
    responder.respond(to      : envelope.data, from : envelope.remoteAddress,
                      useTCP  : false,         on   : context.eventLoop)
      .whenSuccess { response in
        guard let response else { return }
        channel.writeAndFlush(
          AddressedEnvelope(remoteAddress: envelope.remoteAddress,
                            data: response),
          promise: nil
        )
      }
  }
}

/// TCP connection handler of ``DNSServer``.
final class StreamQueryHandler: ChannelInboundHandler {

  typealias InboundIn   = ByteBuffer
  typealias OutboundOut = ByteBuffer

  let responder : QueryResponder

  init(responder: QueryResponder) { self.responder = responder }

  func channelRead(context: ChannelHandlerContext, data: NIOAny) {
    let query   = unwrapInboundIn(data)
    let channel = context.channel
    guard let remoteAddress = channel.remoteAddress else { return }
    responder.respond(to: query, from: remoteAddress, useTCP: true,
                      on: context.eventLoop)
      .whenSuccess { response in
        guard let response else { return }
        channel.writeAndFlush(response, promise: nil) // the encoder frames
      }
  }
}
