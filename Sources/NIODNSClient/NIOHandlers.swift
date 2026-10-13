//
//  DNSClient+Query+TCPHandler.swift
//  NIODNSClient
//
//  Created by Helge Hess.
//  Copyright © 2026 ZeeZide GmbH. All rights reserved.
//

import NIOCore
import NIODNS

extension DNSClient.Query {

  final class UDPHandler: ChannelInboundHandler {

    typealias InboundIn = AddressedEnvelope<ByteBuffer>

    let query   : DNSClient.Query
    let attempt : Int
    let server  : SocketAddress

    init(query: DNSClient.Query, attempt: Int, server: SocketAddress) {
      self.query   = query
      self.attempt = attempt
      self.server  = server
    }

    func channelRead(context: ChannelHandlerContext, data: NIOAny) {
      let envelope = unwrapInboundIn(data)
      guard envelope.remoteAddress == server else { return }
      query.received(envelope.data, attempt: attempt, useTCP: false)
    }

    func errorCaught(context: ChannelHandlerContext, error: Error) {
      query.attemptFailed(attempt, .connectionFailed)
    }
  }

  final class TCPHandler: ChannelInboundHandler {

    typealias InboundIn = ByteBuffer

    let query   : DNSClient.Query
    let attempt : Int

    private var isDelivered = false

    init(query: DNSClient.Query, attempt: Int) {
      self.query   = query
      self.attempt = attempt
    }

    func channelRead(context: ChannelHandlerContext, data: NIOAny) {
      guard !isDelivered else { return }
      isDelivered = true
      query.received(unwrapInboundIn(data), attempt: attempt, useTCP: true)
    }

    func channelInactive(context: ChannelHandlerContext) {
      if !isDelivered { query.attemptFailed(attempt, .connectionClosed) }
      context.fireChannelInactive()
    }

    func errorCaught(context: ChannelHandlerContext, error: Error) {
      if !isDelivered { query.attemptFailed(attempt, .connectionFailed) }
      context.close(promise: nil)
    }
  }
}
