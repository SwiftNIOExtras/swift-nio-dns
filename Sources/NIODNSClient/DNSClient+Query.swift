//
//  DNSClient+Query.swift
//  NIODNSClient
//
//  Created by Helge Hess.
//  Copyright © 2026 ZeeZide GmbH. All rights reserved.
//

import NIOCore
import NIODNS
import NIOPosix

extension DNSClient {

  public enum QueryError: Swift.Error, Hashable, Sendable {
    case invalidName
    case noServers
    case timeout
    case connectionFailed
    case serverFailure(DNSMessage.ResponseCode)
    case badResponse
    case connectionClosed
    case cancelled
  }

  /// A running query of a ``DNSClient``.
  public final class Query: @unchecked Sendable {
    // @unchecked: mutable state is only touched on `eventLoop`.

    public  let id          : UInt16
    public  let name        : String
    public  let kind        : DNSRecord.Kind
    public  let options     : Options
    public  let eventLoop   : EventLoop

    private let promise     : EventLoopPromise<DNSMessage>

    private var packet      : ByteBuffer?
    private var isDone      = false
    private var round       = 0
    private var serverIndex = 0
    private var attempt     = 0
    private var lastError   = QueryError.timeout
    private var channel     : Channel?
    private var timer       : Scheduled<Void>?

    init(id   : UInt16 = .random(in: .min ... .max), name: String,
         kind : DNSRecord.Kind, options: Options, eventLoop: EventLoop)
    {
      self.id        = id
      self.name      = name
      self.kind      = kind
      self.options   = options
      self.eventLoop = eventLoop
      self.promise   = eventLoop.makePromise(of: DNSMessage.self)
    }

    /// The answer, see ``DNSClient/query(_:kind:on:)`` for when it fails.
    public var result : EventLoopFuture<DNSMessage> {
      promise.futureResult
    }

    /// Sends the query (invoke by ``DNSClient``)
    func start() {
      eventLoop.execute {
        guard !self.isDone else { return } // cancelled before
        guard !self.options.servers.isEmpty else {
          return self.finish(.failure(.noServers))
        }

        do {
          let query = DNSMessage(id: self.id, name: self.name, kind: self.kind,
                                 ednsPayloadSize: self.options.ednsPayloadSize)
          self.packet = try query.toByteBuffer()
        }
        catch {
          return self.finish(.failure(.invalidName))
        }

        self.send(useTCP: false)
      }
    }

    /// Cancel the query (``QueryError/cancelled``)
    public func cancel() {
      eventLoop.execute { self.finish(.failure(.cancelled)) }
    }


    private func send(useTCP: Bool) {
      eventLoop.preconditionInEventLoop()
      closeChannel()
      timer?.cancel()
      attempt += 1

      let attempt = self.attempt
      let server  = options.servers[serverIndex]
      let factor  = Int64(1) << Int64(min(round, 3))
      let limit   = TimeAmount.nanoseconds(options.timeout.nanoseconds * factor)

      timer = eventLoop.scheduleTask(in: limit) {
        self.attemptFailed(attempt, .timeout)
      }

      let channel = useTCP
        ? openTCP  (to: server, attempt: attempt, timeout: limit)
        : openUDP(to: server, attempt: attempt)

      channel.whenComplete { result in
        switch result {
          case .failure:
            self.attemptFailed(attempt, .connectionFailed)

          case .success(let channel):
            guard attempt == self.attempt, !self.isDone else {
              channel.close(promise: nil)
              return
            }
            self.channel = channel
            self.write(to: channel, server: server, useTCP: useTCP)
              .whenFailure { _ in
                self.attemptFailed(attempt, .connectionFailed)
              }
        }
      }
    }

    private func openUDP(to server: SocketAddress, attempt: Int)
                 -> EventLoopFuture<Channel>
    {
      let isIPv6 = server.protocol == .inet6
      return DatagramBootstrap(group: eventLoop)
        .channelInitializer { channel in
          channel.eventLoop.makeCompletedFuture {
            try channel.pipeline.syncOperations.addHandler(
              UDPHandler(query: self, attempt: attempt, server: server))
          }
        }
        .bind(host: isIPv6 ? "::" : "0.0.0.0", port: 0)
    }

    private func openTCP(to server: SocketAddress, attempt: Int,
                         timeout: TimeAmount) -> EventLoopFuture<Channel>
    {
      return ClientBootstrap(group: eventLoop)
        .connectTimeout(timeout)
        .channelInitializer { channel in
          channel.eventLoop.makeCompletedFuture {
            try channel.pipeline.syncOperations.addHandlers(
              ByteToMessageHandler(LengthPrefixDecoder<UInt16>()),
              MessageToByteHandler(LengthPrefixEncoder<UInt16>()),
              TCPHandler(query: self, attempt: attempt)
            )
          }
        }
        .connect(to: server)
    }

    private func write(to channel: Channel, server: SocketAddress,
                       useTCP: Bool) -> EventLoopFuture<Void>
    {
      guard let packet else {
        return eventLoop.makeFailedFuture(QueryError.invalidName)
      }
      
      if useTCP {
        return channel.writeAndFlush(packet)
      }
      else {
        return channel
          .writeAndFlush(AddressedEnvelope(remoteAddress: server, data: packet))
      }
    }

    func attemptFailed(_ attempt: Int, _ error: QueryError) {
      eventLoop.preconditionInEventLoop()
      guard attempt == self.attempt, !isDone else { return }
      lastError = error

      serverIndex += 1
      if serverIndex >= options.servers.count {
        serverIndex = 0
        round += 1
      }
      guard round < options.attempts else { return finish(.failure(lastError)) }
      send(useTCP: false)
    }

    func received(_ buffer: ByteBuffer, attempt: Int, useTCP: Bool) {
      eventLoop.preconditionInEventLoop()
      guard attempt == self.attempt, !isDone else { return }

      // Over UDP anybody can send us a packet. Whatever is not the answer to
      // our question is ignored, and we keep waiting for the real one.
      guard let message = try? DNSMessage(bytes: buffer), message.isResponse,
            message.id == id, answersOurQuestion(message)
      else {
        if useTCP { attemptFailed(attempt, .badResponse) }
        return
      }

      if message.isTruncated && !useTCP { return send(useTCP: true) }

      switch message.responseCode {
        case .noError, .nameError:
          finish(.success(message))
        default:
          attemptFailed(attempt, .serverFailure(message.responseCode))
      }
    }

    private func answersOurQuestion(_ message: DNSMessage) -> Bool {
      guard let question = message.questions.first else { return false }
      return question.kind == kind
          && DNSMessage.canonicalName(question.name)
          == DNSMessage.canonicalName(name)
    }

    private func finish(_ result: Result<DNSMessage, QueryError>) {
      eventLoop.preconditionInEventLoop()
      guard !isDone else { return }
      isDone = true
      timer?.cancel()
      timer = nil
      closeChannel()

      switch result {
        case .success(let message) : promise.succeed(message)
        case .failure(let error)   : promise.fail(error)
      }
    }

    private func closeChannel() {
      channel?.close(promise: nil)
      channel = nil
    }
  }
}
