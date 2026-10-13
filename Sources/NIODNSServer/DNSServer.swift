//
//  DNSServer.swift
//  NIODNSServer
//
//  Created by Helge Hess.
//  Copyright © 2026 ZeeZide GmbH. All rights reserved.
//

import NIOCore
import NIOPosix
import NIODNS

/**
 * A small DNS server for testing purposes, UDP and TCP on the same port.
 *
 * Do not use in PROD, intended for testing purposes only.
 *
 * ```swift
 * DNSServer.bind(responder: DNSServer.zone([
 *   DNSRecord(name: "zeezide.de", ttl: 300,
 *             data: .mx(preference: 10, exchange: "mail.zeezide.de"))
 * ]))
 * .whenSuccess { server in
 *   // ... send queries to server.localAddress ...
 *   server.close().whenComplete { _ in print("closed") }
 * }
 * ```
 */
public final class DNSServer: Sendable {

  public struct Query: Sendable {

    public let message       : DNSMessage
    public let remoteAddress : SocketAddress
    public let tcp           : Bool
    public let eventLoop     : EventLoop

    /// The first (in practice the only) question of the message.
    @inlinable
    public var question : DNSMessage.Question? { message.questions.first }

    @inlinable
    public init(message   : DNSMessage, remoteAddress: SocketAddress, tcp: Bool,
                eventLoop : EventLoop)
    {
      self.message       = message
      self.remoteAddress = remoteAddress
      self.tcp           = tcp
      self.eventLoop     = eventLoop
    }
  }
  
  public enum Response: Sendable {
    case message (DNSMessage) // send message, truncated if not fitting
    case raw     (ByteBuffer) // send raw bytes
    case deferred(EventLoopFuture<Response>)
    case drop                 // client will timeout
  }

  /// A closure that returns the ``Response`` for a ``Query``.
  /// E.g. ``DNSServer/zone(_:)`` to respond from a static set of records.
  public typealias Responder = @Sendable ( Query ) -> Response

  /// The address the server listens on, for both UDP and TCP.
  public let localAddress : SocketAddress

  let channels  : [ Channel ]
  let responder : QueryResponder

  init(localAddress : SocketAddress, channels: [ Channel ],
       responder    : QueryResponder)
  {
    self.localAddress = localAddress
    self.channels     = channels
    self.responder    = responder
  }

  /// The number of queries received over UDP and over TCP.
  public var queryCounts : ( udp: Int, tcp: Int ) {
    responder.counts.withLockedValue { $0 }
  }

  /**
   * Starts a server.
   *
   * - Parameters:
   *   - host:      The address to listen on (def: localhost)
   *   - port:      The port (def: 0 - pick one)
   *   - group:     The event loops to run on (def: MTELG.singleton).
   *   - responder: Request handler, e.g. ``zone(_:)``.
   * - Returns:     Future for the running server.
   */
  public static func bind(host      : String = "127.0.0.1", port: Int = 0,
                          group     : EventLoopGroup? = nil,
                          responder : @escaping Responder)
                     -> EventLoopFuture<DNSServer>
  {
    let group = group ?? MultiThreadedEventLoopGroup.singleton
    let queryResponder = QueryResponder(responder: responder)

    // For port 0 the UDP socket has to get the port the TCP socket was given.
    @Sendable func attempt(_ remaining: Int) -> EventLoopFuture<DNSServer> {
      bindTCP(host: host, port: port, group: group, responder:queryResponder)
        .flatMap { tcp in
          guard let adr = tcp.localAddress, let boundPort = adr.port else {
            return tcp.close().flatMapThrowing {
              throw ChannelError.unknownLocalAddress
            }
          }
          return bindUDP(host: host, port: boundPort, group: group,
                         responder: queryResponder)
            .map { udp in
              DNSServer(localAddress: adr, channels: [ tcp, udp ],
                        responder: queryResponder)
            }
            .flatMapError { error in
              tcp.close().flatMap {
                if remaining > 1 { attempt(remaining - 1)                }
                else             { tcp.eventLoop.makeFailedFuture(error) }
              }
            }
        }
    }
    return attempt(port == 0 ? 16 : 1)
  }

  /// Stops the server.
  @discardableResult
  public func close() -> EventLoopFuture<Void> {
    let futures = channels.map { $0.close() }
    return EventLoopFuture.andAllComplete(futures, on: channels[0].eventLoop)
  }

  private static func bindTCP(host: String, port: Int, group: EventLoopGroup,
                              responder: QueryResponder)
                      -> EventLoopFuture<Channel>
  {
    return ServerBootstrap(group: group)
      .serverChannelOption(.socketOption(.so_reuseaddr), value: 1)
      .childChannelInitializer { channel in
        channel.eventLoop.makeCompletedFuture {
          try channel.pipeline.syncOperations.addHandlers(
            ByteToMessageHandler(LengthPrefixDecoder<UInt16>()),
            MessageToByteHandler(LengthPrefixEncoder<UInt16>()),
            StreamQueryHandler(responder: responder)
          )
        }
      }
      .bind(host: host, port: port)
  }

  private static func bindUDP(host: String, port: Int, group: EventLoopGroup,
                              responder: QueryResponder)
                      -> EventLoopFuture<Channel>
  {
    return DatagramBootstrap(group: group)
      .channelInitializer { channel in
        channel.eventLoop.makeCompletedFuture {
          try channel.pipeline.syncOperations
            .addHandler(DatagramQueryHandler(responder: responder))
        }
      }
      .bind(host: host, port: port)
  }
}
