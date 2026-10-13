//
//  DNSClient.swift
//  NIODNSClient
//
//  Created by Helge Hess.
//  Copyright © 2026 ZeeZide GmbH. All rights reserved.
//

import NIOCore
import NIODNS
import NIOPosix

/**
 * A very simple DNS client.
 *
 * ```swift
 * let client = DNSClient(options: .init(servers: [
 *   try SocketAddress(ipAddress: "9.9.9.9", port: 53)
 * ]))
 * client.query("zeezide.de", kind: .mx).result
 *   .whenSuccess { message in
 *     for record in message.answers {
 *       if case .mx(let preference, let exchange) = record.data { ... }
 *     }
 *   }
 * ```
 *
 * Call ``shutdown()`` when done w/ the client.
 */
public final class DNSClient: Sendable {

  public struct Options: Sendable {

    public var servers         : [ SocketAddress ]

    /// Timeout for the first attempt, doubles, capped at 8x
    public var timeout         : TimeAmount

    public var attempts        : Int
    public var ednsPayloadSize : UInt16?

    @inlinable
    public init(servers : [ SocketAddress ] = [],
                timeout : TimeAmount = .seconds(2), retries: Int = 3,
                ednsPayloadSize : UInt16? = DNSMessage.defaultEDNSPayloadSize)
    {
      self.servers         = servers
      self.timeout         = timeout
      self.attempts        = retries + 1
      self.ednsPayloadSize = ednsPayloadSize
    }

    @inlinable
    public init(_ server: SocketAddress) {
      self.init(servers: [ server ])
    }
  }

  public let options        : Options
  public let eventLoopGroup : EventLoopGroup

  /**
   * Create a new client.
   *
   * - Parameters:
   *   - options:        The name servers, timeouts and retries.
   *   - eventLoopGroup: The group the queries run on (def: the singleton
   *                     `MultiThreadedEventLoopGroup`).
   */
  public init(options: Options, eventLoopGroup: EventLoopGroup? = nil) {
    self.options        = options
    self.eventLoopGroup = eventLoopGroup
                       ?? MultiThreadedEventLoopGroup.singleton
  }

  /**
   * Sends a query for a name and record type.
   *
   * The ``Query/result`` of the returned query succeeds w/ the response of a
   * server, also if that is a `NXDOMAIN`. It fails w/ a ``QueryError``, e.g.
   * if no server answered.
   *
   * ```swift
   * let query = client.query("_dmarc.zeezide.de", kind: .txt)
   * query.result.whenComplete { result in
   *   switch result {
   *     case .success(let message) where message.responseCode == .nameError:
   *       print("no such name")
   *     case .success(let message):
   *       for case .txt(let chunks) in message.answers.map({ $0.data }) {
   *         print(chunks.joined())
   *       }
   *     case .failure(let error):
   *       print("query failed:", error)
   *   }
   * }
   * ...
   * query.cancel() // no longer needed: fails the result w/ `.cancelled`
   * ```
   *
   * - Parameters:
   *   - name:      The name to ask for.
   *   - kind:      The record type to ask for.
   *   - eventLoop: The event loop to run on and complete the result on.
   * - Returns:     The running query.
   */
  @discardableResult
  public func query(_       name : String, kind: DNSRecord.Kind,
                    on eventLoop : EventLoop? = nil) -> Query
  {
    let query = Query(name: name, kind: kind, options: options,
                      eventLoop: eventLoop ?? eventLoopGroup.next())
    query.start()
    return query
  }

  /// Shuts the client down. Running queries are not affected.
  public func shutdown() -> EventLoopFuture<Void> {
    // Does nothing yet, just in case we want to add TCP pools later.
    eventLoopGroup.next().makeSucceededVoidFuture()
  }
}
