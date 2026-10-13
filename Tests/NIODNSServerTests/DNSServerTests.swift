//
//  DNSServerTests.swift
//  NIODNSServer
//
//  Created by Helge Hess.
//  Copyright © 2026 ZeeZide GmbH. All rights reserved.
//

import XCTest
import NIOCore
import NIOPosix
import NIODNS
import NIODNSClient
@testable import NIODNSServer

final class DNSServerTests: XCTestCase {

  private var server : DNSServer?

  override func tearDown() {
    try? server?.close().wait()
    server = nil
    super.tearDown()
  }

  private let zone = DNSServer.zone([
    DNSRecord(name: "zeezide.de",       ttl: 300, data: .a("192.0.2.1")),
    DNSRecord(name: "zeezide.de",       ttl: 300,
              data: .mx(preference: 10, exchange: "mail.zeezide.de")),
    DNSRecord(name: "Mail.ZeeZide.de.", ttl:  60, data: .a("192.0.2.25")),
    DNSRecord(name: "www.zeezide.de",   ttl: 300, data: .cname("zeezide.de")),
    DNSRecord(name: "loop.zeezide.de",  ttl: 300,
              data: .cname("loop.zeezide.de"))
  ])


  func testZoneAnswers() throws {
    let server  = try start(zone)
    let message = try ask(server, "zeezide.de", .mx)
    XCTAssertEqual(message.responseCode, .noError)
    XCTAssertTrue (message.isAuthoritative)
    XCTAssertEqual(message.answers.map { $0.data }, [
      .mx(preference: 10, exchange: "mail.zeezide.de")
    ])
    XCTAssertEqual(try ask(server, "MAIL.zeezide.de.", .a).answers.map {
      $0.data
    }, [ .a("192.0.2.25") ])
  }

  func testZoneFollowsCNAMEs() throws {
    let server  = try start(zone)
    let message = try ask(server, "www.zeezide.de", .a)
    XCTAssertEqual(message.answers.map { $0.data }, [
      .cname("zeezide.de"), .a("192.0.2.1")
    ])
    XCTAssertEqual(try ask(server, "loop.zeezide.de", .a).answers.map {
      $0.data
    }, [ .cname("loop.zeezide.de") ])
  }

  func testZoneAnswersANYWithAllRecords() throws {
    let server = try start(zone)
    XCTAssertEqual(try ask(server, "zeezide.de", .any).answers.count, 2)
  }

  func testZoneNoDataAndNameError() throws {
    let server = try start(zone)
    let noData = try ask(server, "zeezide.de", .txt)
    XCTAssertEqual(noData.responseCode, .noError)
    XCTAssertTrue (noData.answers.isEmpty)

    let missing = try ask(server, "nope.zeezide.de", .a)
    XCTAssertEqual(missing.responseCode, .nameError)
    XCTAssertTrue (missing.answers.isEmpty)
  }


  func testLargeResponseIsTruncatedOverUDP() throws {
    let key    = String(repeating: "k", count: 255)
    let server = try start(DNSServer.zone([
      DNSRecord(name: "zeezide.de", ttl: 300, data: .txt([ key, key, key ]))
    ]))

    // W/o EDNS(0) only 512 bytes fit: truncated, the client goes TCP.
    let small = try ask(server, "zeezide.de", .txt, ednsPayloadSize: nil)
    XCTAssertEqual(small.answers.first?.data, .txt([ key, key, key ]))
    XCTAssertEqual(server.queryCounts.udp, 1)
    XCTAssertEqual(server.queryCounts.tcp, 1)

    // W/ it, it fits into UDP.
    let large = try ask(server, "zeezide.de", .txt)
    XCTAssertEqual(large.answers.first?.data, .txt([ key, key, key ]))
    XCTAssertEqual(server.queryCounts.udp, 2)
    XCTAssertEqual(server.queryCounts.tcp, 1)
  }

  func testSeveralQueriesOverOneTCP() throws {
    let server = try start(zone)
    let names  = [ "zeezide.de", "www.zeezide.de", "nope.zeezide.de" ]
    let group  = MultiThreadedEventLoopGroup.singleton
    let client = try ClientBootstrap(group: group)
                       .connect(to: server.localAddress).wait()
    defer { try? client.close().wait() }

    // All queries in one write, each w/ its length prefix.
    var queries = ByteBuffer()
    for ( id, name ) in names.enumerated() {
      let query = try DNSMessage(id: UInt16(id), name: name, kind: .a)
        .toByteBuffer()
      try LengthPrefixEncoder<UInt16>().encode(data: query, out: &queries)
    }
    let collector = ResponseCollector<ByteBuffer>(stream: client.eventLoop,
                                                  expected: names.count)
    try client.eventLoop.submit {
      try client.pipeline.syncOperations.addHandlers(
        ByteToMessageHandler(LengthPrefixDecoder<UInt16>()), collector)
    }.wait()
    try client.writeAndFlush(queries).wait()

    let responses = try collector.done.futureResult.wait()
      .sorted { $0.id < $1.id }
    XCTAssertEqual(responses.map { $0.questions.first?.name }, names)
    XCTAssertEqual(responses.map { $0.responseCode },
                   [ .noError, .noError, .nameError ])
    XCTAssertEqual(server.queryCounts.tcp, 3)
  }

  func testMalformedQueryGetsFormatError() throws {
    let server = try start(zone)
    let group  = MultiThreadedEventLoopGroup.singleton
    let client = try DatagramBootstrap(group: group)
      .bind(host: "127.0.0.1", port: 0).wait()
    defer { try? client.close().wait() }

    let collector = ResponseCollector<AddressedEnvelope<ByteBuffer>>(
      datagrams: client.eventLoop, expected: 1)
    try client.pipeline.addHandler(collector).wait()
    // A header announcing a question, but none follows.
    let query = ByteBuffer(bytes: [ 0xAB, 0xCD, 0x01, 0x00, 0, 1,
                                    0, 0, 0, 0, 0, 0 ])
    try client.writeAndFlush(AddressedEnvelope(
      remoteAddress: server.localAddress, data: query)).wait()

    let response = try collector.done.futureResult.wait().first
    XCTAssertEqual(response?.id, 0xABCD)
    XCTAssertEqual(response?.responseCode, .formatError)
  }

  func testDeferredAndRawResponses() throws {
    let server = try start { query in
      if query.question?.name == "raw.zeezide.de" {
        var response = DNSMessage(responseTo: query.message)
        response.answers = [ DNSRecord(name: "raw.zeezide.de",
                                       ttl: 1, data: .a("192.0.2.9")) ]
        return .raw((try? response.toByteBuffer()) ?? ByteBuffer())
      }
      let later = query.eventLoop.scheduleTask(in: .milliseconds(20)) {
        DNSServer.Response.message(DNSMessage(responseTo: query.message,
                                              responseCode: .refused))
      }
      return .deferred(later.futureResult)
    }

    XCTAssertEqual(try ask(server, "raw.zeezide.de", .a).answers.map {
      $0.data
    }, [ .a("192.0.2.9") ])
    XCTAssertThrowsError(try ask(server, "later.zeezide.de", .a)) {
      XCTAssertEqual($0 as? DNSClient.QueryError, .serverFailure(.refused))
    }
  }


  // MARK: - Helpers

  private func start(_ responder: @escaping DNSServer.Responder)
                 throws -> DNSServer
  {
    let server = try DNSServer.bind(responder: responder).wait()
    self.server = server
    return server
  }

  private func ask(_ server: DNSServer, _ name: String, _ type: DNSRecord.Kind,
                   ednsPayloadSize: UInt16? = DNSMessage.defaultEDNSPayloadSize)
    throws -> DNSMessage
  {
    let options = DNSClient.Options(servers: [ server.localAddress ],
                                    retries: 0,
                                    ednsPayloadSize: ednsPayloadSize)
    return try DNSClient(options: options).query(name, kind: type).result.wait()
  }
}
