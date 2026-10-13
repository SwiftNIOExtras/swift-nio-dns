//
//  DNSClientTests.swift
//  NIODNSClient
//
//  Created by Helge Hess.
//  Copyright © 2026 ZeeZide GmbH. All rights reserved.
//

import XCTest
import NIOCore
import NIOPosix
import NIOConcurrencyHelpers
import NIODNS
import NIODNSServer
@testable import NIODNSClient

final class DNSClientTests: XCTestCase {

  private var servers = [ DNSServer ]()
  private let group   = MultiThreadedEventLoopGroup(numberOfThreads: 1)

  override func tearDown() {
    for server in servers { try? server.close().wait() }
    servers.removeAll()
    try? group.syncShutdownGracefully()
    super.tearDown()
  }

  func testAnswer() throws {
    let asked  = NIOLockedValueBox([ DNSMessage.Question ]())
    let answer = answering(.mx(preference: 10, exchange: "mail.zeezide.de"),
                           .mx(preference: 20, exchange: "backup.zeezide.de"))
    let server = try makeServer { query in
      asked.withLockedValue { $0 += query.message.questions }
      return answer(query)
    }

    let message = try query("zeezide.de", .mx, server).result.wait()
    XCTAssertEqual(message.responseCode, .noError)
    XCTAssertEqual(message.answers.map { $0.data }, [
      .mx(preference: 10, exchange: "mail.zeezide.de"),
      .mx(preference: 20, exchange: "backup.zeezide.de")
    ])
    XCTAssertEqual(asked.withLockedValue { $0 }, [
      DNSMessage.Question(name: "zeezide.de", kind: .mx)
    ])
    XCTAssertEqual(server.queryCounts.udp, 1)
    XCTAssertEqual(server.queryCounts.tcp, 0)
  }

  func testNameError() throws {
    let server  = try makeServer(answering(responseCode: .nameError))
    let message = try query("nope.zeezide.de", .mx, server, retries: 2)
      .result.wait()
    XCTAssertEqual(message.responseCode, .nameError)
    XCTAssertEqual(server.queryCounts.udp, 1) // a definitive answer, no retry
  }

  func testInvalidNameAndNoServers() throws {
    let server = try makeServer { _ in .drop }
    XCTAssertEqual(failure(of: query("a..b", .a, server)), .invalidName)
    XCTAssertEqual(server.queryCounts.udp, 0)
    XCTAssertEqual(failure(of: query("zeezide.de", .a)), .noServers)
  }


  func testTruncatedAnswer() throws {
    // 3 x 255 bytes do not fit into the 512 bytes of a UDP response w/o
    // EDNS(0), the server sends it truncated.
    let key    = String(repeating: "A", count: 255)
    let server = try makeServer(answering(.txt([ "v=DKIM1; p=", key,key,key ])))
    let options = DNSClient.Options(servers: [ server.localAddress ],
                                    ednsPayloadSize: nil) // explicit none
    let message = try DNSClient(options: options, eventLoopGroup: group)
      .query("mail._domainkey.zeezide.de", kind: .txt).result.wait()
    XCTAssertEqual(message.answers.first?.data,
                   .txt([ "v=DKIM1; p=", key, key, key ]))
    XCTAssertEqual(server.queryCounts.udp, 1)
    XCTAssertEqual(server.queryCounts.tcp, 1)
  }

  func testFailingServerFallsThrough() throws {
    let broken  = try makeServer(answering(responseCode: .serverFailure))
    let working = try makeServer(answering(.a("192.0.2.7")))

    let message = try query("zeezide.de", .a, broken, working).result.wait()
    XCTAssertEqual(message.answers.first?.data, .a("192.0.2.7"))
    XCTAssertEqual(broken .queryCounts.udp, 1)
    XCTAssertEqual(working.queryCounts.udp, 1)
  }

  func testServerFailure() throws {
    let refusing = try makeServer(answering(responseCode: .refused))
    XCTAssertEqual(failure(of: query("zeezide.de", .a, refusing, retries: 1)),
                   .serverFailure(.refused))
    XCTAssertEqual(refusing.queryCounts.udp, 2)
  }

  func testTimeout() throws {
    let silent = try makeServer { _ in .drop }
    XCTAssertEqual(failure(of: query("zeezide.de", .mx, silent,
                                     timeout: .milliseconds(50), retries: 1)),
                   .timeout)
    XCTAssertEqual(silent.queryCounts.udp, 2)
  }

  func testSilentServerFallsThrough() throws {
    let silent  = try makeServer { _ in .drop }
    let working = try makeServer(answering(.a("192.0.2.8")))
    let message = try query("zeezide.de", .a, silent, working,
                            timeout: .milliseconds(50)).result.wait()
    XCTAssertEqual(message.answers.first?.data, .a("192.0.2.8"))
  }

  func testAnswerToAnotherQueryIsIgnored() throws {
    // Same question, but not the id we sent: a spoofed or stale packet.
    let server = try makeServer { query in
      var response = DNSMessage(responseTo: query.message)
      response.id &+= 1
      return .message(response)
    }
    XCTAssertEqual(failure(of: query("zeezide.de", .a, server,
                                     timeout: .milliseconds(50))),
                   .timeout)
  }

  func testAnswerToAnotherQuestionIsIgnored() throws {
    // Our id, but a different name in the question.
    let server = try makeServer { query in
      var response = DNSMessage(responseTo: query.message)
      response.questions = [ .init(name: "other.org", kind: .a) ]
      return .message(response)
    }
    XCTAssertEqual(failure(of: query("zeezide.de", .a, server,
                                     timeout: .milliseconds(50))),
                   .timeout)
  }

  func testMalformedResponseIsIgnored() throws {
    let server = try makeServer { query in
      var bytes = ByteBuffer()
      bytes.writeInteger(query.message.id)
      bytes.writeBytes([ 0x81, 0x80, 0, 1 ]) // a question, but no more
      return .raw(bytes)
    }
    XCTAssertEqual(failure(of: query("zeezide.de", .a, server,
                                     timeout: .milliseconds(50))), .timeout)
  }

  func testCancel() throws {
    let silent = try makeServer { _ in .drop }
    let query  = self.query("zeezide.de", .a, silent, timeout: .seconds(30))
    query.cancel()
    XCTAssertThrowsError(try query.result.wait()) {
      XCTAssertEqual($0 as? DNSClient.QueryError, .cancelled)
    }
  }

  func testAsyncAnswer() async throws {
    let server  = try makeServer(answering(.a("192.0.2.4")))
    let message = try await client([ server ]).query("zeezide.de", kind: .a)
    XCTAssertEqual(message.answers.map { $0.data }, [ .a("192.0.2.4") ])
  }

  func testAsyncFailure() async throws {
    let refusing = try makeServer(answering(responseCode: .refused))
    do {
      let message = try await client([ refusing ]).query("zeezide.de", kind: .a)
      XCTFail("expected a failure, got \(message)")
    }
    catch {
      XCTAssertEqual(error as? DNSClient.QueryError, .serverFailure(.refused))
    }
  }

  func testAsyncCancelByTask() async throws {
    let silent = try makeServer { _ in .drop }
    let client = self.client([ silent ], timeout: .seconds(30))
    let task   = Task { try await client.query("zeezide.de", kind: .a) }
    task.cancel()
    do {
      let message = try await task.value
      XCTFail("expected a failure, got \(message)")
    }
    catch {
      XCTAssertEqual(error as? DNSClient.QueryError, .cancelled)
    }
  }


  // MARK: - Helpers

  private func makeServer(_ responder: @escaping DNSServer.Responder)
                 throws -> DNSServer
  {
    let server = try DNSServer.bind(group: group, responder: responder).wait()
    servers.append(server)
    return server
  }

  private func client(_ servers : [ DNSServer ],
                      timeout   : TimeAmount = .seconds(2), retries: Int = 0)
               -> DNSClient
  {
    let options = DNSClient.Options(servers: servers.map { $0.localAddress },
                                    timeout: timeout, retries: retries)
    return DNSClient(options: options, eventLoopGroup: group)
  }

  private func query(_    name : String, _ type: DNSRecord.Kind,
                     _ servers : DNSServer...,
                     timeout   : TimeAmount = .seconds(2), retries: Int = 0)
               -> DNSClient.Query
  {
    client(servers, timeout: timeout, retries: retries).query(name, kind: type)
  }

  /// Waits for a query expected to fail, returns the error.
  private func failure(of query : DNSClient.Query,
                       file     : StaticString = #filePath, line: UInt = #line)
               -> DNSClient.QueryError?
  {
    do {
      let message = try query.result.wait()
      XCTFail("expected a failure, got \(message)", file: file, line: line)
      return nil
    }
    catch { return error as? DNSClient.QueryError }
  }

  /// A responder answering every query w/ the given data.
  private func answering(_ data: DNSRecord.Data...,
                         responseCode: DNSMessage.ResponseCode = .noError)
               -> DNSServer.Responder
  {
    return { query in
      let answers = data.map {
        DNSRecord(name: query.question?.name ?? "", ttl: 300, data: $0)
      }
      return .message(DNSMessage(responseTo: query.message,
                                 responseCode: responseCode,
                                 answers: answers))
    }
  }
}
