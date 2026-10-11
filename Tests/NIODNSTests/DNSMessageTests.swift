//
//  DNSMessageTests.swift
//  NIODNS
//
//  Created by Helge Hess.
//  Copyright © 2026 ZeeZide GmbH. All rights reserved.
//

import XCTest
import NIOCore
@testable import NIODNS

final class DNSMessageTests: XCTestCase {

  func testEncodeQuery() throws {
    let query = DNSMessage(id: 0x1234, name: "example.org", kind: .mx,
                           ednsPayloadSize: nil) // otherwise set to default
    let bytes = try query.toByteBuffer()
    XCTAssertEqual(bytes, ByteBuffer(bytes: [
      0x12, 0x34,             // id
      0x01, 0x00,             // flags: recursion desired
      0x00, 0x01,             // one question
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      7, 0x65, 0x78, 0x61, 0x6D, 0x70, 0x6C, 0x65, // example (7 chars)
      3, 0x6F, 0x72, 0x67,    // org  (3 chars)
      0,                      // root (empty string)
      0x00, 0x0F,             // MX   Type/Kind
      0x00, 0x01              // IN   Class
    ]))
  }

  func testEncodeQueryWithEDNS() throws {
    let query = DNSMessage(id: 1, name: "a.b", kind: .txt)
    let bytes = try query.toByteBuffer()
    // only one additional record? (EDNS)
    XCTAssertEqual(bytes.getInteger(at: 10, as: UInt16.self), 1) // ARCOUNT
    XCTAssertEqual(bytes.getBytes(at: bytes.readableBytes - 11, length: 11), [
      0,                      // root name (empty string)
      0x00, 0x29,             // OPT
      0x04, 0xD0,             // UDP payload size 1232
      0, 0, 0, 0,             // extended RCODE, version, flags
      0, 0                    // no options
    ])
    XCTAssertEqual(try DNSMessage(bytes: bytes).ednsPayloadSize, 1232)
  }

  func testEncodeQueryNames() throws {
    func question(_ name: String) throws -> ByteBuffer? {
      let query = DNSMessage(id: 1, name: name, kind: .a, ednsPayloadSize: nil)
      let bytes = try query.toByteBuffer()
      // the name is followed by the type and the class
      let length = bytes.readableBytes - DNSMessage.headerSize - 4
      return bytes.getSlice(at: DNSMessage.headerSize, length: length)
    }

    let abc  = ByteBuffer(bytes: [ 1, 0x61, 2, 0x62, 0x63, 0 ])
    let root = ByteBuffer(bytes: [ 0 ])
    XCTAssertEqual(try question("a.bc"),  abc)
    XCTAssertEqual(try question("a.bc."), abc)
    XCTAssertEqual(try question(""),      root)
    XCTAssertEqual(try question("."),     root)
  }

  func testEncodeQueryRejectsInvalidNames() {
    let longLabel = String(repeating: "a", count: 64)
    let longName  = Array(repeating: String(repeating: "a", count: 63), count:4)
                      .joined(separator: ".")
    for name in [ "a..b", ".a", longLabel + ".org", longName ] {
      XCTAssertThrowsError(try query(name, .a)) {
        XCTAssertEqual($0 as? DNSMessage.MessageError, .invalidName)
      }
    }
    XCTAssertNoThrow(try query(String(repeating: "a", count: 63) + ".org", .a))
  }

  func testEncodeCompressesNames() throws {
    let bytes = try response(.mx(preference: 10, exchange: "mail.EXAMPLE.org"))

    // The answer starts behind the header and the question (17 bytes).
    let answer = bytes.getBytes(at: 29, length: bytes.readableBytes - 29)
    XCTAssertEqual(answer, [
      0xC0, 0x0C,             // owner: pointer to the question name
      0x00, 0x0F,             // MX
      0x00, 0x01,             // IN
      0x00, 0x00, 0x01, 0x2C, // TTL 300
      0x00, 0x09,             // record data length
      0x00, 0x0A,             // preference
      4, 0x6D, 0x61, 0x69, 0x6C, // mail
      0xC0, 0x0C              // + pointer to `example.org`, any case
    ])
  }

  func testEncodeLeavesSRVAndNAPTRNamesUncompressed() throws {
    let bytes =
      try response(.srv(priority: 1, weight: 2, port: 3, target: "example.org"))
    let message = try DNSMessage(bytes: bytes)
    // The record data length behind the 29 bytes of header and question,
    // and 10 of the record: priority, weight, port + the name in full
    // (7 example 3 org 0).
    XCTAssertEqual(bytes.getInteger(at: 39, as: UInt16.self), 6 + 13)
    XCTAssertEqual(message.answers.first?.data,
                   .srv(priority: 1, weight: 2, port: 3,
                        target: "example.org"))
  }

  func testRoundTrip() throws {
    let data : [ DNSRecord.Data ] = [
      .a("192.0.2.1"), .aaaa("2001:db8::1"), .cname("www.example.org"),
      .ns("ns1.example.org"), .ptr("host.example.org"),
      .mx(preference: 10, exchange: "mail.example.org"),
      .txt([ "v=spf1 -all", String(repeating: "k", count: 255), "" ]),
      .soa(.init(mname: "ns1.example.org", rname: "hostmaster.example.org",
                 serial: 2026100401, refresh: 7200, retry: 3600,
                 expire: 1209600, minimum: 300)),
      .srv(priority: 5, weight: 10, port: 993, target: "imap.example.org"),
      .caa(flags: 128, tag: "issue", value: "letsencrypt.org"),
      .naptr(.init(order: 100, preference: 50, flags: "s",
                   services: "SIP+D2U", regexp: "",
                   replacement: "_sip._udp.example.org")),
      .tlsa(usage: 3, selector: 1, matchingType: 1,
            data: ByteBuffer(bytes: [ 0xDE, 0xAD, 0xBE, 0xEF ]))
    ]
    let records = data.enumerated().map { // a different TTL per record
      DNSRecord(name: "example.org", ttl: UInt32($0.offset), data: $0.element)
    }
    let ns   = DNSRecord (name: "example.org", ttl: 300,
                          data: .ns("ns2.example.org"))
    var sent = DNSMessage(id: 0xBEEF, flags: [ .response, .authoritative ],
                          questions: [ .init(name: "example.org", kind: .any) ],
                          answers: records, authorities: [ ns ],
                          additionals: [ .edns(payloadSize: 4096) ])
    sent.responseCode = .nameError

    let received = try DNSMessage(bytes: try sent.toByteBuffer())
    XCTAssertEqual(received.id,              0xBEEF)
    XCTAssertEqual(received.flags,           sent.flags)
    XCTAssertEqual(received.responseCode,    .nameError)
    XCTAssertTrue (received.isAuthoritative)
    XCTAssertEqual(received.questions,       sent.questions)
    XCTAssertEqual(received.answers.map { $0.data }, records.map { $0.data })
    XCTAssertEqual(received.answers.map { $0.kind }, records.map { $0.kind })
    XCTAssertEqual(received.answers.map { $0.ttl },  records.map { $0.ttl })
    XCTAssertEqual(Set(received.answers.map { $0.name }), [ "example.org" ])
    XCTAssertEqual(received.authorities.map { $0.data },
                   [ .ns("ns2.example.org") ])
    XCTAssertEqual(received.ednsPayloadSize, 4096)
  }

  func testEncodeWritesRawDataOfUnknownTypes() throws {
    let bytes = try response(.other(type: DNSRecord.Kind(rawValue: 99),
                                    rdata: ByteBuffer(bytes: [ 1, 2, 3 ])))
    let message = try DNSMessage(bytes: bytes)
    XCTAssertEqual(message.answers.first?.data,
                   .other(type: DNSRecord.Kind(rawValue: 99),
                          rdata: ByteBuffer(bytes: [ 1, 2, 3 ])))
  }

  func testEncodeRejectsInvalidRecordData() {
    let invalid : [ DNSRecord.Data ] = [
      .a("2001:db8::1"), .aaaa("192.0.2.1"), .a("example.org"),
      .txt([ String(repeating: "k", count: 256) ]),
      .mx(preference: 1, exchange: "a..b")
    ]
    for data in invalid {
      let record  = DNSRecord(name: "example.org", ttl: 300, data: data)
      let message = DNSMessage(id: 1, answers: [ record ])
      XCTAssertThrowsError(try message.toByteBuffer(), "\(data)")
    }
  }

  func testResponseToQuery() throws {
    let query    = try DNSMessage(bytes: try self.query("example.org", .mx))
    var response = DNSMessage(responseTo: query, responseCode: .refused)
    XCTAssertEqual(response.id, 7)
    XCTAssertEqual(response.questions, query.questions)
    XCTAssertEqual(response.flags.rawValue, 0x8105) // QR, RD, REFUSED
    XCTAssertEqual(response.responseCode, .refused)
    XCTAssertTrue (response.additionals.isEmpty)

    response.responseCode = .noError
    XCTAssertEqual(response.flags, [ .response, .recursionDesired ])
  }

  func testParseResponse() throws {
    let bytes = try response(.mx(preference: 10, exchange: "mail.example.org"))
    let message = try DNSMessage(bytes: bytes)

    XCTAssertEqual(message.id, 7)
    XCTAssertTrue (message.isResponse)
    XCTAssertFalse(message.isTruncated)
    XCTAssertEqual(message.responseCode, .noError)
    XCTAssertEqual(message.questions, [
      DNSMessage.Question(name: "example.org", kind: .mx)
    ])
    XCTAssertEqual(message.answers.count, 1)
    XCTAssertEqual(message.answers.first?.name, "example.org")
    XCTAssertEqual(message.answers.first?.kind, .mx)
    XCTAssertEqual(message.answers.first?.ttl,  300)
    XCTAssertEqual(message.answers.first?.data,
                   .mx(preference: 10, exchange: "mail.example.org"))
  }

  func testParseStartsAtReaderIndex() throws {
    var bytes = ByteBuffer(string: "junk")
    bytes.moveReaderIndex(forwardBy: 4)
    bytes.writeImmutableBuffer(try response(.a("192.0.2.1")))

    // Offsets and compression pointers are relative to the reader index.
    let message = try DNSMessage(bytes: bytes)
    XCTAssertEqual(message.answers.first?.data, .a("192.0.2.1"))
  }

  func testParseCompressedNameInRecordData() throws {
    // The exchange is `mail` followed by a pointer to the question name.
    let data  = ByteBuffer(bytes: [ 0, 20, 4, 0x6D, 0x61, 0x69, 0x6C,
                                    DNSMessage.pointerMarker, 0x0C ])
    let bytes   = try response(.other(type: .mx, rdata: data))
    let message = try DNSMessage(bytes: bytes)
    XCTAssertEqual(message.answers.first?.data,
                   .mx(preference: 20, exchange: "mail.example.org"))
  }

  func testParseRejectsPointerLoops() throws {
    // The exchange starts at offset 43: 12 bytes header, 17 question, 12
    // up to the record data, 2 for the preference. One name points at
    // itself, the other one forwards.
    for target : UInt8 in [ 43, 60 ] {
      let data  = ByteBuffer(bytes: [ 0, 20, DNSMessage.pointerMarker, target ])
      let bytes = try response(.other(type: .mx, rdata: data))
      XCTAssertEqual(bytes.readableBytes, 45)
      XCTAssertEqual(bytes.getInteger(at: 43, as: UInt8.self),
                     DNSMessage.pointerMarker)
      XCTAssertThrowsError(try DNSMessage(bytes: bytes)) {
        XCTAssertEqual($0 as? DNSMessage.MessageError, .invalidPointer)
      }
    }
  }

  func testParseTXTChunks() throws {
    let long  = String(repeating: "k", count: 255)
    let bytes = try response(.txt([ "v=DKIM1; p=abc", long, "tail" ]),
                             .txt([ "second" ]))
    let message = try DNSMessage(bytes: bytes)
    XCTAssertEqual(message.answers.map { $0.data }, [
      .txt([ "v=DKIM1; p=abc", long, "tail" ]), .txt([ "second" ])
    ])
  }

  func testParseKeepsUnknownTypesWithRawData() throws {
    // type 99 (SPF, obsolete): not decoded, but its bytes are kept
    let bytes = try response(.other(type: DNSRecord.Kind(rawValue: 99),
                                    rdata: ByteBuffer(bytes: [ 1, 2, 3 ])))
    let message = try DNSMessage(bytes: bytes)
    XCTAssertEqual(message.answers.count, 1)
    XCTAssertEqual(message.answers.first?.kind, DNSRecord.Kind(rawValue: 99))
    XCTAssertEqual(message.answers.first?.kind.description, "TYPE99")
    XCTAssertEqual(message.answers.first?.data,
                   .other(type: DNSRecord.Kind(rawValue: 99),
                          rdata: ByteBuffer(bytes: [ 1, 2, 3 ])))
  }

  func testParseTruncatedMessage() throws {
    let complete = try response(.mx(preference: 10, exchange: "a.example.org"),
                                .mx(preference: 20, exchange: "b.example.org"))
    var cut = complete
    cut.moveWriterIndex(to: complete.writerIndex - 5) // cut the second one

    // W/o the flag the message is malformed ...
    XCTAssertThrowsError(try DNSMessage(bytes: cut)) {
      XCTAssertEqual($0 as? DNSMessage.MessageError, .truncated)
    }

    // ... w/ it, the complete records are kept.
    let flags : DNSMessage.Flags = [ .response, .recursionDesired, .truncated ]
    cut.setInteger(flags.rawValue, at: cut.readerIndex + 2)
    let message = try DNSMessage(bytes: cut)
    XCTAssertTrue (message.isTruncated)
    XCTAssertEqual(message.answers.map { $0.data }, [
      .mx(preference: 10, exchange: "a.example.org")
    ])

    // A header cut short is malformed in any case.
    XCTAssertThrowsError(try DNSMessage(
      bytes: complete.getSlice(at: 0, length: 7) ?? ByteBuffer()))
  }

  func testParseRejectsMalformedRecordData() throws {
    // An address w/ 5 bytes, and a name w/ a label running past the data.
    let cases : [ ( DNSRecord.Kind, ByteBuffer, DNSMessage.MessageError ) ] = [
      ( .a,     ByteBuffer(bytes: [ 192, 0, 2, 1, 7 ]), .invalidRecordData ),
      ( .cname, ByteBuffer(bytes: [ 5, 0x61, 0x62, 0x63, 0 ]), .truncated )
    ]
    for ( type, rdata, expected ) in cases {
      let bytes = try response(.other(type: type, rdata: rdata))
      XCTAssertThrowsError(try DNSMessage(bytes: bytes), "\(type)") {
        XCTAssertEqual($0 as? DNSMessage.MessageError, expected)
      }
    }
  }

  func testParseFromRawSpan() throws {
    let bytes = try response(.a("192.0.2.1"))
    let array = bytes.getBytes(at: 0, length: bytes.readableBytes) ?? []
    let message = try DNSMessage(bytes: array.span.bytes)
    XCTAssertEqual(message.answers.first?.data,  .a("192.0.2.1"))
    XCTAssertEqual(message.answers.first?.class, .in)
    XCTAssertEqual(message.questions.first?.class.description, "IN")
    XCTAssertEqual(DNSRecord.Class(rawValue: 42).description,  "CLASS42")
  }

  func testResponseCodes() throws {
    let bytes   = try response(responseCode: .nameError)
    let message = try DNSMessage(bytes: bytes)
    XCTAssertEqual(message.responseCode, .nameError)
    XCTAssertEqual(message.responseCode.description, "NXDOMAIN")
    XCTAssertEqual(DNSMessage.ResponseCode(rawValue: 9).description, "RCODE9")
  }

  func testReverseName() throws {
    XCTAssertEqual(
      try SocketAddress(ipAddress: "192.0.2.25", port: 0).dnsReverseName,
      "25.2.0.192.in-addr.arpa"
    )
    XCTAssertEqual(
      try SocketAddress(ipAddress: "2001:db8::567:89ab", port: 0)
        .dnsReverseName,
      "b.a.9.8.7.6.5.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa"
    )
  }

  func testReadIPAddress() throws {
    var writer = DNSWriter(buffer: ByteBuffer())
    try writer.writeIPAddress("2001:DB8:0:0::1", as: .inet6)
    XCTAssertEqual(writer.buffer.readableBytes, 16)

    writer.buffer.writeBytes([ 10, 0, 0, 255, 1, 2, 3 ])
    
    let bytes = writer.buffer
    let span  = bytes.readableBytesSpan

    var reader = DNSReader(span)
    let v6     = try reader.readIPAddress(count: 16)
    let v4     = try reader.readIPAddress(count: 4)
    XCTAssertEqual(v6, "2001:db8::1")
    XCTAssertEqual(v4, "10.0.0.255")

    do throws(DNSMessage.MessageError) {
      _ = try reader.readIPAddress(count: 3)
      XCTFail("expected invalidRecordData")
    }
    catch { XCTAssertEqual(error, .invalidRecordData) }

    do throws(DNSMessage.MessageError) {
      _ = try reader.readIPAddress(count: 4) // only 3 bytes left
      XCTFail("expected truncated")
    }
    catch { XCTAssertEqual(error, .truncated) }
  }

  func testCanonicalName() {
    XCTAssertEqual(DNSMessage.canonicalName("WWW.Example.org."),
                   "www.example.org")
    XCTAssertEqual(DNSMessage.canonicalName("example.org"), "example.org")
    XCTAssertEqual(DNSMessage.canonicalName("."), "")
    XCTAssertEqual(DNSMessage.canonicalName(""),  "")
  }


  // MARK: - Helpers

  private func query(_ name: String, _ type: DNSRecord.Kind) throws
               -> ByteBuffer
  {
    try DNSMessage(id: 7, name: name, kind: type).toByteBuffer()
  }

  /**
   * The encoded response to a query for `example.org`, asking for the kind of
   * the first answer (`A` if there is none).
   */
  private func response(_    answers : DNSRecord.Data...,
                        responseCode : DNSMessage.ResponseCode = .noError)
               throws -> ByteBuffer
  {
    let kind  = answers.first?.kind ?? .a
    let query = DNSMessage(id: 7, flags: .recursionDesired, questions: [
      DNSMessage.Question(name: "example.org", kind: kind)
    ])
    let records = answers.map {
      DNSRecord(name: "example.org", ttl: 300, data: $0)
    }
    return try DNSMessage(responseTo: query, responseCode: responseCode,
                          answers: records).toByteBuffer()
  }
}
