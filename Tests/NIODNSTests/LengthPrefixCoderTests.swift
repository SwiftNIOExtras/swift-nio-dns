//
//  LengthPrefixCoderTests.swift
//  NIODNSTests
//
//  Created by Helge Hess.
//  Copyright © 2026 ZeeZide GmbH. All rights reserved.
//

import XCTest
import NIOCore
import NIOEmbedded
import NIODNS

/// The length prefix coders, as used for DNS over TCP.
final class LengthPrefixCoderTests: XCTestCase {

  func testDecoderSplitsAndJoinsFrames() throws {
    let channel = try makeChannel(); defer { _ = try? channel.finish() }

    // Two messages and the start of a third in one read, the rest of the
    // third in a second one.
    try channel.writeInbound(ByteBuffer(bytes: [ 0, 2, 0xA, 0xB,
                                                 0, 1, 0xC,
                                                 0, 3, 0xD ]))
    XCTAssertEqual(try channel.readInbound(), ByteBuffer(bytes: [ 0xA, 0xB ]))
    XCTAssertEqual(try channel.readInbound(), ByteBuffer(bytes: [ 0xC ]))
    XCTAssertNil  (try channel.readInbound(as: ByteBuffer.self))

    try channel.writeInbound(ByteBuffer(bytes: [ 0xE, 0xF ]))
    XCTAssertEqual(try channel.readInbound(),
                   ByteBuffer(bytes: [ 0xD, 0xE, 0xF ]))
  }

  func testDecoderDropsIncompleteFrameAtEnd() throws {
    let channel = try makeChannel()
    try channel.writeInbound(ByteBuffer(bytes: [ 0, 1, 0xA, 0, 5, 0xB ]))

    XCTAssertEqual  (try channel.readInbound(), ByteBuffer(bytes: [ 0xA ]))
    XCTAssertNoThrow(try channel.finish()) // no leftover data error
    XCTAssertNil    (try channel.readInbound(as: ByteBuffer.self))
  }

  func testEncoderPrefixesLength() throws {
    let channel = try makeChannel(); defer { _ = try? channel.finish() }

    try channel.writeOutbound(ByteBuffer(bytes: [ 0xA, 0xB, 0xC ]))
    XCTAssertEqual(try channel.readOutbound(),
                   ByteBuffer(bytes: [ 0, 3, 0xA, 0xB, 0xC ]))

    var out     = ByteBuffer()
    let large   = ByteBuffer(repeating: 0, count: Int(UInt16.max) + 1)
    let encoder = LengthPrefixEncoder<UInt16>()

    XCTAssertThrowsError(try encoder.encode(data: large, out: &out)) {
      XCTAssertEqual($0 as? LengthPrefixError, .messageTooLarge)
    }
    XCTAssertEqual(out.readableBytes, 0)
  }

  func testUInt32Prefix() throws {
    let channel = EmbeddedChannel()
    try channel.pipeline.syncOperations.addHandlers(
      ByteToMessageHandler(LengthPrefixDecoder<UInt32>()),
      MessageToByteHandler(LengthPrefixEncoder<UInt32>())
    )
    defer { _ = try? channel.finish() }

    try channel.writeOutbound(ByteBuffer(bytes: [ 0xA, 0xB ]))
    XCTAssertEqual(try channel.readOutbound(),
                   ByteBuffer(bytes: [ 0, 0, 0, 2, 0xA, 0xB ]))

    try channel.writeInbound(ByteBuffer(bytes: [ 0, 0, 0, 1, 0xC ]))
    XCTAssertEqual(try channel.readInbound(), ByteBuffer(bytes: [ 0xC ]))
  }

  // MARK: - Helpers

  private func makeChannel() throws -> EmbeddedChannel {
    let channel = EmbeddedChannel()
    try channel.pipeline.syncOperations.addHandlers(
      ByteToMessageHandler(LengthPrefixDecoder<UInt16>()),
      MessageToByteHandler(LengthPrefixEncoder<UInt16>())
    )
    return channel
  }

}
