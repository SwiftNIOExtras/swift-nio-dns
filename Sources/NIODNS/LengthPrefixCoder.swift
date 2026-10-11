//
//  NIOMessageCoders.swift
//  NIODNS
//
//  Created by Helge Hess.
//  Copyright © 2026 ZeeZide GmbH. All rights reserved.
//

import NIOCore

/**
 * Splits a stream into the messages, each of which is prefixed w/ its length.
 *
 * An incomplete message at the end of the stream is dropped.
 */
package struct LengthPrefixDecoder<Length>: ByteToMessageDecoder
  where Length: FixedWidthInteger & UnsignedInteger
{
  package typealias InboundOut = ByteBuffer

  @inlinable package init() {}

  /// - Throws: ``LengthPrefixError/messageTooLarge``
  @inlinable
  package mutating func decode(context: ChannelHandlerContext,
                               buffer: inout ByteBuffer) throws -> DecodingState
  {
    let prefixSize = MemoryLayout<Length>.size
    guard let len = buffer.getInteger(at: buffer.readerIndex, as:Length.self)
     else { return .needMoreData }

    guard let count = Int(exactly: len), count <= Int.max - prefixSize else {
      throw LengthPrefixError.messageTooLarge
    }

    guard let message = buffer
      .getSlice(at: buffer.readerIndex + prefixSize, length: count) else
    {
      return .needMoreData
    }

    buffer.moveReaderIndex(forwardBy: prefixSize + count)
    context.fireChannelRead(wrapInboundOut(message))
    return .continue
  }

  @inlinable
  package mutating func decodeLast(context : ChannelHandlerContext,
                                   buffer  : inout ByteBuffer, seenEOF: Bool)
                          throws -> DecodingState
  {
    while case .continue = try decode(context: context, buffer: &buffer) {}
    buffer.moveReaderIndex(to: buffer.writerIndex) // the incomplete rest
    return .needMoreData
  }
}

/// Prefixes each message w/ its length, also: ``LengthPrefixDecoder``.
package struct LengthPrefixEncoder<Length>: MessageToByteEncoder
  where Length: FixedWidthInteger & UnsignedInteger
{
  package typealias OutboundIn = ByteBuffer

  @inlinable
  package init() {}

  /// - Throws: ``LengthPrefixError/messageTooLarge``
  @inlinable
  package func encode(data: ByteBuffer, out: inout ByteBuffer) throws {
    guard let length = Length(exactly: data.readableBytes) else {
      throw LengthPrefixError.messageTooLarge
    }
    out.writeInteger(length)
    out.writeImmutableBuffer(data)
  }
}

package enum LengthPrefixError: Swift.Error, Hashable, Sendable {
  case messageTooLarge
}
