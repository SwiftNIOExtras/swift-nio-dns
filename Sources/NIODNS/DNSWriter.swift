//
//  DNSWriter.swift
//  NIODNS
//
//  Created by Helge Hess.
//  Copyright © 2026 ZeeZide GmbH. All rights reserved.
//

import NIOCore
#if canImport(Darwin)
  import Darwin
#elseif canImport(Glibc)
  import Glibc
#elseif canImport(Musl)
  import Musl
#endif

/**
 * Writes a DNS message to a ``ByteBuffer``.
 *
 * Keeps track of the names written, so that later ones can end in a
 * compression pointer to them.
 */
struct DNSWriter {

  typealias MessageError = DNSMessage.MessageError

  var buffer : ByteBuffer

  /// The index of the message start, for relative compression pointers.
  let messageStart : Int

  /// The offsets of the names (and their suffixes) written so far.
  private var names = [ String : Int ]()

  /// Starts a message at the writer index of the buffer.
  init(buffer: consuming ByteBuffer) {
    self.messageStart = buffer.writerIndex
    self.buffer       = buffer
  }


  // MARK: - Message

  mutating func write(_ message: DNSMessage) throws(MessageError) {
    buffer.writeInteger(message.id)
    buffer.writeInteger(message.flags.rawValue)
    buffer.writeInteger(try count(of: message.questions))
    buffer.writeInteger(try count(of: message.answers))
    buffer.writeInteger(try count(of: message.authorities))
    buffer.writeInteger(try count(of: message.additionals))

    for question in message.questions {
      try writeName(question.name)
      buffer.writeInteger(question.kind.rawValue)
      buffer.writeInteger(question.class.rawValue)
    }

    for record in message.answers     { try write(record) }
    for record in message.authorities { try write(record) }
    for record in message.additionals { try write(record) }
  }

  private func count<T>(of section: [ T ]) throws(MessageError) -> UInt16 {
    guard let count = UInt16(exactly: section.count) else {
      throw .tooLarge
    }
    return count
  }


  // MARK: - Records

  mutating func write(_ record: DNSRecord) throws(MessageError) {
    try writeName(record.name)
    buffer.writeInteger(record.kind.rawValue)
    buffer.writeInteger(record.class.rawValue)
    buffer.writeInteger(record.ttl)

    let lengthIndex = buffer.writerIndex
    buffer.writeInteger(UInt16(0)) // patched below
    try write(record.data)
    guard let length = UInt16(exactly: buffer.writerIndex - lengthIndex - 2)
    else {
      throw .tooLarge
    }
    buffer.setInteger(length, at: lengthIndex)
  }

  /**
   * Writes the ``DNSRecord/Data``. Names are compressed, except in the data
   * of types newer than the original DNS ones.
   */
  mutating func write(_ data: DNSRecord.Data) throws(MessageError) {
    switch data {
      case .a    (let address) : try writeIPAddress(address, as: .inet)
      case .aaaa (let address) : try writeIPAddress(address, as: .inet6)
      case .cname(let target)  : try writeName(target)
      case .ns   (let target)  : try writeName(target)
      case .ptr  (let target)  : try writeName(target)

      case .mx(let preference, let exchange):
        buffer.writeInteger(preference)
        try writeName(exchange)

      case .txt(let chunks):
        for chunk in chunks { try writeCharacterString(chunk) }

      case .soa(let soa):
        try writeName(soa.mname)
        try writeName(soa.rname)
        buffer.writeInteger(soa.serial)
        buffer.writeInteger(soa.refresh)
        buffer.writeInteger(soa.retry)
        buffer.writeInteger(soa.expire)
        buffer.writeInteger(soa.minimum)

      case .srv(let priority, let weight, let port, let target):
        buffer.writeInteger(priority)
        buffer.writeInteger(weight)
        buffer.writeInteger(port)
        try writeName(target, compress: false)

      case .caa(let flags, let tag, let value):
        buffer.writeInteger(flags)
        try writeCharacterString(tag)
        buffer.writeString(value)

      case .naptr(let naptr):
        buffer.writeInteger(naptr.order)
        buffer.writeInteger(naptr.preference)
        try writeCharacterString(naptr.flags)
        try writeCharacterString(naptr.services)
        try writeCharacterString(naptr.regexp)
        try writeName(naptr.replacement, compress: false)

      case .tlsa(let usage, let selector, let matchingType, let data):
        buffer.writeInteger(usage)
        buffer.writeInteger(selector)
        buffer.writeInteger(matchingType)
        buffer.writeImmutableBuffer(data)

      case .other(_, let rdata):
        buffer.writeImmutableBuffer(rdata)
    }
  }


  // MARK: - Values

  /// Writes an IP address in presentation format as its 4 (`.inet`) or 16
  /// (`.inet6`) bytes.
  mutating func writeIPAddress(_ address: String,
                               as family: NIOBSDSocket.ProtocolFamily)
                  throws(MessageError)
  {
    switch ( try? SocketAddress(ipAddress: address, port: 0), family ) {
      case ( .v4(let address)?, .inet ):
        withUnsafeBytes(of: address.address.sin_addr) {
          _ = buffer.writeBytes($0)
        }
      case ( .v6(let address)?, .inet6 ):
        withUnsafeBytes(of: address.address.sin6_addr) {
          _ = buffer.writeBytes($0)
        }
      default:
        throw .invalidRecordData
    }
  }

  /// Writes a length prefixed string, as used in `TXT` and `NAPTR` records.
  mutating func writeCharacterString(_ string: String) throws(MessageError) {
    guard let length = UInt8(exactly: string.utf8.count) else {
      throw .invalidRecordData
    }
    buffer.writeInteger(length)
    buffer.writeString(string)
  }

  /**
   * Writes a domain name as labels. A trailing dot is optional.
   *
   * W/ `compress` the name ends in a pointer to the longest suffix written
   * before. The suffixes written are remembered either way.
   *
   * - Parameters:
   *   - name:     ASCII domain name.
   *   - compress: Whether the name may end in a pointer.
   * - Throws:     ``DNSMessage/MessageError/invalidName`` for empty or
   *               overlong labels, or more than 255 bytes.
   */
  mutating func writeName(_ name: String, compress: Bool = true)
                  throws(MessageError)
  {
    let name   = DNSMessage.withoutRootDot(name)
    let labels = name.isEmpty
      ? []
      : name.split(separator: ".", omittingEmptySubsequences: false)
    var length = 1
    for label in labels {
      let count = label.utf8.count
      guard count > 0, count <= DNSMessage.maxLabelLength else {
        throw .invalidName
      }
      length += 1 + count
    }
    guard length <= DNSMessage.maxNameLength else { throw .invalidName }

    for index in labels.indices {
      let suffix = labels[index...].joined(separator: ".").lowercased()
      if compress, let offset = names[suffix] {
        buffer.writeInteger(UInt16(DNSMessage.pointerMarker) << 8
                            | UInt16(offset))
        return // EXIT
      }

      let offset = buffer.writerIndex - messageStart
      if offset <= DNSMessage.maxPointerOffset, names[suffix] == nil {
        names[suffix] = offset
      }

      buffer.writeInteger(UInt8(labels[index].utf8.count))
      buffer.writeSubstring(labels[index])
    }

    buffer.writeInteger(UInt8(0)) // the root
  }
}
