//
//  DNSReader.swift
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

/// Wrapper to read specific DNS types.
struct DNSReader: ~Escapable {

  typealias MessageError = DNSMessage.MessageError

  let message : RawSpan // whole message
  var cursor  : Int     // pos of next read
  let end     : Int     // upper limit

  @_lifetime(borrow message)
  init(_ message: borrowing RawSpan) {
    self.message = copy message
    self.cursor  = 0
    self.end     = message.byteCount
  }

  @_lifetime(copy message)
  private init(message: borrowing RawSpan, cursor: Int, end: Int) {
    self.message = copy message
    self.cursor  = cursor
    self.end     = end
  }

  var isAtEnd        : Bool { cursor >= end }
  var remainingCount : Int  { max(0, end - cursor) }

  /// Returns a reader for the next `count` bytes, and skips them.
  @_lifetime(copy self)
  mutating func readSlice(count: Int) throws(MessageError) -> DNSReader {
    guard count <= end - cursor else { throw .truncated }
    let reader = DNSReader(message: message, cursor: cursor, end:cursor + count)
    cursor += count
    return reader
  }

  mutating func readInteger<T>(as: T.Type = T.self) throws(MessageError) -> T
    where T: FixedWidthInteger & BitwiseCopyable
  {
    let size = MemoryLayout<T>.size
    guard size <= end - cursor else { throw .truncated }

    let value = message.unsafeLoadUnaligned(fromByteOffset: cursor, as: T.self)
    cursor += size
    return T(bigEndian: value)
  }

  mutating func readBytes(count: Int) throws(MessageError) -> ByteBuffer {
    guard count <= end - cursor else { throw .truncated }
    let start = cursor
    cursor += count
    var buffer = ByteBuffer()
    buffer.writeBytes(message.extracting(start ..< start + count))
    return buffer
  }

  mutating func readString(count: Int) throws(MessageError) -> String {
    guard count <= end - cursor else { throw .truncated }
    let start = cursor
    cursor += count
    return string(at: start, count: count)
  }

  /// Reads a string prefixed w/ its length as one byte (`TXT`, `NAPTR`).
  mutating func readString() throws(MessageError) -> String {
    let length = try readInteger(as: UInt8.self)
    return try readString(count: Int(length))
  }

  /// Read IPv4/IPv6 addresses and return as string (e.g. `1.2.3.4`).
  mutating func readIPAddress(count: Int) throws(MessageError) -> String {
    switch count {
      case 4:
        let v = try readInteger(as: UInt32.self)
        return "\(v >> 24).\(v >> 16 & 0xFF).\(v >> 8 & 0xFF).\(v & 0xFF)"

      case 16:
        guard count <= (end - cursor) else { throw .truncated }

        var address = sockaddr_in6()
        address.sin6_family = sa_family_t(AF_INET6)
        let start = cursor
        message.withUnsafeBytes { source in
          withUnsafeMutableBytes(of: &address.sin6_addr) {
            $0.copyMemory(from: .init(rebasing: source[start ..< start + 16]))
          }
        }
        cursor += count

        guard let string = SocketAddress(address, host: "").ipAddress else {
          throw .invalidRecordData
        }
        return string // via inet_ntop

      default:
        throw .invalidRecordData
    }
  }


  // MARK: - Names

  /// Reads a domain name.
  mutating func readName() throws(MessageError) -> String {
    var labels   = [ String ]()
    var position = cursor
    var limit    = end  // labels before the first pointer stay in the data
    var nameEnd  : Int? // behind the name as stored here
    var jumps    = 0
    var length   = 0

    while true {
      let byte = try byte(at: position, limit: limit)
      if byte == 0 {
        nameEnd = nameEnd ?? position + 1
        break
      }

      if byte & DNSMessage.pointerMarker == DNSMessage.pointerMarker {
        let low    = try self.byte(at: position + 1, limit: limit)
        let target = Int(byte & DNSMessage.pointerOffsetMask) << 8 | Int(low)

        nameEnd = nameEnd ?? position + 2
        jumps  += 1

        // A pointer has to lead backwards.
        guard target < position, jumps <= DNSMessage.maxPointerJumps else {
          throw .invalidPointer
        }

        position = target
        limit    = message.byteCount
        continue
      }

      guard byte & DNSMessage.pointerMarker == 0 else { throw .invalidName }

      let count = Int(byte)
      length += count + 1
      guard length <= DNSMessage.maxNameLength else { throw .invalidName }
      guard (position + 1 + count) <= limit    else { throw .truncated   }

      labels.append(string(at: position + 1, count: count))
      position += 1 + count
    }

    cursor = nameEnd ?? position + 1
    return labels.joined(separator: ".")
  }


  // MARK: - Questions and Records

  mutating func readQuestion() throws(MessageError) -> DNSMessage.Question {
    let name = try readName()
    let type = DNSRecord.Kind (rawValue: try readInteger())
    let clz  = DNSRecord.Class(rawValue: try readInteger())

    return DNSMessage.Question(name: name, kind: type, class: clz)
  }

  mutating func readRecord() throws(MessageError) -> DNSRecord {
    let name     = try readName()
    let type     = DNSRecord.Kind (rawValue: try readInteger())
    let dnsClass = DNSRecord.Class(rawValue: try readInteger())
    let ttl      = try readInteger(as: UInt32.self)
    let length   = try readInteger(as: UInt16.self)

    var rdata = try readSlice(count: Int(length))
    let data  = try rdata.readRecordData(type: type)
    guard rdata.isAtEnd else { throw .invalidRecordData }

    return DNSRecord(name: name, class: dnsClass, ttl: ttl, data: data)
  }

  mutating func readRecordData(type: DNSRecord.Kind) throws(MessageError)
                -> DNSRecord.Data
  {
    switch type {
      case .a     : return .a    (try readIPAddress(count: 4))
      case .aaaa  : return .aaaa (try readIPAddress(count: 16))
      case .cname : return .cname(try readName())
      case .ns    : return .ns   (try readName())
      case .ptr   : return .ptr  (try readName())

      case .mx:
        let preference = try readInteger(as: UInt16.self)
        return .mx(preference: preference, exchange: try readName())

      case .txt:
        var chunks = [ String ]()
        while !isAtEnd {
          chunks.append(try readString())
        }
        return .txt(chunks)

      case .soa:
        let mname   = try readName()
        let rname   = try readName()
        let serial  = try readInteger(as: UInt32.self)
        let refresh = try readInteger(as: UInt32.self)
        let retry   = try readInteger(as: UInt32.self)
        let expire  = try readInteger(as: UInt32.self)
        let minimum = try readInteger(as: UInt32.self)
        return .soa(.init(mname   : mname,   rname : rname, serial : serial,
                          refresh : refresh, retry : retry, expire : expire,
                          minimum : minimum))

      case .srv:
        let priority = try readInteger(as: UInt16.self)
        let weight   = try readInteger(as: UInt16.self)
        let port     = try readInteger(as: UInt16.self)
        return .srv(priority : priority, weight: weight, port: port,
                    target   : try readName())

      case .caa:
        let flags = try readInteger(as: UInt8.self)
        let tag   = try readString()
        let value = try readString(count: remainingCount)
        return .caa(flags: flags, tag: tag, value: value)

      case .naptr:
        let order      = try readInteger(as: UInt16.self)
        let preference = try readInteger(as: UInt16.self)
        let flags      = try readString()
        let services   = try readString()
        let regexp     = try readString()
        return .naptr(.init(order: order, preference: preference,
                            flags: flags, services  : services, regexp: regexp,
                            replacement: try readName()))

      case .tlsa:
        let usage        = try readInteger(as: UInt8.self)
        let selector     = try readInteger(as: UInt8.self)
        let matchingType = try readInteger(as: UInt8.self)
        let data = try readBytes(count: remainingCount)
        return .tlsa(usage        : usage,        selector : selector,
                     matchingType : matchingType, data     : data)

      default:
        let rdata = try readBytes(count: remainingCount)
        return .other(type: type, rdata: rdata)
    }
  }


  // MARK: - Helpsters

  private func byte(at position: Int, limit: Int)
                 throws(MessageError) -> UInt8
  {
    guard position < limit else { throw .truncated }
    return message.unsafeLoad(fromByteOffset: position, as: UInt8.self)
  }

  private func string(at offset: Int, count: Int) -> String {
    message.withUnsafeBytes {
      let ptr = UnsafeRawBufferPointer(rebasing: $0[offset ..< offset + count])
      return String(decoding: ptr, as: UTF8.self)
    }
  }
}
