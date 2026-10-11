//
//  DNSMessage.swift
//  NIODNS
//
//  Created by Helge Hess.
//  Copyright © 2026 ZeeZide GmbH. All rights reserved.
//

import NIOCore

/**
 * A DNS message.
 *
 * They are composed of a unique ``id``, the ``questions`` ("requests") and
 * various ``answers`` (plus ``authorities`` and ``additionals``). And a few
 * flags/response-code.
 *
 * Queries (requests) only rarely have ``answers`` (the ``DNSRecord``'s), but
 * they can for EDNS (and NOTIFY/UPDATE).
 * Response messages do mirror the ``questions`` they have answers for.
 *
 * Usually those messages are sent over UDP, but sometimes TCP is used too
 * (mostly for larger messages).
 */
@frozen public struct DNSMessage: Hashable, Identifiable, Sendable {

  /// Flags and ``responseCode``
  @frozen public struct Flags: OptionSet, Hashable, Sendable {
    public let rawValue : UInt16
    @inlinable public init(rawValue: UInt16) { self.rawValue = rawValue }

    public static let response           = Flags(rawValue: 0x8000) // QR
    public static let authoritative      = Flags(rawValue: 0x0400) // AA
    public static let truncated          = Flags(rawValue: 0x0200) // TC
    public static let recursionDesired   = Flags(rawValue: 0x0100) // RD
    public static let recursionAvailable = Flags(rawValue: 0x0080) // RA

    public static let responseCodeMask   = UInt16(0x000F) // RCODE
  }
  
  /// The response code of a DNS message.
  @frozen public struct ResponseCode: RawRepresentable, Hashable, Sendable {
    public let rawValue : UInt8
    @inlinable public init(rawValue: UInt8) { self.rawValue = rawValue }

    public static let noError        = ResponseCode(rawValue: 0)
    public static let formatError    = ResponseCode(rawValue: 1)
    public static let serverFailure  = ResponseCode(rawValue: 2)
    public static let nameError      = ResponseCode(rawValue: 3) // NXDOMAIN
    public static let notImplemented = ResponseCode(rawValue: 4)
    public static let refused        = ResponseCode(rawValue: 5)
  }

  /// Query ask: name, record type and class.
  @frozen public struct Question: Hashable, Sendable {

    /// The name asked for, w/o the trailing dot.
    public var name    : String
    public var kind    : DNSRecord.Kind  // e.g. `.mx`
    public var `class` : DNSRecord.Class // almost always `.in`

    @inlinable
    public init(name  : String, kind: DNSRecord.Kind,
                class : DNSRecord.Class = .in)
    {
      self.name  = name
      self.kind  = kind
      self.class = `class`
    }
  }

  public var id          : UInt16
  public var flags       : Flags
  public var questions   = [ Question  ]()
  public var answers     = [ DNSRecord ]()
  public var authorities = [ DNSRecord ]()
  public var additionals = [ DNSRecord ]()

  @inlinable
  public init(id: UInt16, flags: Flags = [], questions: [ Question ] = [],
              answers     : [ DNSRecord ] = [],
              authorities : [ DNSRecord ] = [],
              additionals : [ DNSRecord ] = [])
  {
    self.id          = id
    self.flags       = flags
    self.questions   = questions
    self.answers     = answers
    self.authorities = authorities
    self.additionals = additionals
  }

  /**
   * Build a response to a query.
   *
   * Same id/questions, response flag set, recursion desired flag copied.
   *
   * - Parameters:
   *   - query:        The query to answer.
   *   - responseCode: The response code, e.g. ``ResponseCode/nameError``.
   *   - answers:      The records of the answer section.
   */
  @inlinable
  public init(responseTo query : DNSMessage,
              responseCode     : ResponseCode  = .noError,
              answers          : [ DNSRecord ] = [])
  {
    let flags = query.flags.intersection(.recursionDesired).union(.response)
    self.init(id: query.id, flags: flags, questions: query.questions,
              answers: answers)
    self.responseCode = responseCode
  }

  /**
   * Build a standard, recursive query for one name and type.
   *
   * - Parameters:
   *   - id:              Message id.
   *   - name:            ASCII domain name, optional trailing dot.
   *   - kind:            Record type to ask for (e.g. `.mx`).
   *   - ednsPayloadSize: The UDP payload size to, if any.
   */
  @inlinable
  public init(id: UInt16, name: String, kind: DNSRecord.Kind,
              ednsPayloadSize: UInt16? = DNSMessage.defaultEDNSPayloadSize)
  {
    self.init(id: id, flags: .recursionDesired,
              questions: [ Question(name: name, kind: kind) ])
    if let ednsPayloadSize {
      additionals.append(.edns(payloadSize: ednsPayloadSize))
    }
  }

  @inlinable public var isResponse     : Bool { flags.contains(.response)      }
  @inlinable public var isTruncated    : Bool { flags.contains(.truncated)     }
  @inlinable public var isAuthoritative: Bool { flags.contains(.authoritative) }

  @inlinable public var responseCode : ResponseCode {
    get {
      ResponseCode(rawValue: UInt8(flags.rawValue & Flags.responseCodeMask))
    }
    set {
      let mask = Flags.responseCodeMask
      flags = Flags(rawValue: flags.rawValue & ~mask
                            | UInt16(newValue.rawValue) & mask)
    }
  }

  /// The UDP payload size the sender announced via EDNS(0), `nil` if the
  /// message has no `OPT` record.
  @inlinable public var ednsPayloadSize : UInt16? {
    additionals.first(where: { $0.kind == .opt })?.class.rawValue
  }

  public static let defaultEDNSPayloadSize = UInt16(1232) // EDNS(0)
  /// The largest message allowed over UDP w/o EDNS(0).
  public static let maxUDPPayloadSize      = 512


  // MARK: - Zerialization

  static let headerSize         = 12
  static let maxLabelLength     = 63 // max domain name len
  static let maxNameLength      = 255
  /// The top two bits of a label length byte mark a compression pointer,
  /// the remaining 14 bits are the offset.
  static let pointerMarker      = UInt8(0xC0)
  static let pointerOffsetMask  = UInt8(0x3F)
  /// The largest offset a compression pointer can express.
  static let maxPointerOffset   = 0x3FFF
  /// More pointers in one name than this must be a loop.
  static let maxPointerJumps    = 127

  public enum MessageError: Swift.Error, Hashable, Sendable {
    case truncated
    case invalidName
    case invalidPointer
    case invalidRecordData
    case tooLarge
  }

  /**
   * Serialize.
   *
   * Names are compressed, except in the data of `SRV` and `NAPTR` records.
   * The ``DNSRecord/Data/other(type:rdata:)`` done as is.
   *
   * - Parameters:
   *   - allocator: The allocator for the buffer.
   * - Returns:     The bytes of the message.
   * - Throws:      ``DNSMessage/MessageError`` for data that cannot be put on
   *                the wire.
   */
  public func toByteBuffer(allocator: ByteBufferAllocator = .init())
                throws(MessageError) -> ByteBuffer
  {
    var writer =
      DNSWriter(buffer: allocator.buffer(capacity: Self.maxUDPPayloadSize))
    try writer.write(self)
    return writer.buffer
  }

  /**
   * Deserialize a message.
   *
   * - Parameters:
   *   - bytes: The bytes to decode.
   * - Throws:  ``DNSMessage/MessageError``
   */
  public init(bytes: RawSpan) throws(MessageError) {
    var reader = DNSReader(bytes)

    self.id    = try reader.readInteger()
    self.flags = Flags(rawValue: try reader.readInteger())

    let questionCount   = try reader.readInteger(as: UInt16.self)
    let answerCount     = try reader.readInteger(as: UInt16.self)
    let authorityCount  = try reader.readInteger(as: UInt16.self)
    let additionalCount = try reader.readInteger(as: UInt16.self)

    for _ in 0..<questionCount {
      questions.append(try reader.readQuestion())
    }

    // Appended one by one: in a truncated message the records before the
    // cut are kept.
    do throws(MessageError) {
      for _ in 0..<answerCount {
        answers.append(try reader.readRecord())
      }
      for _ in 0..<authorityCount {
        authorities.append(try reader.readRecord())
      }
      for _ in 0..<additionalCount {
        additionals.append(try reader.readRecord())
      }
    }
    catch {
      guard isTruncated else { throw error }
    }
  }

  /**
   * Deserialize a message.
   *
   * - Parameters:
   *   - bytes: The bytes to decode.
   * - Throws:  ``DNSMessage/MessageError``
   */
  @inlinable public init(bytes: ByteBuffer) throws(MessageError) {
    try self.init(bytes: bytes.readableBytesSpan)
  }

}

extension DNSMessage.ResponseCode: CustomStringConvertible {

  @inlinable
  public var description : String {
    switch self {
      case .noError        : "NOERROR"
      case .formatError    : "FORMERR"
      case .serverFailure  : "SERVFAIL"
      case .nameError      : "NXDOMAIN"
      case .notImplemented : "NOTIMP"
      case .refused        : "REFUSED"
      default              : "RCODE\(rawValue)"
    }
  }
}

// MARK: - Helpers

extension DNSMessage {

  /// Canonical domain name ("WWW.Example.org." => "www.example.org")
  @inlinable public static func canonicalName(_ name: String) -> String {
    String(withoutRootDot(name)).lowercased()
  }

  /// Returns the name w/o the trailing dot, if it has one.
  @inlinable static func withoutRootDot(_ name: String) -> Substring {
    name.hasSuffix(".") ? name.dropLast() : Substring(name)
  }
}
