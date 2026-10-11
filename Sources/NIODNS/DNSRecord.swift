//
//  DNSRecord.swift
//  NIODNS
//
//  Created by Helge Hess.
//  Copyright © 2026 ZeeZide GmbH. All rights reserved.
//

import NIOCore

/**
 * A DNS resource record.
 *
 * It's used in ``DNSMessage`` to carry the data of the ``DNSMessage/answers``
 * (and it's section peers).
 *
 * This has a class, usually ``Class/in``, plus the actual ``Data`` payload for
 * each ``Kind``. Plus the owner name and a TTL.
 */
@frozen public struct DNSRecord: Hashable, Sendable {

  /// The class of a question/record (``in``).
  @frozen public struct Class: RawRepresentable, Hashable, Sendable {
    public let rawValue : UInt16
    @inlinable public init(rawValue: UInt16) { self.rawValue = rawValue }

    public static let `in`   = Class(rawValue:   1) // Internet
    public static let chaos  = Class(rawValue:   3) // Chaosnet
    public static let hesiod = Class(rawValue:   4) // Hesiod
    public static let any    = Class(rawValue: 255) // * query class
  }

  /// The type of a resource record, e.g. ``mx``.
  @frozen public struct Kind: RawRepresentable, Hashable, Sendable {
    public let rawValue : UInt16
    @inlinable public init(rawValue: UInt16) { self.rawValue = rawValue }

    public static let a     = Kind(rawValue:   1)
    public static let ns    = Kind(rawValue:   2)
    public static let cname = Kind(rawValue:   5)
    public static let soa   = Kind(rawValue:   6)
    public static let ptr   = Kind(rawValue:  12)
    public static let mx    = Kind(rawValue:  15)
    public static let txt   = Kind(rawValue:  16)
    public static let aaaa  = Kind(rawValue:  28)
    public static let srv   = Kind(rawValue:  33)
    public static let naptr = Kind(rawValue:  35)
    public static let opt   = Kind(rawValue:  41) // EDNS(0)
    public static let tlsa  = Kind(rawValue:  52)
    public static let any   = Kind(rawValue: 255) // * query
    public static let caa   = Kind(rawValue: 257)
  }

  /// Names w/o trailing dot, addresses in presentation
  public enum Data: Hashable, Sendable {

    case a    (String)
    case aaaa (String)
    case cname(String)
    case ns   (String)
    case ptr  (String)
    case mx   (preference: UInt16, exchange: String)
    case txt  ([ String ]) // e.g. a DKIM key has multiple
    case soa  (SOA)
    case srv  (priority: UInt16, weight: UInt16, port: UInt16, target: String)
    case caa  (flags: UInt8, tag: String, value: String)
    case naptr(NAPTR)
    case tlsa (usage: UInt8, selector: UInt8, matchingType: UInt8,
               data: ByteBuffer)
    case other(type: Kind, rdata: ByteBuffer) // unsupported/OPT

    @frozen public struct SOA: Hashable, Sendable {

      public var mname   : String // primary name server of zone
      public var rname   : String // admin, `@` as the first .
      public var serial  : UInt32
      public var refresh : UInt32
      public var retry   : UInt32
      public var expire  : UInt32
      public var minimum : UInt32 // TTL of negative answers

      @inlinable
      public init(mname   : String, rname : String, serial : UInt32,
                  refresh : UInt32, retry : UInt32, expire : UInt32,
                  minimum : UInt32)
      {
        self.mname   = mname
        self.rname   = rname
        self.serial  = serial
        self.refresh = refresh
        self.retry   = retry
        self.expire  = expire
        self.minimum = minimum
      }
    }

    @frozen public struct NAPTR: Hashable, Sendable {

      public var order       : UInt16
      public var preference  : UInt16
      public var flags       : String
      public var services    : String
      public var regexp      : String
      public var replacement : String

      @inlinable
      public init(order    : UInt16, preference : UInt16, flags       : String,
                  services : String, regexp     : String, replacement : String)
      {
        self.order       = order
        self.preference  = preference
        self.flags       = flags
        self.services    = services
        self.regexp      = regexp
        self.replacement = replacement
      }
    }
  }

  /// The owner, no trailing dot.
  public var name     : String

  /// Usually ``Class/in``, for `OPT` the payload size.
  public var `class`  : Class

  /// TTL in seconds.
  public var ttl      : UInt32

  /// The data (and type)
  public var data     : Data

  @inlinable
  public init(name: String, class: Class = .in, ttl: UInt32, data: Data) {
    self.name  = name
    self.class = `class`
    self.ttl   = ttl
    self.data  = data
  }

  /// The type of the record.
  @inlinable public var kind : Kind { data.kind }

  /// The EDNS(0) `OPT` pseudo record, gives the UDP payload size.
  @inlinable public static func edns(payloadSize: UInt16) -> DNSRecord {
    // The class carries the payload size, the TTL the extended RCODE, the
    // version and the flags (all 0).
    DNSRecord(name : "", class : Class(rawValue: payloadSize),
              ttl  : 0,  data  : .other(type: .opt, rdata: ByteBuffer()))
  }
}

extension DNSRecord.Kind: CustomStringConvertible {

  @inlinable public var stringValue : String {
    switch self {
      case .a     : "A"
      case .ns    : "NS"
      case .cname : "CNAME"
      case .soa   : "SOA"
      case .ptr   : "PTR"
      case .mx    : "MX"
      case .txt   : "TXT"
      case .aaaa  : "AAAA"
      case .srv   : "SRV"
      case .naptr : "NAPTR"
      case .opt   : "OPT"
      case .tlsa  : "TLSA"
      case .any   : "ANY"
      case .caa   : "CAA"
      default     : "TYPE\(rawValue)"
    }
  }
  @inlinable public var description : String { stringValue }
}

extension DNSRecord.Class: CustomStringConvertible {

  @inlinable public var stringValue : String {
    switch self {
      case .in     : "IN"
      case .chaos  : "CH"
      case .hesiod : "HS"
      case .any    : "ANY"
      default      : "CLASS\(rawValue)"
    }
  }
  @inlinable public var description : String { stringValue }
}

extension DNSRecord.Data {

  /// The record type the data belongs to.
  @inlinable public var kind : DNSRecord.Kind {
    switch self {
      case .a                  : .a
      case .aaaa               : .aaaa
      case .cname              : .cname
      case .ns                 : .ns
      case .ptr                : .ptr
      case .mx                 : .mx
      case .txt                : .txt
      case .soa                : .soa
      case .srv                : .srv
      case .caa                : .caa
      case .naptr              : .naptr
      case .tlsa               : .tlsa
      case .other(let type, _) : type
    }
  }
}
