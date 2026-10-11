//
//  SocketAddress+Ext.swift
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

public extension NIOCore.SocketAddress {

  /**
   * The domain name for a reverse lookups (`PTR`).
   *
   * Essentially the IP reversed and `.in-addr.arpa` or `.ip6.arpa` added.
   */
  @inlinable
  var dnsReverseName : String? {
    switch self {
      case .v4(let address):
        let v = UInt32(bigEndian: address.address.sin_addr.s_addr)
        return "\(v&0xFF).\(v>>8 & 0xFF).\(v>>16 & 0xFF).\(v>>24).in-addr.arpa"

      case .v6(let address):
        return withUnsafeBytes(of: address.address.sin6_addr) { bytes in
          var name = ""
          name.reserveCapacity(64 + 9)
          for byte in bytes.reversed() {
            name += String(byte & 0x0F, radix: 16) + "."
            name += String(byte >> 4,   radix: 16) + "."
          }
          name += "ip6.arpa"
          return name
        }

      case .unixDomainSocket:
        return nil
    }
  }
}
