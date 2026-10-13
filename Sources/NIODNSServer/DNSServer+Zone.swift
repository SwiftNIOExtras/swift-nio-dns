//
//  DNSServer+Zone.swift
//  NIODNSServer
//
//  Created by Helge Hess.
//  Copyright © 2026 ZeeZide GmbH. All rights reserved.
//

import NIODNS

public extension DNSServer {

  /**
   * A responder closure that serves from a list of ``DNSRecord``'s.
   *
   * ```swift
   * let started = DNSServer.bind(responder: DNSServer.zone([
   *   DNSRecord(name: "zeezide.de",     ttl: 300, data: .a("192.0.2.1")),
   *   DNSRecord(name: "www.zeezide.de", ttl: 300, data: .cname("zeezide.de"))
   * ]))
   * ```
   */
  static func zone(_ records: [ DNSRecord ]) -> Responder {
    let key           = DNSMessage.canonicalName
    let recordsByName = Dictionary(grouping: records) { key($0.name) }
    
    return { query in
      var response = DNSMessage(responseTo: query.message)
      response.flags.insert(.authoritative)

      guard let question = query.question else { // no question?
        response.responseCode = .formatError; return .message(response)
      }
      guard recordsByName[key(question.name)] != nil else { // 404
        response.responseCode = .nameError; return .message(response)
      }

      var name    = key(question.name)
      var visited = Set<String>()

      while let records = recordsByName[name], visited.insert(name).inserted {
        let matching = records.filter {
          question.kind == .any || $0.kind == question.kind
        }
        guard matching.isEmpty else {
          response.answers += matching
          break
        }
        guard let alias = records.first(where: { $0.kind == .cname }),
              case .cname(let target) = alias.data else
        {
          break
        }

        response.answers.append(alias)
        name = key(target)
      }
      return .message(response)
    }
  }
}
