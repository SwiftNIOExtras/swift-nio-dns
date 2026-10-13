## swift-nio-dns

Raw DNS support for SwiftNIO.

- `NIODNS`:       The protocol types/coders.
- `NIODNSClient`: Small DNS client.
- `NIODNSServer`: Small test server, do not use in PROD

### Client

```swift
let client = DNSClient(options: .init(servers: [
  try SocketAddress(ipAddress: "9.9.9.9", port: 53)
]))
client.query("zeezide.de", kind: .txt).result.whenComplete { result in
  switch result {
    case .success(let message):
      for record in message.answers { print(record.data) }
    case .failure(let error): // a DNSClient.QueryError
      print("query failed:", error)
  }
}
```

### Server

```swift
DNSServer.bind(responder: DNSServer.zone([
  DNSRecord(name: "zeezide.de", ttl: 300,
            data: .mx(preference: 10, exchange: "mail.zeezide.de"))
]))
.whenSuccess { server in
  print("Server listening on:", server.localAddress)
}

let refusing = DNSServer.bind { query in
  .message(DNSMessage(responseTo: query.message, responseCode: .refused))
}
```


### Who

**Macro** is brought to you by
[Helge Heß](https://github.com/helje5/) / [ZeeZide](https://zeezide.de).
We like feedback, GitHub stars, cool contract work, 
presumably any form of praise you can think of.

**Want to support my work**?
Buy an [app](https://zeezide.de/en/products/products.html).
You don't have to use it! 😀
