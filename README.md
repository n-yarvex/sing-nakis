# sing-nakis

Nakis for [sing](https://github.com/SagerNet/sing): a client and a service that speak the
[nakis](https://github.com/n-yarvex/nakis) wire protocol and plug into sing-box as an
outbound and an inbound.

The wire logic is the same as the standalone nakis: 2-byte frames with in-band padding,
a per-direction NAP so a tunnel can be reused only after both sides finished cleanly,
TLS exporter bound proofs, half close with a rolling timeout, and UDP carried over a tunnel
with a small jitter mux. TLS, DNS, routing and dialing are left to the caller.

```go
client, err := nakis.NewClient(nakis.ClientOptions{
	UUID:      uuid,
	Servers:   []M.Socksaddr{server},
	DialOut:   dial,
	Handshake: handshake,
})
client.Start()
conn, err := client.DialContext(ctx, destination)
packetConn, err := client.ListenPacket(ctx, destination)
```

```go
service, err := nakis.NewService(nakis.ServiceOptions{
	Handler:   handler,
	Users:     []nakis.User{{Name: "sekai", UUID: uuid}},
	Handshake: handshake,
})
err = service.NewConnection(ctx, conn, source, onClose)
```

## Notes

* `Handshake` receives a connection that must be wrapped by the standard library
  `crypto/tls`. The proof is bound to the TLS exporter, so uTLS and Reality are not usable.
* Zero values in the options mean the same defaults as nakis. Negative values turn a
  numeric knob off where that makes sense.

## Tests

```
go test -race ./...
NAKIS_BIN=/path/to/nakis go test -race -run Interop ./...
```

The interop tests run the official nakis client and server against this library, TCP and UDP.
