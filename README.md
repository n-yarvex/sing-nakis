# sing-nakis

Nakis for [sing](https://github.com/SagerNet/sing): a client and a service that speak the
[nakis](https://github.com/n-yarvex/nakis) wire protocol and plug into sing-box as an
outbound and an inbound.

The wire logic is the same as the standalone nakis: 

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

* TLS is required on both sides, and only the standard library stack works. The client proof is bound to the TLS exporter, so uTLS and Reality are rejected at initialisation.
* UDP uses nakis' own tunnel mode; uot is not involved.
* The server never dials anything itself: targets go through the router, so rules, DNS and private address policy are sing-box's.
* No client metadata, no fingerprintable defaults in the protocol.
* Zero values in the options mean the same defaults as nakis. Negative values turn a numeric knob off where that makes sense.

## Tests

We have run the regular tests (TCP, UDP, large data) and passed with goleak and -race testing. The sing-box tests were run on Linux only, and no benchmark data is included here, nor are any claims made about detection (censorship) resistance.
