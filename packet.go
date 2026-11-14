package nakis

import (
	"bufio"
	"context"
	"errors"
	"io"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sagernet/sing/common/buf"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

type packetItem struct {
	data []byte
	from M.Socksaddr
}

type packetLink struct {
	recv   chan packetItem
	done   chan struct{}
	once   sync.Once
	rd     *deadline
	wd     *deadline
	local  net.Addr
	mux    *jitterMux
	last   atomic.Int64
	napped atomic.Bool
	mc     *Tunnel
	failed atomic.Pointer[error]
}

func newPacketLink(mc *Tunnel, local net.Addr) *packetLink {
	p := &packetLink{
		recv:  make(chan packetItem, udpRecvCap),
		done:  make(chan struct{}),
		rd:    newDeadline(),
		wd:    newDeadline(),
		local: local,
		mc:    mc,
	}
	p.last.Store(time.Now().UnixNano())
	return p
}

func (p *packetLink) deliver(from M.Socksaddr, data []byte) {
	cp := GetBuf(len(data))
	copy(cp, data)
	select {
	case p.recv <- packetItem{data: cp, from: from}:
	default:
		PutBuf(cp)
	}
}

func (p *packetLink) ReadPacket(buffer *buf.Buffer) (M.Socksaddr, error) {
	select {
	case <-p.done:
		return M.Socksaddr{}, p.closeError()
	case <-p.rd.wait():
		return M.Socksaddr{}, os.ErrDeadlineExceeded
	default:
	}
	select {
	case item, ok := <-p.recv:
		if !ok {
			return M.Socksaddr{}, p.closeError()
		}
		_, err := buffer.Write(item.data)
		PutBuf(item.data)
		return item.from, err
	case <-p.done:
		return M.Socksaddr{}, p.closeError()
	case <-p.rd.wait():
		return M.Socksaddr{}, os.ErrDeadlineExceeded
	}
}

func (p *packetLink) closeError() error {
	if err := p.failed.Load(); err != nil {
		return *err
	}
	select {
	case <-p.done:
		return net.ErrClosed
	default:
		return io.EOF
	}
}

func (p *packetLink) WritePacket(buffer *buf.Buffer, destination M.Socksaddr) error {
	defer buffer.Release()
	select {
	case <-p.done:
		return net.ErrClosed
	case <-p.wd.wait():
		return os.ErrDeadlineExceeded
	default:
	}
	if destination.Port == 0 {
		return E.New("missing destination port")
	}
	rec, err := appendRecord(make([]byte, 0, buffer.Len()+24), udpAddr{host: destination.AddrString(), port: destination.Port}, buffer.Bytes())
	if err != nil {
		return err
	}
	p.last.Store(time.Now().UnixNano())
	if p.mux.failed.Load() {
		return io.ErrClosedPipe
	}
	p.mux.push(rec)
	return nil
}

func (p *packetLink) ReadFrom(b []byte) (int, net.Addr, error) {
	buffer := buf.With(b)
	destination, err := p.ReadPacket(buffer)
	if err != nil {
		return 0, nil, err
	}
	return buffer.Len(), destination.UDPAddr(), nil
}

func (p *packetLink) WriteTo(b []byte, addr net.Addr) (int, error) {
	err := p.WritePacket(buf.As(append([]byte(nil), b...)), M.SocksaddrFromNet(addr))
	if err != nil {
		return 0, err
	}
	return len(b), nil
}

func (p *packetLink) LocalAddr() net.Addr { return p.local }

func (p *packetLink) SetDeadline(t time.Time) error {
	p.rd.set(t)
	p.wd.set(t)
	return nil
}

func (p *packetLink) SetReadDeadline(t time.Time) error {
	p.rd.set(t)
	return nil
}

func (p *packetLink) SetWriteDeadline(t time.Time) error {
	p.wd.set(t)
	return nil
}

func (p *packetLink) drainRecv() {
	for {
		select {
		case item, ok := <-p.recv:
			if !ok {
				return
			}
			PutBuf(item.data)
		default:
			return
		}
	}
}

func (p *packetLink) watchIdle(ctx context.Context, idle time.Duration, quit <-chan struct{}, idled *atomic.Bool) {
	ticker := time.NewTicker(udpTick)
	defer ticker.Stop()
	for {
		select {
		case <-quit:
			return
		case <-ctx.Done():
			_ = p.mc.Close()
			return
		case <-ticker.C:
			if time.Since(time.Unix(0, p.last.Load())) > idle {
				idled.Store(true)
				_ = p.mc.Close()
				return
			}
		}
	}
}

var (
	_ N.NetPacketConn = (*servicePacket)(nil)
	_ N.NetPacketConn = (*clientPacket)(nil)
)

type servicePacket struct {
	*packetLink
	srv   *Service
	ended sync.Once
	endOK bool
}

func (s *Service) servePackets(ctx context.Context, mc *Tunnel, source M.Socksaddr) bool {
	if s.opts.DisableUDP {
		_ = mc.Send(nil, ErrorBytes(0, "udp is switched off on this server"))
		return false
	}
	if sendWithPad(mc, OKByte) != nil {
		return false
	}
	br := bufio.NewReaderSize(mc, 16<<10)
	buffer := make([]byte, 0xFFFF)
	_ = mc.SetReadDeadline(time.Now().Add(s.opts.UDPIdleTimeout))
	first, data, err := readRecord(br, buffer)
	if err != nil {
		if errors.Is(err, ErrNap) {
			return mc.Nap() == nil
		}
		return false
	}
	_ = mc.SetReadDeadline(time.Time{})

	pc := &servicePacket{packetLink: newPacketLink(mc, mc.LocalAddr()), srv: s}
	pc.mux = newJitterMux(s.opts.UDPJitter, func(b []byte) error { return mc.Send(nil, b) })
	pc.deliver(M.ParseSocksaddrHostPort(first.host, first.port), data)
	s.logger.DebugContext(ctx, "udp association from ", source, " to ", first.host, ":", first.port)
	go s.opts.Handler.NewPacketConnectionEx(ctx, pc, source, M.ParseSocksaddrHostPort(first.host, first.port), func(error) { _ = pc.Close() })
	return pc.consume(ctx, br, buffer)
}

func (p *servicePacket) consume(ctx context.Context, br *bufio.Reader, buffer []byte) bool {
	quit := make(chan struct{})
	var idled atomic.Bool
	go p.watchIdle(ctx, p.srv.opts.UDPIdleTimeout, quit, &idled)

	var err error
	for {
		var a udpAddr
		var data []byte
		a, data, err = readRecord(br, buffer)
		if err != nil {
			break
		}
		p.last.Store(time.Now().UnixNano())
		p.deliver(M.ParseSocksaddrHostPort(a.host, a.port), data)
	}
	close(quit)
	close(p.recv)
	p.once.Do(func() { close(p.done) })
	if idled.Load() {
		p.srv.logger.DebugContext(ctx, "udp association idle for too long, closed")
		p.end(false)
		return false
	}
	if !errors.Is(err, ErrNap) {
		p.end(false)
		return false
	}
	return p.end(true)
}

func (p *servicePacket) end(nap bool) bool {
	p.ended.Do(func() {
		p.mux.close()
		p.endOK = nap && !p.mux.failed.Load() && p.mc.Nap() == nil
		if p.endOK {
			_ = p.mc.SetReadDeadline(time.Now().Add(p.srv.opts.HalfCloseTimeout))
		}
	})
	return p.endOK
}

func (p *servicePacket) Close() error {
	first := false
	p.once.Do(func() {
		first = true
		close(p.done)
	})
	if first {
		go p.end(true)
	}
	return nil
}

type clientPacket struct {
	*packetLink
	client *Client
	ref    *sessionRef
	lease  *leased
	ended  sync.Once
}

func (c *Client) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	ref, ok := c.beginSession(nil)
	if !ok {
		return nil, net.ErrClosed
	}
	l, err := c.dialTunnel(ctx, uotHost, 0)
	if err != nil {
		c.endSession(ref)
		return nil, err
	}
	if !ref.bind(l.mc) {
		_ = l.mc.Close()
		c.endSession(ref)
		return nil, net.ErrClosed
	}
	if err = sendWithPad(l.mc, l.first); err != nil {
		l.broken.Store(true)
		l.release()
		c.endSession(ref)
		return nil, err
	}
	pc := &clientPacket{
		packetLink: newPacketLink(l.mc, duplexAddr("nakis-udp")),
		client:     c,
		ref:        ref,
		lease:      l,
	}
	ref.access.Lock()
	ref.closer = func() { _ = pc.Close() }
	ref.access.Unlock()
	pc.mux = newJitterMux(c.opts.UDPJitter, func(b []byte) error {
		err := l.mc.Send(nil, b)
		if err != nil {
			l.broken.Store(true)
		}
		return err
	})
	go pc.run()
	return pc, nil
}

func (p *clientPacket) run() {
	defer func() {
		if r := recover(); r != nil {
			p.client.logger.Error("recovered from a crash while serving a udp association: ", r)
		}
	}()
	p.down()
	p.once.Do(func() { close(p.done) })
	p.end()
	p.drainRecv()
	p.lease.release()
	p.client.endSession(p.ref)
}

func (p *clientPacket) down() {
	l := p.lease
	mc := l.mc
	if err := mc.ReadReply(); err != nil {
		l.broken.Store(true)
		var mew *PeerError
		if errors.As(err, &mew) {
			p.client.logger.Warn("the server wouldn't carry udp: ", err)
		} else {
			p.client.hintOnce(err)
		}
		p.fail(E.Cause(err, "udp tunnel"))
		return
	}
	br := bufio.NewReaderSize(mc, 16<<10)
	buffer := make([]byte, 0xFFFF)
	for {
		a, data, err := readRecord(br, buffer)
		if err != nil {
			if errors.Is(err, ErrNap) {
				l.napSeen.Store(true)
			} else {
				l.broken.Store(true)
				p.fail(E.Cause(err, "udp tunnel"))
			}
			return
		}
		p.last.Store(time.Now().UnixNano())
		p.deliver(M.ParseSocksaddrHostPort(a.host, a.port), data)
	}
}

func (p *clientPacket) fail(err error) {
	p.failed.CompareAndSwap(nil, &err)
	p.once.Do(func() { close(p.done) })
}

func (p *clientPacket) end() {
	p.ended.Do(func() {
		l := p.lease
		p.mux.close()
		if p.mux.failed.Load() {
			l.broken.Store(true)
		}
		if !l.broken.Load() && l.napSent.CompareAndSwap(false, true) {
			if err := l.mc.Nap(); err != nil {
				l.broken.Store(true)
			}
		}
		_ = l.mc.SetReadDeadline(time.Now().Add(p.client.drainWindow()))
	})
}

func (p *clientPacket) Close() error {
	first := false
	p.once.Do(func() {
		first = true
		close(p.done)
	})
	if first {
		go p.end()
	}
	return nil
}
