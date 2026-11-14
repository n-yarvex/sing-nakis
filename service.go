package nakis

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/sagernet/sing/common/auth"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

type Handler interface {
	N.TCPConnectionHandlerEx
	N.UDPConnectionHandlerEx
}

type User struct {
	Name string
	UUID string
}

type ServiceOptions struct {
	Logger           logger.ContextLogger
	Handler          Handler
	Users            []User
	Handshake        func(ctx context.Context, conn net.Conn) (net.Conn, error)
	HandshakeTimeout time.Duration
	IdleTimeout      time.Duration
	HalfCloseTimeout time.Duration
	SendPack         int
	SendTail         int
	SendQuiet        int
	MergePack        int
	MaxQueue         int
	DisableUDP       bool
	UDPIdleTimeout   time.Duration
	UDPJitter        time.Duration
}

type serviceUser struct {
	name  string
	guard *Guard
}

type Service struct {
	opts   ServiceOptions
	logger logger.ContextLogger
	users  atomic.Pointer[[]*serviceUser]

	skewNote atomic.Bool
	turnNote atomic.Bool
	turned   atomic.Int64

	access  sync.Mutex
	tunnels map[*Tunnel]struct{}
	closed  bool
}

func NewService(options ServiceOptions) (*Service, error) {
	if options.Handler == nil {
		return nil, E.New("missing handler")
	}
	if options.Logger == nil {
		options.Logger = logger.NOP()
	}
	options.HandshakeTimeout = orDuration(options.HandshakeTimeout, 10*time.Second)
	options.IdleTimeout = orDuration(options.IdleTimeout, 120*time.Second)
	options.HalfCloseTimeout = orDuration(options.HalfCloseTimeout, 120*time.Second)
	options.SendPack = clamp(orInt(options.SendPack, 32*1024), 1024, PackCap)
	options.SendTail = clamp(orInt(options.SendTail, 512), 0, options.SendPack-1)
	options.SendQuiet = clamp(orInt(options.SendQuiet, 4), 0, 64)
	options.MergePack = clamp(orInt(options.MergePack, 20*1024), 1024, FrameCap)
	options.MaxQueue = clamp(orInt(options.MaxQueue, 4*1024*1024), 64*1024, 256*1024*1024)
	options.UDPIdleTimeout = orDuration(options.UDPIdleTimeout, 300*time.Second)
	options.UDPJitter = jitterSpan(options.UDPJitter)
	s := &Service{
		opts:    options,
		logger:  options.Logger,
		tunnels: make(map[*Tunnel]struct{}),
	}
	if err := s.UpdateUsers(options.Users); err != nil {
		return nil, err
	}
	return s, nil
}

func (s *Service) UpdateUsers(users []User) error {
	if len(users) == 0 {
		return E.New("missing users")
	}
	list := make([]*serviceUser, 0, len(users))
	for index, user := range users {
		id, err := ParseUUID(user.UUID)
		if err != nil {
			return E.Cause(err, "invalid uuid of users[", index, "]")
		}
		list = append(list, &serviceUser{name: user.Name, guard: NewGuard(id)})
	}
	s.users.Store(&list)
	return nil
}

func (s *Service) Close() error {
	s.access.Lock()
	s.closed = true
	tunnels := make([]*Tunnel, 0, len(s.tunnels))
	for mc := range s.tunnels {
		tunnels = append(tunnels, mc)
	}
	s.access.Unlock()
	for _, mc := range tunnels {
		_ = mc.Close()
	}
	return nil
}

func (s *Service) track(mc *Tunnel) bool {
	s.access.Lock()
	defer s.access.Unlock()
	if s.closed {
		return false
	}
	s.tunnels[mc] = struct{}{}
	return true
}

func (s *Service) untrack(mc *Tunnel) {
	s.access.Lock()
	delete(s.tunnels, mc)
	s.access.Unlock()
}

func (s *Service) NewConnection(ctx context.Context, conn net.Conn, source M.Socksaddr, onClose N.CloseHandlerFunc) error {
	var batch *Batcher
	secured := conn
	if s.opts.Handshake != nil {
		batch = NewBatcher(conn)
		hctx, cancel := context.WithTimeout(ctx, s.opts.HandshakeTimeout)
		tc, err := s.opts.Handshake(hctx, batch)
		cancel()
		if err != nil {
			return E.Cause(err, "tls handshake")
		}
		secured = tc
	}
	mc := WrapTunnel(secured, batch)
	if s.opts.Handshake != nil {
		bind, err := ExportBinding(secured)
		if err != nil {
			_ = secured.Close()
			return err
		}
		mc.bind = bind
	}
	if !s.track(mc) {
		_ = mc.Close()
		return net.ErrClosed
	}
	s.serve(ctx, mc, source, onClose)
	return nil
}

func (s *Service) serve(ctx context.Context, mc *Tunnel, source M.Socksaddr, onClose N.CloseHandlerFunc) {
	var result error
	defer func() {
		if r := recover(); r != nil {
			s.logger.ErrorContext(ctx, "recovered from a crash while serving ", source, ": ", r)
			result = E.New("panic: ", r)
		}
		s.untrack(mc)
		_ = mc.Close()
		if onClose != nil {
			onClose(result)
		}
	}()

	user, err := s.admit(ctx, mc, source)
	if err != nil {
		if !errors.Is(err, errTurnedAway) {
			result = err
		}
		return
	}
	ctx = auth.ContextWithUser(ctx, user.name)
	for {
		_ = mc.SetReadDeadline(time.Now().Add(s.opts.IdleTimeout))
		again, err := s.serveOne(ctx, mc, source)
		if err != nil {
			if !errors.Is(err, io.EOF) && !errors.Is(err, ErrNap) && ctx.Err() == nil {
				s.logger.DebugContext(ctx, "request from ", source, " ended: ", err)
			}
			return
		}
		if !again {
			s.logger.DebugContext(ctx, "tunnel from ", source, " is not reusable, closing")
			return
		}
	}
}

var errTurnedAway = errors.New("turned away")

func (s *Service) admit(ctx context.Context, mc *Tunnel, source M.Socksaddr) (*serviceUser, error) {
	frame, prefix, err := mc.ReadFirst(s.opts.IdleTimeout, min(s.opts.HandshakeTimeout, firstBody))
	if err != nil {
		return nil, err
	}
	if frame == nil {
		s.refuse(ctx, source, errors.New("not a nakis frame"))
		s.decoy(mc, prefix)
		return nil, errTurnedAway
	}
	if len(frame) < ProofSize {
		PutBuf(frame)
		s.refuse(ctx, source, ErrBadMac)
		s.decoy(mc, nil)
		return nil, errTurnedAway
	}
	var matched *serviceUser
	verdict := ErrBadMac
	for _, user := range *s.users.Load() {
		err := user.guard.Accept(frame[:ProofSize], mc.bind)
		if err == nil {
			matched = user
			break
		}
		if !errors.Is(err, ErrBadMac) {
			verdict = err
		}
	}
	if matched == nil {
		PutBuf(frame)
		s.refuse(ctx, source, verdict)
		s.decoy(mc, nil)
		return nil, errTurnedAway
	}
	if len(frame) == ProofSize {
		PutBuf(frame)
		return matched, nil
	}
	mc.Unread(frame, ProofSize)
	return matched, nil
}

func (s *Service) refuse(ctx context.Context, source M.Socksaddr, err error) {
	s.turned.Add(1)
	if s.turnNote.CompareAndSwap(false, true) {
		time.AfterFunc(time.Minute, func() {
			n := s.turned.Swap(0)
			s.turnNote.Store(false)
			s.logger.Warn("turned away ", n, " connection(s) in the last minute that didn't present a valid proof, if one of them is yours, check the uuid and the clock")
		})
	}
	var stale *StaleError
	if errors.As(err, &stale) && s.skewNote.CompareAndSwap(false, true) {
		s.logger.WarnContext(ctx, "a client's clock is ", stale.Skew.Round(time.Second), " away from mine, the allowed gap is ", ProofWindow, ", remote ", source)
		time.AfterFunc(10*time.Second, func() { s.skewNote.Store(false) })
		return
	}
	s.logger.DebugContext(ctx, "proof from ", source, " refused: ", err)
}

func readN(mc *Tunnel, n int) ([]byte, error) {
	buf := make([]byte, n)
	_, err := io.ReadFull(mc, buf)
	return buf, err
}

func (s *Service) serveOne(ctx context.Context, mc *Tunnel, source M.Socksaddr) (bool, error) {
	version, err := mc.ReadByte()
	if err != nil {
		return false, err
	}
	if ctx.Err() != nil {
		return false, ctx.Err()
	}
	if version != HelloVersion {
		return false, E.New("invalid protocol version 0x", fmt.Sprintf("%x", version))
	}
	cmd, err := mc.ReadByte()
	if err != nil {
		return false, err
	}
	if cmd != CmdConnect {
		return false, E.New("unknown command 0x", fmt.Sprintf("%x", cmd))
	}
	idLen, err := mc.ReadByte()
	if err != nil {
		return false, err
	}
	if idLen > 0 {
		if _, err = readN(mc, int(idLen)); err != nil {
			return false, err
		}
	}
	hostLen, err := mc.ReadByte()
	if err != nil {
		return false, err
	}
	if hostLen == 0 {
		return false, E.New("connect host is empty")
	}
	host, err := readN(mc, int(hostLen))
	if err != nil {
		return false, err
	}
	pb, err := readN(mc, 2)
	if err != nil {
		return false, err
	}
	_ = mc.SetReadDeadline(time.Time{})

	if string(host) == uotHost {
		return s.servePackets(ctx, mc, source), nil
	}
	destination := M.ParseSocksaddrHostPort(string(host), binary.BigEndian.Uint16(pb))
	return s.serveStream(ctx, mc, source, destination), nil
}

func (s *Service) serveStream(ctx context.Context, mc *Tunnel, source M.Socksaddr, destination M.Socksaddr) bool {
	s.logger.DebugContext(ctx, "stream from ", source, " to ", destination)
	target, user := newDuplex(destination, source)
	go s.opts.Handler.NewConnectionEx(ctx, user, source, destination, func(error) { _ = user.Close() })
	clean := newBridge(s, mc, target, tlsLike(strconv.Itoa(int(destination.Port)))).run()
	_ = target.Close()
	_ = user.Close()
	return clean
}

func errnoOf(err error) byte {
	var e syscall.Errno
	if errors.As(err, &e) {
		return byte(e)
	}
	return 0
}

type bridge struct {
	srv    *Service
	tun    *Tunnel
	target *duplexConn

	access sync.Mutex
	cond   *sync.Cond
	box    *Box
	closed bool
	eof    bool

	gate *Gate

	wMu     sync.Mutex
	greeted bool

	napSeen      atomic.Bool
	napSent      atomic.Bool
	broken       atomic.Bool
	feedWG       sync.WaitGroup
	gatherFinish chan struct{}
	half         time.Duration
}

func newBridge(srv *Service, tun *Tunnel, target *duplexConn, inner bool) *bridge {
	opts := srv.opts
	n := &bridge{
		srv:          srv,
		tun:          tun,
		target:       target,
		box:          NewBox(opts.MergePack, 0),
		gatherFinish: make(chan struct{}),
		half:         opts.HalfCloseTimeout,
	}
	n.cond = sync.NewCond(&n.access)
	n.gate = NewGate(GateOptions{
		Pack:  opts.SendPack,
		Tail:  opts.SendTail,
		Quiet: opts.SendQuiet,
		Head:  Headroom,
		Plan:  shapePlan(false, inner, 0),
		Pad:   true,
		Fill:  shapeFill,
	}, n.write)
	return n
}

func (n *bridge) write(wire []byte, pad int) error {
	n.wMu.Lock()
	defer n.wMu.Unlock()
	if n.greeted {
		return n.fail(n.tun.SendWirePad(wire, pad))
	}
	n.greeted = true
	pre := GetBuf(len(wire) + 1)
	pre[Headroom] = RespOK
	copy(pre[Headroom+1:], wire[Headroom:])
	err := n.tun.SendWirePad(pre, pad)
	PutBuf(pre)
	return n.fail(err)
}

func (n *bridge) fail(err error) error {
	if err != nil {
		n.broken.Store(true)
	}
	return err
}

func (n *bridge) sendNap() error {
	n.wMu.Lock()
	defer n.wMu.Unlock()
	if !n.greeted {
		n.greeted = true
		if err := n.tun.Send(nil, OKByte); err != nil {
			return err
		}
	}
	return n.tun.Nap()
}

func (n *bridge) stop() {
	n.access.Lock()
	n.closed = true
	n.box.Drain()
	n.cond.Broadcast()
	n.access.Unlock()
	_ = n.target.Close()
}

func (n *bridge) deposit(p []byte) bool {
	n.access.Lock()
	defer n.access.Unlock()
	for n.box.Size() >= n.srv.opts.MaxQueue && !n.closed {
		n.cond.Wait()
	}
	if n.closed {
		return false
	}
	n.box.Push(p)
	n.cond.Broadcast()
	return true
}

func (n *bridge) gather() {
	defer close(n.gatherFinish)
	for {
		if n.napSent.Load() {
			_ = n.tun.SetReadDeadline(time.Now().Add(n.half))
		}
		p, err := n.tun.ReadFrame()
		if err != nil {
			if errors.Is(err, ErrNap) {
				n.napSeen.Store(true)
				_ = n.target.SetReadDeadline(time.Now().Add(n.half))
			} else {
				n.broken.Store(true)
			}
			n.access.Lock()
			n.eof = true
			n.cond.Broadcast()
			n.access.Unlock()
			return
		}
		if !n.deposit(p) {
			PutBuf(p)
		}
	}
}

func (n *bridge) feed() {
	defer n.feedWG.Done()
	for {
		n.access.Lock()
		for n.box.Empty() && !n.eof && !n.closed {
			n.cond.Wait()
		}
		if n.closed {
			n.access.Unlock()
			return
		}
		if n.box.Empty() {
			n.access.Unlock()
			if n.broken.Load() {
				n.stop()
			} else {
				_ = n.target.CloseWrite()
			}
			return
		}
		d, merged := n.box.Merge(nil)
		n.cond.Broadcast()
		n.access.Unlock()

		_, err := n.target.Write(d)
		if !merged {
			PutBuf(d)
		}
		if err != nil {
			n.srv.logger.Debug("target write failed: ", err)
			n.stop()
			return
		}
	}
}

func (n *bridge) mill() (clean bool) {
	wire := GetBuf(Headroom + PackCap)
	defer PutBuf(wire)
	half := PackCap >> 1
	defer func() {
		n.gate.Flush()
		n.gate.Close()
	}()

	for {
		if n.napSeen.Load() {
			_ = n.target.SetReadDeadline(time.Now().Add(n.half))
		}
		k, err := n.target.Read(wire[Headroom:])
		if k > 0 {
			if k >= half {
				n.gate.Flush()
				if n.write(wire[:Headroom+k], 0) != nil {
					return
				}
			} else {
				n.gate.Feed(wire[Headroom : Headroom+k])
			}
			if n.broken.Load() {
				return
			}
		}
		if err != nil {
			if errors.Is(err, io.EOF) {
				return !n.broken.Load()
			}
			if !errors.Is(err, net.ErrClosed) {
				n.srv.logger.Debug("target read ended: ", err)
			}
			return false
		}
	}
}

func (n *bridge) run() bool {
	if lead := n.tun.TakePending(); lead != nil {
		n.box.Push(lead)
	}
	n.feedWG.Add(1)
	go n.feed()
	go n.gather()

	if !n.mill() {
		n.stop()
		n.feedWG.Wait()
		n.dispose()
		if n.broken.Load() || n.sendNap() != nil {
			return false
		}
		n.napSent.Store(true)
		_ = n.tun.SetReadDeadline(time.Now().Add(serverDrain))
		<-n.gatherFinish
		return n.finish()
	}

	if n.sendNap() != nil {
		n.stop()
		n.feedWG.Wait()
		n.dispose()
		return false
	}
	n.napSent.Store(true)
	_ = n.tun.SetReadDeadline(time.Now().Add(n.half))
	<-n.gatherFinish
	guard := time.AfterFunc(n.half, n.stop)
	n.feedWG.Wait()
	guard.Stop()
	n.stop()
	n.dispose()
	return n.finish()
}

func (n *bridge) dispose() {
	n.access.Lock()
	n.box.Dispose()
	n.access.Unlock()
}

func (n *bridge) finish() bool {
	if n.broken.Load() || !n.napSeen.Load() {
		return false
	}
	_ = n.tun.SetReadDeadline(time.Time{})
	return true
}

var httpMethods = []string{"GET ", "HEAD ", "POST ", "PUT ", "DELETE ", "OPTIONS ", "PATCH ", "CONNECT ", "TRACE ", "PRI "}

const decoyWelcome = "<!DOCTYPE html>\n<html>\n<head>\n<title>Welcome to nginx!</title>\n<style>\nhtml { color-scheme: light dark; }\nbody { width: 35em; margin: 0 auto;\nfont-family: Tahoma, Verdana, Arial, sans-serif; }\n</style>\n</head>\n<body>\n<h1>Welcome to nginx!</h1>\n<p>If you see this page, the nginx web server is successfully installed and\nworking. Further configuration is required.</p>\n\n<p>For online documentation and support please refer to\n<a href=\"http://nginx.org/\">nginx.org</a>.<br/>\nCommercial support is available at\n<a href=\"http://nginx.com/\">nginx.com</a>.</p>\n\n<p><em>Thank you for using nginx.</em></p>\n</body>\n</html>\n"

func errorPage(code int, text string) string {
	return fmt.Sprintf("<html>\r\n<head><title>%d %s</title></head>\r\n<body>\r\n<center><h1>%d %s</h1></center>\r\n<hr><center>nginx</center>\r\n</body>\r\n</html>\r\n", code, text, code, text)
}

func decoyReply(head []byte) []byte {
	line := string(head)
	if i := strings.Index(line, "\r\n"); i >= 0 {
		line = line[:i]
	}
	status, text, body, isHead := 400, "Bad Request", errorPage(400, "Bad Request"), false
	for _, m := range httpMethods {
		if strings.HasPrefix(line, m) {
			isHead = m == "HEAD "
			if strings.HasPrefix(line[len(m):], "/ ") || strings.HasPrefix(line[len(m):], "/index.html ") {
				status, text, body = 200, "OK", decoyWelcome
			} else {
				status, text, body = 404, "Not Found", errorPage(404, "Not Found")
			}
			break
		}
	}
	var out bytes.Buffer
	fmt.Fprintf(&out, "HTTP/1.1 %d %s\r\nServer: nginx\r\nDate: %s\r\nContent-Type: text/html\r\nContent-Length: %d\r\nConnection: close\r\n\r\n",
		status, text, time.Now().UTC().Format(http.TimeFormat), len(body))
	if !isHead {
		out.WriteString(body)
	}
	return out.Bytes()
}

func (s *Service) decoy(mc *Tunnel, prefix []byte) {
	_ = mc.Conn.SetDeadline(time.Now().Add(decoyWait))
	head := append([]byte(nil), prefix...)
	buf := make([]byte, 1024)
	for len(head) < decoyHead && !bytes.Contains(head, []byte("\r\n\r\n")) {
		n, err := mc.rd.Read(buf)
		head = append(head, buf[:n]...)
		if err != nil {
			break
		}
	}
	_, _ = mc.Conn.Write(decoyReply(head))
}
