package nakis

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"math/rand"
	"net"
	"sort"
	"strconv"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
)

type ClientOptions struct {
	Context          context.Context
	Logger           logger.Logger
	UUID             string
	Servers          []M.Socksaddr
	DialOut          func(ctx context.Context, server M.Socksaddr) (net.Conn, error)
	Handshake        func(ctx context.Context, conn net.Conn) (net.Conn, error)
	HandshakeTimeout time.Duration
	RaceCount        int
	PoolLo           int
	PoolHi           int
	PoolMaxAge       time.Duration
	PoolMaxUses      int
	SendPack         int
	SendTail         int
	SendQuiet        int
	ShapeUp          []Range
	ShapeWait        time.Duration
	HalfCloseTimeout time.Duration
	UDPJitter        time.Duration
	NoWarm           bool
}

type tuning struct {
	poolHi int
	raceN  int
}

type Client struct {
	opts   ClientOptions
	racer  *racer
	pool   *idlePool
	plan   []Range
	logger logger.Logger

	hinted  atomic.Bool
	parked  atomic.Bool
	firstUp atomic.Bool
	sem     chan struct{}
	kick    chan struct{}

	tuneNow  atomic.Pointer[tuning]
	tuneFast tuning
	tuneMid  tuning
	tuneSlow tuning

	access  sync.Mutex
	want    int
	flying  int
	used    int
	miss    int
	calm    int
	fails   int
	hold    time.Time
	hits    uint64
	misses  uint64
	tuneLap int

	ctx      context.Context
	cancel   context.CancelFunc
	loop     sync.WaitGroup
	sessions sync.WaitGroup

	sessionAccess sync.Mutex
	active        map[*sessionRef]struct{}
	closing       bool
}

type sessionRef struct {
	access  sync.Mutex
	closer  func()
	tunnel  *Tunnel
	aborted bool
}

func (s *sessionRef) bind(mc *Tunnel) bool {
	s.access.Lock()
	defer s.access.Unlock()
	if s.aborted {
		return false
	}
	s.tunnel = mc
	return true
}

func (s *sessionRef) abort() {
	s.access.Lock()
	s.aborted = true
	mc, closer := s.tunnel, s.closer
	s.access.Unlock()
	if closer != nil {
		closer()
	}
	if mc != nil {
		_ = mc.Close()
	}
}

func (c *Client) beginSession(closer func()) (*sessionRef, bool) {
	c.sessionAccess.Lock()
	defer c.sessionAccess.Unlock()
	if c.closing {
		return nil, false
	}
	ref := &sessionRef{closer: closer}
	c.active[ref] = struct{}{}
	c.sessions.Add(1)
	return ref, true
}

func (c *Client) endSession(ref *sessionRef) {
	c.sessionAccess.Lock()
	delete(c.active, ref)
	c.sessionAccess.Unlock()
	c.sessions.Done()
}

func (c *Client) abortSessions() {
	c.sessionAccess.Lock()
	refs := make([]*sessionRef, 0, len(c.active))
	for ref := range c.active {
		refs = append(refs, ref)
	}
	c.sessionAccess.Unlock()
	for _, ref := range refs {
		ref.abort()
	}
}

func NewClient(options ClientOptions) (*Client, error) {
	id, err := ParseUUID(options.UUID)
	if err != nil {
		return nil, E.Cause(err, "invalid uuid")
	}
	if len(options.Servers) == 0 {
		return nil, E.New("missing server")
	}
	if options.DialOut == nil {
		return nil, E.New("missing dial function")
	}
	if options.Logger == nil {
		options.Logger = logger.NOP()
	}
	for _, plan := range options.ShapeUp {
		if plan.Min < 1 || plan.Max < plan.Min || plan.Max > ShapeCap {
			return nil, E.New("invalid shape range: ", plan.Min, "-", plan.Max)
		}
	}
	if len(options.ShapeUp) > ShapeSlots {
		return nil, E.New("shape_up takes at most ", ShapeSlots, " ranges")
	}
	options.RaceCount = clamp(orInt(options.RaceCount, 3), 2, 12)
	options.PoolLo = clamp(orInt(options.PoolLo, 2), 1, 1024)
	options.PoolHi = clamp(orInt(options.PoolHi, 32), options.PoolLo+1, 4096)
	options.PoolMaxUses = clamp(orInt(options.PoolMaxUses, 8), 0, 100)
	options.SendPack = clamp(orInt(options.SendPack, 20*1024), 1024, PackCap)
	options.SendTail = clamp(orInt(options.SendTail, 512), 0, options.SendPack-1)
	options.SendQuiet = clamp(orInt(options.SendQuiet, 4), 0, 64)
	options.HandshakeTimeout = orDuration(options.HandshakeTimeout, 10*time.Second)
	options.PoolMaxAge = orDuration(options.PoolMaxAge, 45*time.Second)
	options.ShapeWait = orDuration(options.ShapeWait, 20*time.Millisecond)
	options.HalfCloseTimeout = orDuration(options.HalfCloseTimeout, 120*time.Second)
	options.UDPJitter = jitterSpan(options.UDPJitter)
	if options.Context == nil {
		options.Context = context.Background()
	}

	ctx, cancel := context.WithCancel(options.Context)
	c := &Client{
		opts:     options,
		logger:   options.Logger,
		sem:      make(chan struct{}, spawnCap),
		kick:     make(chan struct{}, 1),
		want:     options.PoolLo,
		ctx:      ctx,
		cancel:   cancel,
		active:   make(map[*sessionRef]struct{}),
		tuneFast: tuning{poolHi: options.PoolHi, raceN: 10},
		tuneMid:  tuning{poolHi: options.PoolHi, raceN: options.RaceCount},
		tuneSlow: tuning{poolHi: min(options.PoolLo+8, options.PoolHi), raceN: 3},
	}
	mid := c.tuneMid
	c.tuneNow.Store(&mid)
	c.plan = options.ShapeUp
	c.pool = newIdlePool(options.PoolHi, options.PoolMaxAge, options.PoolMaxUses)
	c.racer = &racer{
		id:        id,
		servers:   options.Servers,
		dialOut:   options.DialOut,
		handshake: options.Handshake,
		timeout:   options.HandshakeTimeout,
		step:      raceStep,
		spare:     c.stash,
		book:      make(map[string]*scoreCard),
	}
	return c, nil
}

func jitterSpan(d time.Duration) time.Duration {
	switch {
	case d == 0:
		return 8 * time.Millisecond
	case d < 0:
		return 0
	}
	return min(d, 200*time.Millisecond)
}

func (c *Client) hintOnce(err error) {
	if !errors.Is(err, io.EOF) && !errors.Is(err, syscall.ECONNRESET) {
		return
	}
	if c.hinted.CompareAndSwap(false, true) {
		c.logger.Warn("the server hung up on a tunnel without answering, usually that means a wrong uuid or clocks more than 30s apart: ", err)
		time.AfterFunc(30*time.Second, func() { c.hinted.Store(false) })
	}
}

func (c *Client) stash(mc *Tunnel) {
	c.pool.put(mc, 0)
}

func (c *Client) poke() {
	select {
	case c.kick <- struct{}{}:
	default:
	}
}

func approach(cur, target int) int {
	step := (target - cur) / 3
	if step == 0 {
		switch {
		case target > cur:
			step = 1
		case target < cur:
			step = -1
		}
	}
	return cur + step
}

func (c *Client) pickTuning(fails, total int, hitRate float64, rtt int64) tuning {
	switch {
	case fails >= 3:
		return c.tuneFast
	case total < 8:
		return c.tuneMid
	case hitRate < 0.5:
		return c.tuneFast
	case fails == 0 && hitRate > 0.9 && rtt > 0 && rtt < int64(300*time.Millisecond):
		return c.tuneSlow
	default:
		return c.tuneMid
	}
}

func (c *Client) retune() {
	c.access.Lock()
	c.tuneLap++
	if c.tuneLap < 3 {
		c.access.Unlock()
		return
	}
	c.tuneLap = 0
	fails := c.fails
	hits, misses := c.hits, c.misses
	c.access.Unlock()

	total := int(hits + misses)
	rate := -1.0
	if total >= 8 {
		rate = float64(hits) / float64(total)
	}
	cur := c.tuneNow.Load()
	goal := c.pickTuning(fails, total, rate, c.racer.avgRTT())
	next := tuning{
		poolHi: approach(cur.poolHi, goal.poolHi),
		raceN:  approach(cur.raceN, goal.raceN),
	}
	next.poolHi = min(max(next.poolHi, min(c.opts.PoolLo+4, c.opts.PoolHi)), c.opts.PoolHi)
	next.raceN = min(max(next.raceN, 2), 12)
	c.tuneNow.Store(&next)
}

func (c *Client) spawn() {
	select {
	case c.sem <- struct{}{}:
	case <-c.ctx.Done():
		c.access.Lock()
		c.flying--
		c.access.Unlock()
		return
	}
	defer func() { <-c.sem }()

	pause := time.NewTimer(time.Duration(rand.Int63n(int64(120 * time.Millisecond))))
	select {
	case <-pause.C:
	case <-c.ctx.Done():
		pause.Stop()
	}
	mc, err := c.racer.dialOne(c.ctx)

	c.access.Lock()
	c.flying--
	was := c.fails
	if err != nil {
		c.fails++
		c.hold = time.Now().Add(500 * time.Millisecond << uint(min(c.fails, 6)))
	} else {
		c.fails = 0
	}
	fails := c.fails
	c.access.Unlock()
	if err == nil {
		if was >= 3 {
			c.logger.Info("tunnels to the server are working again")
		} else if c.firstUp.CompareAndSwap(false, true) {
			c.logger.Info("first tunnel to the server is up")
		}
		c.stash(mc)
		return
	}
	if c.ctx.Err() == nil && (fails == 1 || fails%10 == 0) {
		c.logger.Warn("couldn't open a tunnel to the server (", fails, " failed in a row), will keep retrying with a growing pause: ", err)
	}
}

func (c *Client) topUp() {
	if c.opts.NoWarm || c.parked.Load() {
		return
	}
	idle := c.pool.size()
	c.access.Lock()
	if time.Now().Before(c.hold) {
		c.access.Unlock()
		return
	}
	n := min(min(c.want, c.pool.maxSize)-idle-c.flying, spawnCap-c.flying)
	if n <= 0 {
		c.access.Unlock()
		return
	}
	c.flying += n
	c.access.Unlock()
	for i := 0; i < n; i++ {
		go c.spawn()
	}
}

func (c *Client) tick() {
	c.access.Lock()
	need := c.used + 1
	c.used = 0
	prev := c.want
	switch {
	case c.miss > 0:
		c.want += max(c.miss*4, 4)
		c.calm = 0
	case need > c.want:
		c.want = need + need/2
		c.calm = 0
	default:
		c.calm++
		if c.calm >= 10 && c.want > c.opts.PoolLo && c.want > need*2 {
			c.want = max(c.want-c.want/8, c.opts.PoolLo)
			c.calm = 0
		}
	}
	c.want = min(max(c.want, c.opts.PoolLo), min(c.tuneNow.Load().poolHi, c.pool.maxSize))
	c.miss = 0
	now := c.want
	c.access.Unlock()

	if now != prev {
		c.logger.Debug("pool want adjusted from ", prev, " to ", now)
	}
	c.pool.sweep()
	c.retune()
}

func (c *Client) run() {
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	last := time.Now()
	for {
		select {
		case <-c.ctx.Done():
			return
		case <-c.kick:
		case <-ticker.C:
		}
		if time.Since(last) >= time.Second {
			c.tick()
			last = time.Now()
		}
		c.topUp()
	}
}

func (c *Client) Start() {
	c.loop.Add(1)
	go func() {
		defer c.loop.Done()
		c.run()
	}()
	c.poke()
}

func (c *Client) SetKeepIdleConnections(keep bool) {
	c.parked.Store(!keep)
	if keep {
		c.poke()
		return
	}
	c.pool.drain()
}

func (c *Client) CloseIdleConnections() {
	c.pool.drain()
}

func (c *Client) Reset() {
	c.pool.drain()
	c.access.Lock()
	c.fails = 0
	c.hold = time.Time{}
	c.access.Unlock()
	c.racer.forget()
	c.poke()
}

func (c *Client) Close() error {
	return c.Shutdown(5 * time.Second)
}

func (c *Client) Shutdown(timeout time.Duration) error {
	c.sessionAccess.Lock()
	c.closing = true
	c.sessionAccess.Unlock()
	c.cancel()
	done := make(chan struct{})
	go func() {
		c.loop.Wait()
		c.sessions.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(timeout):
		c.logger.Warn("some sessions were still running when the shutdown wait ran out, closing them")
		c.abortSessions()
		select {
		case <-done:
		case <-time.After(abortWait):
			c.logger.Error("some sessions did not stop even after being closed, giving up on them")
		}
	}
	c.pool.closeAll()
	return nil
}

func (c *Client) lease(ctx context.Context) (*leased, error) {
	if mc, uses, ok := c.pool.take(); ok {
		c.access.Lock()
		c.hits++
		c.access.Unlock()
		return c.fresh(&leased{mc: mc, home: c.pool, uses: uses + 1}), nil
	}
	c.access.Lock()
	c.miss++
	c.misses++
	c.access.Unlock()
	mc, err := c.racer.race(ctx, c.tuneNow.Load().raceN)
	if err != nil {
		return nil, err
	}
	return c.fresh(&leased{mc: mc, home: c.pool, uses: 1}), nil
}

func (c *Client) drainWindow() time.Duration {
	d := clientDrain
	if rtt := time.Duration(c.racer.avgRTT()) * 2; rtt > d {
		d = min(rtt, maxDrain)
	}
	return d
}

func (c *Client) fresh(l *leased) *leased {
	if !l.mc.life.drawn() {
		l.mc.life = newLife(c.opts.PoolMaxUses)
	}
	return l
}

func (c *Client) dialTunnel(ctx context.Context, host string, port uint16) (*leased, error) {
	hello, err := RequestBytes(host, port)
	if err != nil {
		return nil, err
	}
	c.access.Lock()
	c.used++
	c.access.Unlock()
	l, err := c.lease(ctx)
	if err != nil {
		return nil, err
	}
	l.first = hello
	l.inner = tlsLike(strconv.Itoa(int(port)))
	if !l.mc.sealed {
		l.first = append(MakeProof(c.racer.id, l.mc.bind), hello...)
		l.mc.sealed = true
	}
	return l, nil
}

func (c *Client) flight(first int, inner bool) (plan []Range, pad bool, fill time.Duration) {
	if len(c.plan) == 0 {
		return shapePlan(true, inner, first), true, shapeFill
	}
	plan = append([]Range(nil), c.plan...)
	plan[0].Min = max(plan[0].Min, first)
	plan[0].Max = max(plan[0].Max, plan[0].Min)
	return plan, false, c.opts.ShapeWait
}

func (c *Client) DialContext(ctx context.Context, destination M.Socksaddr) (net.Conn, error) {
	host := destination.AddrString()
	if host == "" || destination.Port == 0 {
		return nil, E.New("invalid destination ", destination)
	}
	if host == uotHost {
		return nil, E.New("reserved destination ", host)
	}
	app, user := newDuplex(duplexAddr("nakis-local"), destination)
	ref, ok := c.beginSession(func() { _ = app.Close() })
	if !ok {
		return nil, net.ErrClosed
	}
	l, err := c.dialTunnel(ctx, host, destination.Port)
	if err != nil {
		c.endSession(ref)
		return nil, err
	}
	if !ref.bind(l.mc) {
		_ = l.mc.Close()
		c.endSession(ref)
		return nil, net.ErrClosed
	}
	go func() {
		defer c.endSession(ref)
		defer app.Close()
		defer func() {
			if r := recover(); r != nil {
				c.logger.Error("recovered from a crash while serving a stream: ", r)
			}
		}()
		c.shuttle(app, l, destination)
		l.release()
	}()
	return user, nil
}

type idlePool struct {
	maxSize int
	maxAge  time.Duration
	maxUses int

	access sync.Mutex
	idle   []idleItem
	closed bool
}

type idleItem struct {
	mc      *Tunnel
	watch   *idleWatch
	expires time.Time
	uses    int
}

func newIdlePool(maxSize int, maxAge time.Duration, maxUses int) *idlePool {
	return &idlePool{maxSize: maxSize, maxAge: maxAge, maxUses: maxUses}
}

type leased struct {
	mc      *Tunnel
	home    *idlePool
	uses    int
	first   []byte
	inner   bool
	napSent atomic.Bool
	napSeen atomic.Bool
	broken  atomic.Bool
}

func (l *leased) release() {
	if l.broken.Load() || !l.napSent.Load() || !l.napSeen.Load() || l.mc.Dirty() || l.mc.life.spent(l.uses, l.mc.Moved()) {
		_ = l.mc.Close()
		return
	}
	_ = l.mc.SetDeadline(time.Time{})
	l.home.put(l.mc, l.uses)
}

var errSkipped = errors.New("dial skipped")

type scoreCard struct {
	lat       int64
	fails     int
	coolUntil time.Time
}

type racer struct {
	servers   []M.Socksaddr
	dialOut   func(ctx context.Context, server M.Socksaddr) (net.Conn, error)
	id        []byte
	handshake func(ctx context.Context, conn net.Conn) (net.Conn, error)
	timeout   time.Duration
	step      time.Duration
	spare     func(*Tunnel)

	access sync.Mutex
	book   map[string]*scoreCard
	rtt    int64
}

func (r *racer) forget() {
	r.access.Lock()
	clear(r.book)
	r.rtt = 0
	r.access.Unlock()
}

func (r *racer) avgRTT() int64 {
	r.access.Lock()
	defer r.access.Unlock()
	return r.rtt
}

func (r *racer) grade(addr string, d time.Duration, ok bool) {
	r.access.Lock()
	defer r.access.Unlock()
	card := r.book[addr]
	if card == nil {
		if len(r.book) >= scoreCap {
			for key := range r.book {
				delete(r.book, key)
				break
			}
		}
		card = &scoreCard{}
		r.book[addr] = card
	}
	if !ok {
		card.fails = min(card.fails+1, 10)
		card.coolUntil = time.Now().Add(min(time.Duration(card.fails)*2*time.Second, time.Minute))
		card.lat = min(card.lat*2+int64(time.Second), int64(30*time.Second))
		return
	}
	card.fails = 0
	card.coolUntil = time.Time{}
	if card.lat == 0 || card.lat >= int64(time.Second) {
		card.lat = int64(d)
	} else {
		card.lat += (int64(d) - card.lat) / 4
	}
	if d > 0 {
		if r.rtt == 0 {
			r.rtt = int64(d)
		} else {
			r.rtt += (int64(d) - r.rtt) / 8
		}
	}
}

func (r *racer) cost(addr string, now time.Time) int64 {
	card := r.book[addr]
	if card == nil {
		return int64(100 * time.Millisecond)
	}
	if now.Before(card.coolUntil) {
		return card.lat + int64(2*time.Second)
	}
	if card.lat > 0 {
		return card.lat
	}
	return int64(100 * time.Millisecond)
}

func (r *racer) candidates() []M.Socksaddr {
	addrs := append([]M.Socksaddr(nil), r.servers...)
	rand.Shuffle(len(addrs), func(i, j int) { addrs[i], addrs[j] = addrs[j], addrs[i] })
	now := time.Now()
	costs := make(map[string]int64, len(addrs))
	r.access.Lock()
	for _, addr := range addrs {
		costs[addr.String()] = r.cost(addr.String(), now)
	}
	r.access.Unlock()
	sort.SliceStable(addrs, func(i, j int) bool { return costs[addrs[i].String()] < costs[addrs[j].String()] })
	return addrs
}

func (r *racer) secure(ctx context.Context, raw net.Conn) (*Tunnel, error) {
	if r.handshake == nil {
		return WrapTunnel(raw, nil), nil
	}
	b := NewBatcher(raw)
	hctx, cancel := context.WithTimeout(ctx, r.timeout)
	tc, err := r.handshake(hctx, b)
	cancel()
	if err != nil {
		return nil, E.Cause(err, "tls handshake")
	}
	bind, err := ExportBinding(tc)
	if err != nil {
		return nil, err
	}
	mc := WrapTunnel(tc, b)
	mc.bind = bind
	return mc, nil
}

func ExportBinding(conn net.Conn) ([]byte, error) {
	for conn != nil {
		if holder, ok := conn.(interface{ ConnectionState() tls.ConnectionState }); ok {
			state := holder.ConnectionState()
			return state.ExportKeyingMaterial("nakis/bind", nil, 32)
		}
		inner, ok := conn.(interface{ NetConn() net.Conn })
		if !ok {
			break
		}
		conn = inner.NetConn()
	}
	return nil, E.New("tls connection can't export keying material, utls and reality are not supported")
}

func (r *racer) dialTo(ctx context.Context, server M.Socksaddr) (*Tunnel, error) {
	start := time.Now()
	key := server.String()
	raw, err := r.dialOut(ctx, server)
	if err != nil {
		if ctx.Err() == nil {
			r.grade(key, 0, false)
		}
		return nil, err
	}
	mc, err := r.secure(ctx, raw)
	if err != nil {
		_ = raw.Close()
		if ctx.Err() == nil {
			r.grade(key, 0, false)
		}
		return nil, err
	}
	r.grade(key, time.Since(start), true)
	return mc, nil
}

func (r *racer) dialOne(ctx context.Context) (*Tunnel, error) {
	lastErr := errors.New("all dials failed")
	for _, server := range r.candidates() {
		mc, err := r.dialTo(ctx, server)
		if err == nil {
			return mc, nil
		}
		lastErr = err
	}
	return nil, lastErr
}

type raceResult struct {
	mc  *Tunnel
	err error
}

func (r *racer) race(ctx context.Context, width int) (*Tunnel, error) {
	addrs := r.candidates()
	if len(addrs) > width {
		addrs = addrs[:width]
	}

	raceCtx, cancel := context.WithCancel(ctx)
	results := make(chan raceResult, len(addrs))
	for i, addr := range addrs {
		go func(i int, addr M.Socksaddr) {
			res := raceResult{err: errSkipped}
			defer func() {
				if r := recover(); r != nil {
					res = raceResult{err: E.New("dial panic: ", r)}
				}
				results <- res
			}()
			if i >= 2 {
				t := time.NewTimer(time.Duration(i-1) * r.step)
				defer t.Stop()
				select {
				case <-t.C:
				case <-raceCtx.Done():
					return
				}
			}
			mc, err := r.dialTo(raceCtx, addr)
			res = raceResult{mc: mc, err: err}
		}(i, addr)
	}

	var lastErr error
	for i := range addrs {
		res := <-results
		if res.err == nil {
			go r.adoptLosers(results, len(addrs)-i-1, cancel)
			return res.mc, nil
		}
		if !errors.Is(res.err, errSkipped) {
			lastErr = res.err
		}
	}
	cancel()
	if lastErr == nil {
		lastErr = errors.New("all dials skipped")
	}
	return nil, lastErr
}

func (r *racer) adoptLosers(results <-chan raceResult, left int, cancel context.CancelFunc) {
	for ; left > 0; left-- {
		res := <-results
		if res.err != nil || res.mc == nil {
			continue
		}
		if r.spare != nil {
			r.spare(res.mc)
		} else {
			_ = res.mc.Close()
		}
	}
	cancel()
}

func (p *idlePool) take() (*Tunnel, int, bool) {
	var stale []*Tunnel
	defer func() {
		for _, mc := range stale {
			_ = mc.Close()
		}
	}()
	p.access.Lock()
	defer p.access.Unlock()
	now := time.Now()
	for len(p.idle) > 0 {
		it := p.idle[len(p.idle)-1]
		p.idle = p.idle[:len(p.idle)-1]
		if now.Before(it.expires) && it.watch.Stop() {
			return it.mc, it.uses, true
		}
		stale = append(stale, it.mc)
	}
	return nil, 0, false
}

func (p *idlePool) put(mc *Tunnel, uses int) {
	if p.maxUses > 0 && uses >= p.maxUses {
		_ = mc.Close()
		return
	}
	p.access.Lock()
	if p.closed || len(p.idle) >= p.maxSize {
		p.access.Unlock()
		_ = mc.Close()
		return
	}
	p.idle = append(p.idle, idleItem{mc: mc, watch: mc.Watch(), expires: time.Now().Add(p.maxAge), uses: uses})
	p.access.Unlock()
}

func (p *idlePool) sweep() {
	var stale []*Tunnel
	p.access.Lock()
	now := time.Now()
	keep := p.idle[:0]
	for _, it := range p.idle {
		if now.Before(it.expires) && !it.watch.Dead() {
			keep = append(keep, it)
		} else {
			stale = append(stale, it.mc)
		}
	}
	clear(p.idle[len(keep):])
	p.idle = keep
	p.access.Unlock()
	for _, mc := range stale {
		_ = mc.Close()
	}
}

func (p *idlePool) size() int {
	p.access.Lock()
	defer p.access.Unlock()
	return len(p.idle)
}

func (p *idlePool) drain() {
	p.access.Lock()
	all := p.idle
	p.idle = nil
	p.access.Unlock()
	for _, it := range all {
		_ = it.mc.Close()
	}
}

func (p *idlePool) closeAll() {
	p.access.Lock()
	p.closed = true
	all := p.idle
	p.idle = nil
	p.access.Unlock()
	for _, it := range all {
		_ = it.mc.Close()
	}
}
