package nakis

import (
	"io"
	"net"
	"os"
	"sync"
	"time"
)

const duplexLimit = 256 << 10

type duplexAddr string

func (a duplexAddr) Network() string { return "nakis" }

func (a duplexAddr) String() string { return string(a) }

type deadline struct {
	access sync.Mutex
	timer  *time.Timer
	cancel chan struct{}
}

func newDeadline() *deadline {
	return &deadline{cancel: make(chan struct{})}
}

func isClosed(c <-chan struct{}) bool {
	select {
	case <-c:
		return true
	default:
		return false
	}
}

func (d *deadline) set(t time.Time) {
	d.access.Lock()
	defer d.access.Unlock()
	if d.timer != nil && !d.timer.Stop() {
		<-d.cancel
	}
	d.timer = nil
	closed := isClosed(d.cancel)
	if t.IsZero() {
		if closed {
			d.cancel = make(chan struct{})
		}
		return
	}
	if wait := time.Until(t); wait > 0 {
		if closed {
			d.cancel = make(chan struct{})
		}
		cancel := d.cancel
		d.timer = time.AfterFunc(wait, func() { close(cancel) })
		return
	}
	if !closed {
		close(d.cancel)
	}
}

func (d *deadline) wait() <-chan struct{} {
	d.access.Lock()
	defer d.access.Unlock()
	return d.cancel
}

type pipe struct {
	access   sync.Mutex
	data     []byte
	eof      bool
	err      error
	gone     bool
	readable chan struct{}
	writable chan struct{}
}

func newPipe() *pipe {
	return &pipe{readable: make(chan struct{}, 1), writable: make(chan struct{}, 1)}
}

func poke(c chan struct{}) {
	select {
	case c <- struct{}{}:
	default:
	}
}

type duplexConn struct {
	in, out *pipe
	local   net.Addr
	remote  net.Addr
	rd, wd  *deadline
	closed  chan struct{}
	once    sync.Once
}

func newDuplex(localA, remoteA net.Addr) (*duplexConn, *duplexConn) {
	ab, ba := newPipe(), newPipe()
	a := &duplexConn{in: ba, out: ab, local: localA, remote: remoteA, rd: newDeadline(), wd: newDeadline(), closed: make(chan struct{})}
	b := &duplexConn{in: ab, out: ba, local: remoteA, remote: localA, rd: newDeadline(), wd: newDeadline(), closed: make(chan struct{})}
	return a, b
}

func (c *duplexConn) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	for {
		select {
		case <-c.closed:
			return 0, net.ErrClosed
		case <-c.rd.wait():
			return 0, os.ErrDeadlineExceeded
		default:
		}
		c.in.access.Lock()
		if len(c.in.data) > 0 {
			n := copy(p, c.in.data)
			c.in.data = c.in.data[n:]
			if len(c.in.data) == 0 {
				c.in.data = nil
			}
			c.in.access.Unlock()
			poke(c.in.writable)
			return n, nil
		}
		if c.in.eof {
			err := c.in.err
			c.in.access.Unlock()
			if err != nil {
				return 0, err
			}
			return 0, io.EOF
		}
		c.in.access.Unlock()
		select {
		case <-c.in.readable:
		case <-c.rd.wait():
			return 0, os.ErrDeadlineExceeded
		case <-c.closed:
			return 0, net.ErrClosed
		}
	}
}

func (c *duplexConn) Write(p []byte) (int, error) {
	written := 0
	for {
		select {
		case <-c.closed:
			return written, net.ErrClosed
		case <-c.wd.wait():
			return written, os.ErrDeadlineExceeded
		default:
		}
		c.out.access.Lock()
		if c.out.gone || c.out.eof {
			c.out.access.Unlock()
			return written, io.ErrClosedPipe
		}
		if len(p) == 0 {
			c.out.access.Unlock()
			return written, nil
		}
		if space := duplexLimit - len(c.out.data); space > 0 {
			n := min(space, len(p))
			c.out.data = append(c.out.data, p[:n]...)
			c.out.access.Unlock()
			poke(c.out.readable)
			written += n
			p = p[n:]
			continue
		}
		c.out.access.Unlock()
		select {
		case <-c.out.writable:
		case <-c.wd.wait():
			return written, os.ErrDeadlineExceeded
		case <-c.closed:
			return written, net.ErrClosed
		}
	}
}

func (c *duplexConn) CloseWrite() error {
	c.out.access.Lock()
	c.out.eof = true
	c.out.access.Unlock()
	poke(c.out.readable)
	poke(c.out.writable)
	return nil
}

func (c *duplexConn) abort(err error) {
	c.out.access.Lock()
	if !c.out.eof {
		c.out.err = err
	}
	c.out.eof = true
	c.out.access.Unlock()
	poke(c.out.readable)
	poke(c.out.writable)
}

func (c *duplexConn) Close() error {
	c.once.Do(func() {
		close(c.closed)
		c.out.access.Lock()
		c.out.eof = true
		c.out.access.Unlock()
		c.in.access.Lock()
		c.in.gone = true
		c.in.data = nil
		c.in.access.Unlock()
		poke(c.out.readable)
		poke(c.out.writable)
		poke(c.in.readable)
		poke(c.in.writable)
	})
	return nil
}

func (c *duplexConn) LocalAddr() net.Addr { return c.local }

func (c *duplexConn) RemoteAddr() net.Addr { return c.remote }

func (c *duplexConn) SetDeadline(t time.Time) error {
	c.rd.set(t)
	c.wd.set(t)
	return nil
}

func (c *duplexConn) SetReadDeadline(t time.Time) error {
	c.rd.set(t)
	return nil
}

func (c *duplexConn) SetWriteDeadline(t time.Time) error {
	c.wd.set(t)
	return nil
}
