package nakis

import (
	"bufio"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math/big"
	mrand "math/rand/v2"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"
)

var errMangled = errors.New("nakis: malformed udp record")

type udpAddr struct {
	host string
	port uint16
}

func (a udpAddr) appendTo(b []byte) ([]byte, error) {
	if ip, err := netip.ParseAddr(a.host); err == nil {
		ip = ip.Unmap()
		if ip.Is4() {
			v := ip.As4()
			b = append(b, 1)
			b = append(b, v[:]...)
		} else {
			v := ip.As16()
			b = append(b, 4)
			b = append(b, v[:]...)
		}
	} else {
		if len(a.host) == 0 || len(a.host) > 255 {
			return nil, errMangled
		}
		b = append(b, 3, byte(len(a.host)))
		b = append(b, a.host...)
	}
	return binary.BigEndian.AppendUint16(b, a.port), nil
}

func readAddr(r io.Reader, atyp byte) (udpAddr, error) {
	var a udpAddr
	switch atyp {
	case 1, 4:
		raw := make([]byte, map[byte]int{1: 4, 4: 16}[atyp])
		if _, err := io.ReadFull(r, raw); err != nil {
			return a, err
		}
		ip, _ := netip.AddrFromSlice(raw)
		a.host = ip.String()
	case 3:
		var n [1]byte
		if _, err := io.ReadFull(r, n[:]); err != nil {
			return a, err
		}
		if n[0] == 0 {
			return a, errMangled
		}
		name := make([]byte, n[0])
		if _, err := io.ReadFull(r, name); err != nil {
			return a, err
		}
		a.host = string(name)
	default:
		return a, errMangled
	}
	var pb [2]byte
	if _, err := io.ReadFull(r, pb[:]); err != nil {
		return a, err
	}
	a.port = binary.BigEndian.Uint16(pb[:])
	return a, nil
}

func appendRecord(b []byte, a udpAddr, data []byte) ([]byte, error) {
	if len(data) > 0xFFFF {
		return nil, errMangled
	}
	b, err := a.appendTo(b)
	if err != nil {
		return nil, err
	}
	b = binary.BigEndian.AppendUint16(b, uint16(len(data)))
	return append(b, data...), nil
}

func readRecord(r *bufio.Reader, buf []byte) (udpAddr, []byte, error) {
	atyp, err := r.ReadByte()
	if err != nil {
		return udpAddr{}, nil, err
	}
	a, err := readAddr(r, atyp)
	if err != nil {
		return a, nil, midRecord(err)
	}
	var lb [2]byte
	if _, err := io.ReadFull(r, lb[:]); err != nil {
		return a, nil, midRecord(err)
	}
	n := int(binary.BigEndian.Uint16(lb[:]))
	if _, err := io.ReadFull(r, buf[:n]); err != nil {
		return a, nil, midRecord(err)
	}
	return a, buf[:n], nil
}

func midRecord(err error) error {
	if errors.Is(err, ErrNap) || errors.Is(err, io.EOF) {
		return fmt.Errorf("%w: cut short", errMangled)
	}
	return err
}

func randBelow(n int) int {
	v, err := rand.Int(rand.Reader, big.NewInt(int64(n)))
	if err != nil {
		return mrand.IntN(n)
	}
	return int(v.Int64())
}

func sendWithPad(mc *Tunnel, payload []byte) error {
	wire := GetBuf(Headroom + len(payload))
	defer PutBuf(wire)
	copy(wire[Headroom:], payload)
	return mc.SendWirePad(wire, 4+randBelow(udpPadMax))
}

type jitterMux struct {
	jitter time.Duration
	send   func([]byte) error

	mu     sync.Mutex
	cond   *sync.Cond
	q      [][]byte
	size   int
	closed bool
	failed atomic.Bool
	stop   chan struct{}
	done   chan struct{}
}

func newJitterMux(jitter time.Duration, send func([]byte) error) *jitterMux {
	m := &jitterMux{jitter: jitter, send: send, stop: make(chan struct{}), done: make(chan struct{})}
	m.cond = sync.NewCond(&m.mu)
	go m.run()
	return m
}

func (m *jitterMux) push(rec []byte) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed || m.failed.Load() || m.size+len(rec) > udpQueueMax {
		return false
	}
	cp := GetBuf(len(rec))
	copy(cp, rec)
	m.q = append(m.q, cp)
	m.size += len(rec)
	m.cond.Signal()
	return true
}

func (m *jitterMux) nap() {
	t := time.NewTimer(time.Duration(mrand.Int64N(int64(m.jitter))) + time.Microsecond)
	defer t.Stop()
	select {
	case <-t.C:
	case <-m.stop:
	}
}

func (m *jitterMux) take() []byte {
	m.mu.Lock()
	defer m.mu.Unlock()
	if len(m.q) == 0 {
		return nil
	}
	var out []byte
	i := 0
	for i < len(m.q) && (i == 0 || len(out)+len(m.q[i]) <= udpBatchMax) {
		out = append(out, m.q[i]...)
		m.size -= len(m.q[i])
		PutBuf(m.q[i])
		i++
	}
	m.q = m.q[:copy(m.q, m.q[i:])]
	return out
}

func (m *jitterMux) abandon() {
	m.failed.Store(true)
	m.mu.Lock()
	for _, p := range m.q {
		PutBuf(p)
	}
	m.q, m.size = nil, 0
	m.mu.Unlock()
}

func (m *jitterMux) run() {
	defer close(m.done)
	for {
		m.mu.Lock()
		for len(m.q) == 0 && !m.closed {
			m.cond.Wait()
		}
		empty := len(m.q) == 0
		m.mu.Unlock()
		if empty {
			return
		}
		if m.jitter > 0 {
			m.nap()
		}
		for {
			batch := m.take()
			if batch == nil {
				break
			}
			if err := m.send(batch); err != nil {
				m.abandon()
				return
			}
		}
	}
}

func (m *jitterMux) close() {
	m.mu.Lock()
	if !m.closed {
		m.closed = true
		close(m.stop)
	}
	m.cond.Broadcast()
	m.mu.Unlock()
	<-m.done
}
