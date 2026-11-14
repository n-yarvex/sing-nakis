package nakis

import "time"

const (
	FrameCap   = BufMax - 2
	PackCap    = FrameCap - 1
	ShapeCap   = 16382
	ShapeSlots = 8
)

const (
	uotHost     = "udp.nakis.arpa"
	udpQueueMax = 1 << 20
	udpBatchMax = 32 << 10
	udpPadMax   = 400
	udpTick     = 10 * time.Second
	udpGiveUp   = 50
	udpRecvCap  = 256
)

const (
	spawnCap    = 16
	raceStep    = 50 * time.Millisecond
	clientDrain = 500 * time.Millisecond
	maxDrain    = 5 * time.Second
	scoreCap    = 4096
	abortWait   = 3 * time.Second
	serverDrain = 5 * time.Second
	firstBody   = 3 * time.Second
	decoyWait   = time.Second
	decoyHead   = 4096
)

func clamp(v, lo, hi int) int { return min(max(v, lo), hi) }

func orDuration(v, fallback time.Duration) time.Duration {
	if v <= 0 {
		return fallback
	}
	return v
}

func orInt(v, fallback int) int {
	if v == 0 {
		return fallback
	}
	if v < 0 {
		return 0
	}
	return v
}
