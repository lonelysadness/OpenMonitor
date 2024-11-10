package nfq

import (
	"fmt"
	"net"
	"sync/atomic"
	"time"

	"github.com/florianl/go-nfqueue"
	"github.com/tevino/abool"
)

// Packet represents a network packet
type Packet struct {
	ID        uint32
	SrcIP     net.IP
	DstIP     net.IP
	SrcPort   uint16
	DstPort   uint16
	Protocol  uint8
	Inbound   bool
	Timestamp time.Time

	queue          *Queue
	verdictSet     chan struct{}
	verdictPending *abool.AtomicBool
}

// Mark constants for packet handling
const (
	MarkAccept       = 1700
	MarkBlock        = 1701
	MarkDrop         = 1702
	MarkAcceptAlways = 1710
	MarkBlockAlways  = 1711
	MarkDropAlways   = 1712
)

func markToString(mark uint32) string {
	switch mark {
	case MarkAccept:
		return "Accept"
	case MarkBlock:
		return "Block"
	case MarkDrop:
		return "Drop"
	case MarkAcceptAlways:
		return "AcceptAlways"
	case MarkBlockAlways:
		return "BlockAlways"
	case MarkDropAlways:
		return "DropAlways"
	default:
		return fmt.Sprintf("unknown(%d)", mark)
	}
}

func (p *Packet) setVerdict(mark uint32) error {
	atomic.AddUint64(&p.queue.pendingVerdicts, 1)
	defer func() {
		atomic.AddUint64(&p.queue.pendingVerdicts, ^uint64(0))
		select {
		case p.queue.verdictCompleted <- struct{}{}:
		default:
		}
	}()

	// Synchronous verdict setting with retries
	nfq := p.queue.nf.Load().(*nfqueue.Nfqueue)
	for attempt := 0; attempt < 5; attempt++ {
		err := nfq.SetVerdictWithMark(p.ID, nfqueue.NfAccept, int(mark))
		if err == nil {
			// Update verdict statistics
			switch mark {
			case MarkAccept:
				atomic.AddUint64(&p.queue.Stats.Accept, 1)
			case MarkBlock:
				atomic.AddUint64(&p.queue.Stats.Block, 1)
			case MarkDrop:
				atomic.AddUint64(&p.queue.Stats.Drop, 1)
			case MarkAcceptAlways:
				atomic.AddUint64(&p.queue.Stats.AcceptPerm, 1)
			case MarkBlockAlways:
				atomic.AddUint64(&p.queue.Stats.BlockPerm, 1)
			case MarkDropAlways:
				atomic.AddUint64(&p.queue.Stats.DropPerm, 1)
			}
			return nil
		}

		// Check if error is temporary
		if opErr, ok := err.(interface{ Temporary() bool }); ok && opErr.Temporary() {
			time.Sleep(10 * time.Millisecond)
			continue
		}

		// Terminal error, trigger queue restart
		select {
		case p.queue.Restart <- struct{}{}:
		default:
		}
		return fmt.Errorf("failed to set verdict %s (attempt %d): %w", markToString(mark), attempt, err)
	}

	atomic.AddUint64(&p.queue.Stats.Errors, 1)
	return fmt.Errorf("failed to set verdict after 5 attempts")
}

func (p *Packet) Accept() error {
	return p.setVerdict(MarkAccept)
}

func (p *Packet) Block() error {
	if p.verdictPending.SetToIf(false, true) {
		defer close(p.verdictSet)
		if p.Protocol == 1 || p.Protocol == 58 { // ICMP or ICMPv6
			return p.setVerdict(MarkDrop)
		}
		return p.setVerdict(MarkBlock)
	}
	return fmt.Errorf("verdict already set")
}

func (p *Packet) Drop() error {
	if p.verdictPending.SetToIf(false, true) {
		defer close(p.verdictSet)
		return p.setVerdict(MarkDrop)
	}
	return fmt.Errorf("verdict already set")
}

func (p *Packet) PermanentAccept() error {
	if p.verdictPending.SetToIf(false, true) {
		defer close(p.verdictSet)
		// Don't permanently accept localhost packets
		if !p.Inbound && p.DstIP.IsLoopback() {
			return p.setVerdict(MarkAccept)
		}
		return p.setVerdict(MarkAcceptAlways)
	}
	return fmt.Errorf("verdict already set")
}

func (p *Packet) PermanentBlock() error {
	if p.verdictPending.SetToIf(false, true) {
		defer close(p.verdictSet)
		if p.Protocol == 1 || p.Protocol == 58 { // ICMP or ICMPv6
			return p.setVerdict(MarkDropAlways)
		}
		return p.setVerdict(MarkBlockAlways)
	}
	return fmt.Errorf("verdict already set")
}

func (p *Packet) PermanentDrop() error {
	if p.verdictPending.SetToIf(false, true) {
		defer close(p.verdictSet)
		return p.setVerdict(MarkDropAlways)
	}
	return fmt.Errorf("verdict already set")
}
