package nfq

import (
	"fmt"
	"net"
	"sync/atomic"
	"time"

	"github.com/florianl/go-nfqueue"
	"github.com/tevino/abool"
	"github.com/lonelysadness/OpenMonitor/pkg/netutils"
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

	// Protocol constants
	ProtocolICMP  = 1
	ProtocolIGMP  = 2
	ProtocolTCP   = 6
	ProtocolUDP   = 17
	ProtocolICMP6 = 58
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

	nfq := p.queue.nf.Load().(*nfqueue.Nfqueue)
	for {
		if err := nfq.SetVerdictWithMark(p.ID, nfqueue.NfAccept, int(mark)); err != nil {
			// Check for temporary errors
			if opErr, ok := err.(interface{ Temporary() bool }); ok && opErr.Temporary() {
				continue
			}
			if opErr, ok := err.(interface{ Timeout() bool }); ok && opErr.Timeout() {
				continue
			}

			// For non-temporary errors, trigger queue restart
			select {
			case p.queue.restart <- struct{}{}:
			default:
			}
			
			return fmt.Errorf("failed to set verdict %s: %w", markToString(mark), err)
		}
		return nil
	}
}

func (p *Packet) Accept() error {
	if p.verdictPending.SetToIf(false, true) {
		defer close(p.verdictSet)
		return p.setVerdict(MarkAccept)
	}
	return fmt.Errorf("verdict already set")
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

// Add helper methods
func (p *Packet) IsICMP() bool {
	return p.Protocol == ProtocolICMP || p.Protocol == ProtocolICMP6
}

func (p *Packet) IsIGMP() bool {
	return p.Protocol == ProtocolIGMP
}

func (p *Packet) IsTCP() bool {
	return p.Protocol == ProtocolTCP
}

func (p *Packet) IsUDP() bool {
	return p.Protocol == ProtocolUDP
}

// String returns a string representation of the packet
func (p *Packet) String() string {
	srcScope := netutils.GetIPScope(p.SrcIP)
	dstScope := netutils.GetIPScope(p.DstIP)
	return fmt.Sprintf("%s(%s):%d -> %s(%s):%d (Proto: %d, ID: %d)",
		p.SrcIP, srcScope, p.SrcPort, 
		p.DstIP, dstScope, p.DstPort, 
		p.Protocol, p.ID)
}
