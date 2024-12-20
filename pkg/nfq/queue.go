package nfq

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"runtime"
	"sync/atomic"
	"time"

	"github.com/florianl/go-nfqueue"
	"github.com/tevino/abool"
)

// QueueStats holds statistics for packet verdicts
type QueueStats struct {
	Total      uint64
	Accept     uint64
	Block      uint64
	Drop       uint64
	AcceptPerm uint64
	BlockPerm  uint64
	DropPerm   uint64
	Errors     uint64
}

// Queue wraps a nfqueue
type Queue struct {
	id                   uint16
	afFamily             uint8
	nf                   atomic.Value
	packets              chan Packet
	cancelSocketCallback context.CancelFunc
	Restart              chan struct{}

	pendingVerdicts  uint64
	verdictCompleted chan struct{}

	// Make stats public
	Stats struct {
		Accept     uint64
		Block      uint64
		Drop       uint64
		AcceptPerm uint64
		BlockPerm  uint64
		DropPerm   uint64
		Errors     uint64
		Total      uint64 // Add this for tracking total packets
	}
}

// New opens a new nfQueue
func New(qid uint16, v6 bool) (*Queue, error) {
	ctx, cancel := context.WithCancel(context.Background())
	q := &Queue{
		id:                   qid,
		afFamily:             2,                        // AF_INET
		packets:              make(chan Packet, 10000), // Increase buffer size
		Restart:              make(chan struct{}, 1),
		verdictCompleted:     make(chan struct{}, 100), // Increase buffer size
		cancelSocketCallback: cancel,
	}

	if v6 {
		q.afFamily = 10 // AF_INET6
	}

	if err := q.open(ctx); err != nil {
		return nil, err
	}

	// Add socket recovery goroutine
	go func() {
	Wait:
		for {
			select {
			case <-ctx.Done():
				return
			case <-q.Restart:
				runtime.Gosched()
			}

			for {
				err := q.open(ctx)
				if err == nil {
					continue Wait
				}
				select {
				case <-ctx.Done():
					return
				case <-time.After(100 * time.Millisecond):
				}
			}
		}
	}()

	return q, nil
}

func (q *Queue) open(ctx context.Context) error {
	cfg := &nfqueue.Config{
		NfQueue:      q.id,
		MaxPacketLen: 1600,
		MaxQueueLen:  0xffff,
		AfFamily:     q.afFamily,
		Copymode:     nfqueue.NfQnlCopyPacket,
		ReadTimeout:  1000 * time.Millisecond,
		WriteTimeout: 1000 * time.Millisecond,
	}

	nfq, err := nfqueue.Open(cfg)
	if err != nil {
		return fmt.Errorf("failed to open nfqueue: %w", err)
	}

	q.nf.Store(nfq)

	ctx, cancel := context.WithCancel(ctx)
	q.cancelSocketCallback = cancel

	// Register callback handler - use handlePacket directly
	err = nfq.RegisterWithErrorFunc(ctx,
		func(a nfqueue.Attribute) int {
			select {
			case <-ctx.Done():
				return 0
			default:
				return q.handlePacket(a)
			}
		},
		func(e error) int {
			select {
			case <-ctx.Done():
				return 0
			default:
				fmt.Printf("nfqueue error: %v\n", e)
				return 1
			}
		},
	)
	if err != nil {
		nfq.Close()
		return fmt.Errorf("failed to register callback: %w", err)
	}

	return nil
}

func (q *Queue) handlePacket(attr nfqueue.Attribute) int {
	if attr.PacketID == nil {
		atomic.AddUint64(&q.Stats.Errors, 1)
		return 0
	}

	atomic.AddUint64(&q.Stats.Total, 1) // Use Total instead of Processed

	pkt := &Packet{
		ID:             *attr.PacketID,
		queue:          q,
		verdictSet:     make(chan struct{}),
		verdictPending: abool.New(),
		Timestamp:      time.Now(),
	}

	if attr.Payload == nil {
		fmt.Printf("Warning: packet #%d has no payload\n", pkt.ID)
		return 0
	}

	// Parse IP header
	payload := *attr.Payload
	if len(payload) < 20 {
		return 0
	}

	// Get IP version from first 4 bits
	version := payload[0] >> 4

	if version == 4 {
		// IPv4
		pkt.Protocol = payload[9]
		pkt.SrcIP = net.IP(payload[12:16])
		pkt.DstIP = net.IP(payload[16:20])

		// TCP/UDP ports start at offset 20 for IPv4
		if len(payload) >= 24 {
			pkt.SrcPort = binary.BigEndian.Uint16(payload[20:22])
			pkt.DstPort = binary.BigEndian.Uint16(payload[22:24])
		}
	} else if version == 6 {
		// IPv6
		pkt.Protocol = payload[6]
		pkt.SrcIP = net.IP(payload[8:24])
		pkt.DstIP = net.IP(payload[24:40])

		// TCP/UDP ports start at offset 40 for IPv6
		if len(payload) >= 44 {
			pkt.SrcPort = binary.BigEndian.Uint16(payload[40:42])
			pkt.DstPort = binary.BigEndian.Uint16(payload[42:44])
		}
	}

	select {
	case q.packets <- *pkt:
		// Successfully queued
	default:
		// Queue is full, accept packet
		if nfq := q.nf.Load().(*nfqueue.Nfqueue); nfq != nil {
			_ = nfq.SetVerdict(pkt.ID, nfqueue.NfDrop)
		}
		atomic.AddUint64(&q.Stats.Errors, 1) // Count as error instead of dropped
	}

	return 0
}

// Destroy closes the nfqueue
func (q *Queue) Destroy() {
	if q.cancelSocketCallback != nil {
		q.cancelSocketCallback()
	}

	if nfq := q.nf.Load().(*nfqueue.Nfqueue); nfq != nil {
		nfq.Close()
	}
}

// PacketChannel returns the packet channel
func (q *Queue) PacketChannel() <-chan Packet {
	return q.packets
}

func (q *Queue) ID() uint16 {
	return q.id
}

func (q *Queue) GetVerdictStats() QueueStats {
	return QueueStats{
		Total:      atomic.LoadUint64(&q.Stats.Total),
		Accept:     atomic.LoadUint64(&q.Stats.Accept),
		Block:      atomic.LoadUint64(&q.Stats.Block),
		Drop:       atomic.LoadUint64(&q.Stats.Drop),
		AcceptPerm: atomic.LoadUint64(&q.Stats.AcceptPerm),
		BlockPerm:  atomic.LoadUint64(&q.Stats.BlockPerm),
		DropPerm:   atomic.LoadUint64(&q.Stats.DropPerm),
		Errors:     atomic.LoadUint64(&q.Stats.Errors),
	}
}
