package display

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/lonelysadness/OpenMonitor/pkg/ebpf"
	"github.com/lonelysadness/OpenMonitor/pkg/nfq"
)

type Monitor struct {
	term *Terminal
}

func NewMonitor() *Monitor {
	return &Monitor{
		term: NewTerminal(),
	}
}

func (m *Monitor) Start(ctx context.Context, connEvents chan *ebpf.ConnectionEvent,
	bwUpdates chan *ebpf.BandwidthInfo, inPackets, outPackets <-chan nfq.Packet,
	inQueue, outQueue *nfq.Queue) {

	ticker := time.NewTicker(1 * time.Second)
	monitorTicker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	defer monitorTicker.Stop()

	// Initial clear
	fmt.Print("\033[2J")

	for {
		select {
		case conn := <-connEvents:
			key := fmt.Sprintf("%v:%d -> %v:%d [%d]",
				conn.SrcAddr, conn.SrcPort,
				conn.DstAddr, conn.DstPort,
				conn.Protocol)
			m.term.UpdateConnections(key, time.Now())

		case pkt := <-inPackets:
			go func(p nfq.Packet) {
				if err := p.Accept(); err != nil {
					fmt.Printf("Error setting IN verdict: %v\n", err)
				}
			}(pkt)
			m.term.AddActivity("IN", FormatPacketInfo(pkt, true))

		case pkt := <-outPackets:
			go func(p nfq.Packet) {
				if err := p.Accept(); err != nil {
					fmt.Printf("Error setting OUT verdict: %v\n", err)
				}
			}(pkt)
			m.term.AddActivity("OUT", FormatPacketInfo(pkt, false))

		case bw := <-bwUpdates:
			if bw != nil {
				m.term.UpdateBandwidth(bw.RX, bw.TX)
			}

		case <-ticker.C:
			m.term.CleanOldConnections(30 * time.Second)
			m.term.UpdateQueueStats(inQueue, outQueue)
			m.term.Display()

		case <-monitorTicker.C:
			// Queue health monitoring
			for _, q := range []*nfq.Queue{inQueue, outQueue} {
				stats := q.GetVerdictStats()
				if stats.Errors > 1000 {
					select {
					case q.Restart <- struct{}{}:
						log.Printf("High error rate detected (%d), restarting queue %d", stats.Errors, q.ID())
					default:
					}
				}
			}

		case <-ctx.Done():
			return
		}
	}
}
