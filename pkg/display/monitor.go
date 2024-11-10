
package display

import (
	"context"
	"fmt"
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
	bwUpdates chan *ebpf.BandwidthInfo, inPackets, outPackets <-chan nfq.Packet) {
	
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

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
				p.Accept()
			}(pkt)
			m.term.AddActivity("IN", FormatPacketInfo(pkt, true))

		case pkt := <-outPackets:
			go func(p nfq.Packet) {
				p.Accept()
			}(pkt)
			m.term.AddActivity("OUT", FormatPacketInfo(pkt, false))

		case bw := <-bwUpdates:
			if bw != nil {
				m.term.UpdateBandwidth(bw.RX, bw.TX)
			}

		case <-ticker.C:
			m.term.CleanOldConnections(30 * time.Second)
			m.term.Display()

		case <-ctx.Done():
			return
		}
	}
}