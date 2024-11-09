package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/lonelysadness/OpenMonitor/pkg/display"
	"github.com/lonelysadness/OpenMonitor/pkg/ebpf"
	"github.com/lonelysadness/OpenMonitor/pkg/ebpf/bandwidth"
	"github.com/lonelysadness/OpenMonitor/pkg/ebpf/connection_listener"
	"github.com/lonelysadness/OpenMonitor/pkg/ebpf/exec"
	"github.com/lonelysadness/OpenMonitor/pkg/nfq"
)

func main() {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if os.Geteuid() != 0 {
		log.Fatal("This program must be run as root")
	}

	// Initialize NFQueue and iptables
	if err := nfq.StartNFQueue(); err != nil {
		log.Fatalf("Failed to setup iptables: %v", err)
	}
	defer nfq.StopNFQueue()

	if err := nfq.InitConntrack(); err != nil {
		log.Fatalf("Failed to initialize conntrack: %v", err)
	}
	defer nfq.CloseConntrack()

	// Create packet queues with correct queue numbers
	outQueue, err := nfq.New(17040, false) // OUTPUT queue
	if err != nil {
		log.Fatalf("Failed to create outbound queue: %v", err)
	}
	defer outQueue.Destroy()

	inQueue, err := nfq.New(17041, false) // INPUT queue
	if err != nil {
		log.Fatalf("Failed to create inbound queue: %v", err)
	}
	defer inQueue.Destroy()

	// Start monitors
	bandwidthUpdates := make(chan *ebpf.BandwidthInfo, 100)
	go bandwidth.BandwidthStatsWorker(ctx, 5*time.Second, bandwidthUpdates)

	connEvents := make(chan *ebpf.ConnectionEvent, 100)
	go connection_listener.ConnectionListenerWorker(ctx, connEvents)

	execTracer, err := exec.New()
	if err != nil {
		log.Fatalf("Failed to start exec tracer: %v", err)
	}
	defer execTracer.Close()

	// Monitor connections and packets
	go monitorAll(ctx, connEvents, bandwidthUpdates, inQueue.PacketChannel(), outQueue.PacketChannel())

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	<-sigChan

	log.Println("Shutting down...")
}

func monitorAll(ctx context.Context, connEvents chan *ebpf.ConnectionEvent,
	bwUpdates chan *ebpf.BandwidthInfo, inPackets, outPackets <-chan nfq.Packet) {

	term := display.NewTerminal()
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
			term.UpdateConnections(key, time.Now())

		case pkt := <-inPackets:
			go func(p nfq.Packet) {
				p.Accept()
			}(pkt)
			term.AddActivity("IN", display.FormatPacketInfo(pkt, true))

		case pkt := <-outPackets:
			go func(p nfq.Packet) {
				p.Accept()
			}(pkt)
			term.AddActivity("OUT", display.FormatPacketInfo(pkt, false))

		case bw := <-bwUpdates:
			if bw != nil {
				term.UpdateBandwidth(bw.RX, bw.TX)
			}

		case <-ticker.C:
			term.CleanOldConnections(30 * time.Second)
			term.Display()

		case <-ctx.Done():
			return
		}
	}
}
