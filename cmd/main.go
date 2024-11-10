package main

import (
	"context"
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

	// Create packet handlers with proper cleanup
	outQueue, err := nfq.New(17040, false) // OUTPUT queue
	if err != nil {
		log.Fatalf("Failed to create outbound queue: %v", err)
	}
	defer func() {
		outQueue.Destroy()
		time.Sleep(100 * time.Millisecond) // Allow time for cleanup
	}()

	inQueue, err := nfq.New(17041, false) // INPUT queue
	if err != nil {
		log.Fatalf("Failed to create inbound queue: %v", err)
	}
	defer func() {
		inQueue.Destroy()
		time.Sleep(100 * time.Millisecond) // Allow time for cleanup
	}()

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

	// Start the monitor
	monitor := display.NewMonitor()
	go monitor.Start(ctx, connEvents, bandwidthUpdates, inQueue.PacketChannel(), outQueue.PacketChannel())

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	<-sigChan

	log.Println("Shutting down...")
}
