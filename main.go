// filepath: /home/none/OpenMonitor/main.go
package main

import (
	"errors"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/lonelysadness/OpenMonitor/internal/connection"
	"github.com/lonelysadness/OpenMonitor/internal/display"
	"github.com/lonelysadness/OpenMonitor/internal/monitor"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
	_ "github.com/lonelysadness/OpenMonitor/internal/process/handlers" // Register handlers
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -cflags "-O2 -g -Wall -Werror" bpf ebpf/monitor.c

func main() {
	// Allow the current process to lock memory for eBPF resources.
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatalf("failed to remove memlock: %v", err)
	}

	// Load pre-compiled programs and maps into the kernel.
	objs := bpfObjects{}
	if err := loadBpfObjects(&objs, nil); err != nil {
		log.Fatalf("failed to load bpf objects: %v", err)
	}
	defer objs.Close()

	// Attach outbound TCP monitoring
	linkTCPConnect, err := link.AttachTracing(link.TracingOptions{
		Program: objs.bpfPrograms.TcpConnect,
	})
	if err != nil {
		log.Fatalf("failed to attach to tcp_connect: %v", err)
	}
	defer linkTCPConnect.Close()

	// Attach outbound UDP monitoring
	linkUDPV4, err := link.AttachTracing(link.TracingOptions{
		Program: objs.bpfPrograms.UdpV4Connect,
	})
	if err != nil {
		log.Fatalf("failed to attach to udp_v4_connect: %v", err)
	}
	defer linkUDPV4.Close()

	linkUDPV6, err := link.AttachTracing(link.TracingOptions{
		Program: objs.bpfPrograms.UdpV6Connect,
	})
	if err != nil {
		log.Fatalf("failed to attach to udp_v6_connect: %v", err)
	}
	defer linkUDPV6.Close()

	// Attach inbound TCP monitoring via sockops
	cgroupPath := "/sys/fs/cgroup"
	linkSockOps, err := link.AttachCgroup(link.CgroupOptions{
		Path:    cgroupPath,
		Program: objs.bpfPrograms.SocketOperations,
		Attach:  ebpf.AttachCGroupSockOps,
	})
	if err != nil {
		log.Fatalf("failed to attach sockops: %v", err)
	}
	defer linkSockOps.Close()

	// Attach inbound UDP monitoring
	linkUDPRcv, err := link.AttachTracing(link.TracingOptions{
		Program: objs.bpfPrograms.UdpRcv,
	})
	if err != nil {
		log.Fatalf("failed to attach to udp_rcv: %v", err)
	}
	defer linkUDPRcv.Close()

	// Create a new ringbuf reader.
	rd, err := ringbuf.NewReader(objs.bpfMaps.PmConnectionEvents)
	if err != nil {
		log.Fatalf("failed to open ring buffer: %v", err)
	}
	defer rd.Close()

	// Handle termination signals.
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		<-sig
		rd.Close()
	}()

	// Start connection cleanup goroutine
	go connection.CleanupOldConnections()

	fmt.Println("Listening for events...")
	display.PrintHeader()

	for {
		record, err := rd.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				return
			}
			log.Printf("failed to read from ring buffer: %v", err)
			continue
		}

		monitor.HandleEvent(record)
	}
}
