package bandwidth

import (
	"context"
	"fmt"
	"path/filepath"
	"syscall"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
	"golang.org/x/sys/unix"

	ebpfapi "github.com/lonelysadness/OpenMonitor/pkg/ebpf"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -cflags "-O2 -g -Wall -Werror" bpf ../programs/bandwidth.c

// Add totalBandwidth struct to track cumulative bandwidth
type totalBandwidth struct {
	rx uint64
	tx uint64
}

func BandwidthStatsWorker(ctx context.Context, interval time.Duration, updates chan *ebpfapi.BandwidthInfo) error {
	if err := rlimit.RemoveMemlock(); err != nil {
		return fmt.Errorf("failed to remove memlock: %w", err)
	}

	objs := bpfObjects{}
	if err := loadBpfObjects(&objs, nil); err != nil {
		return fmt.Errorf("failed to load BPF objects: %w", err)
	}
	defer objs.Close()

	// Find and attach to cgroup
	cgroupPath, err := findCgroupPath()
	if err != nil {
		return fmt.Errorf("failed to find cgroup path: %w", err)
	}

	sockOptsLink, err := link.AttachCgroup(link.CgroupOptions{
		Path:    cgroupPath,
		Attach:  ebpf.AttachCGroupSockOps,
		Program: objs.SocketOperations,
	})
	if err != nil {
		return fmt.Errorf("failed to attach sockops: %w", err)
	}

	// Attach UDP tracers
	links := []link.Link{}
	programs := []*ebpf.Program{
		objs.UdpSendmsg,
		objs.UdpRecvmsg,
		objs.Udpv6Sendmsg,
		objs.Udpv6Recvmsg,
	}

	for _, prog := range programs {
		l, err := link.AttachTracing(link.TracingOptions{Program: prog})
		if err != nil {
			return fmt.Errorf("failed to attach UDP tracer: %w", err)
		}
		links = append(links, l)
	}
	defer func() {
		for _, l := range links {
			l.Close()
		}
		sockOptsLink.Close()
	}()

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	// Add total bandwidth tracker
	var total totalBandwidth

	for {
		select {
		case <-ticker.C:
			var key bpfSkKey
			var info bpfSkInfo
			currentTotal := totalBandwidth{}

			// Sum up all bandwidth entries
			iter := objs.OmBandwidthMap.Iterate()
			for iter.Next(&key, &info) {
				currentTotal.rx += info.Rx
				currentTotal.tx += info.Tx
			}

			// Only send updates when bandwidth changes
			if currentTotal.rx != total.rx || currentTotal.tx != total.tx {
				total = currentTotal
				updates <- &ebpfapi.BandwidthInfo{
					RX:       total.rx,
					TX:       total.tx,
					Reported: 0,
				}
			}
		case <-ctx.Done():
			return nil
		}
	}
}

func findCgroupPath() (string, error) {
	cgroupPath := "/sys/fs/cgroup"

	var st syscall.Statfs_t
	err := syscall.Statfs(cgroupPath, &st)
	if err != nil {
		return "", err
	}

	isCgroupV2 := st.Type == unix.CGROUP2_SUPER_MAGIC
	if !isCgroupV2 {
		cgroupPath = filepath.Join(cgroupPath, "unified")
	}

	return cgroupPath, nil
}
