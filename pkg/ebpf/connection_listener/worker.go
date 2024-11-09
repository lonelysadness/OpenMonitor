package connection_listener

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
	"github.com/lonelysadness/OpenMonitor/pkg/ebpf"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -cflags "-O2 -g -Wall -Werror" bpf ../programs/monitor.c

func ConnectionListenerWorker(ctx context.Context, events chan *ebpf.ConnectionEvent) error {
	// Allow the current process to lock memory for eBPF resources
	if err := rlimit.RemoveMemlock(); err != nil {
		return fmt.Errorf("failed to remove memory lock: %w", err)
	}

	// Load pre-compiled programs into the kernel
	objs := bpfObjects{}
	if err := loadBpfObjects(&objs, nil); err != nil {
		return fmt.Errorf("failed to load BPF objects: %w", err)
	}
	defer objs.Close()

	rd, err := ringbuf.NewReader(objs.OmConnectionEvents)
	if err != nil {
		return fmt.Errorf("failed to create ring buffer reader: %w", err)
	}
	defer rd.Close()

	// Read events from ring buffer
	go func() {
		for {
			record, err := rd.Read()
			if err != nil {
				if errors.Is(err, ringbuf.ErrClosed) {
					return
				}
				continue
			}

			var event ebpf.ConnectionEvent
			if err := binary.Read(bytes.NewBuffer(record.RawSample), binary.LittleEndian, &event); err != nil {
				continue
			}

			select {
			case events <- &event:
			case <-ctx.Done():
				return
			}
		}
	}()

	<-ctx.Done()
	return nil
}
