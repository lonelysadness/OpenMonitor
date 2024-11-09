package exec

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
	"github.com/lonelysadness/OpenMonitor/pkg/ebpf"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -cflags "-O2 -g -Wall -Werror" bpfexec ../programs/exec.c

type Tracer struct {
	objs     bpfexecObjects
	link     link.Link
	reader   *ringbuf.Reader
	events   chan *ebpf.ExecEvent
	stopChan chan struct{}
}

func New() (*Tracer, error) {
	if err := rlimit.RemoveMemlock(); err != nil {
		return nil, fmt.Errorf("failed to remove memory lock: %w", err)
	}

	t := &Tracer{
		events:   make(chan *ebpf.ExecEvent),
		stopChan: make(chan struct{}),
	}

	if err := loadBpfexecObjects(&t.objs, nil); err != nil {
		return nil, fmt.Errorf("failed to load BPF objects: %w", err)
	}

	tp, err := link.Tracepoint("syscalls", "sys_enter_execve", t.objs.EnterExecve, nil)
	if err != nil {
		t.Close()
		return nil, fmt.Errorf("failed to create tracepoint: %w", err)
	}
	t.link = tp

	reader, err := ringbuf.NewReader(t.objs.OmExecMap)
	if err != nil {
		t.Close()
		return nil, fmt.Errorf("failed to create ring buffer reader: %w", err)
	}
	t.reader = reader

	go t.readEvents()
	return t, nil
}

func (t *Tracer) readEvents() {
	for {
		record, err := t.reader.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				return
			}
			continue
		}

		var event ebpf.ExecEvent
		if err := binary.Read(bytes.NewBuffer(record.RawSample), binary.LittleEndian, &event); err != nil {
			continue
		}

		select {
		case t.events <- &event:
		case <-t.stopChan:
			return
		}
	}
}

func (t *Tracer) Close() error {
	close(t.stopChan)
	if t.reader != nil {
		t.reader.Close()
	}
	if t.link != nil {
		t.link.Close()
	}
	return t.objs.Close()
}
