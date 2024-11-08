package monitor

import (
	"bytes"
	"encoding/binary"
	"log"

	"github.com/cilium/ebpf/ringbuf"
	"github.com/lonelysadness/OpenMonitor/internal/connection"
	"github.com/lonelysadness/OpenMonitor/internal/display"
	"github.com/lonelysadness/OpenMonitor/internal/types"
)

func HandleEvent(record ringbuf.Record) {
	var event types.Event
	if err := binary.Read(bytes.NewBuffer(record.RawSample), binary.LittleEndian, &event); err != nil {
		log.Printf("failed to parse ringbuf event: %v", err)
		return
	}

	key := connection.ConnKey{
		Saddr:     event.Saddr,
		Daddr:     event.Daddr,
		Sport:     event.Sport,
		Dport:     event.Dport,
		Protocol:  event.Protocol,
		Direction: event.Direction,
	}

	if connection.IsRecentConnection(key) {
		return
	}

	display.PrintEvent(event)
}
