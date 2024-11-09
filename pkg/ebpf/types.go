package ebpf

// ConnectionEvent matches the Event struct in monitor.c
type ConnectionEvent struct {
	SrcAddr   [4]uint32
	DstAddr   [4]uint32
	SrcPort   uint16
	DstPort   uint16
	PID       uint32
	IPVersion uint8
	Protocol  uint8
	Direction uint8
}

// BandwidthInfo matches the sk_info struct in bandwidth.c
type BandwidthInfo struct {
	RX       uint64
	TX       uint64
	Reported uint64
}

// ExecEvent matches the event_t struct in exec.c
type ExecEvent struct {
	Filename [1024]byte
	Argv     [32][1024]byte
	Argc     uint32
	UID      uint32
	GID      uint32
	PID      uint32
	Comm     [1024]byte
}
