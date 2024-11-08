package types

// Network constants
const (
	AF_INET  = 2
	AF_INET6 = 10
	TCP      = 6
	UDP      = 17
	UDPLite  = 136
	OUTBOUND = 0
	INBOUND  = 1
)

// Event represents a network connection event
type Event struct {
	Saddr     [4]uint32
	Daddr     [4]uint32
	Sport     uint16
	Dport     uint16
	Pid       uint32
	IpVersion uint8
	Protocol  uint8
	Direction uint8
}
