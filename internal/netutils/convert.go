package netutils

import (
	"encoding/binary"
	"fmt"
	"net"

	"github.com/lonelysadness/OpenMonitor/internal/types"
)

func ConvertArrayToIP(input [4]uint32, ipv6 bool) string {
	if !ipv6 {
		return fmt.Sprintf("%d.%d.%d.%d",
			byte(input[0]), byte(input[0]>>8), byte(input[0]>>16), byte(input[0]>>24))
	}
	ip := net.IP(make([]byte, 16))
	for i := 0; i < 4; i++ {
		binary.BigEndian.PutUint32(ip[i*4:], input[i])
	}
	return ip.String()
}

func GetProtocolName(protocol uint8) string {
	switch protocol {
	case types.TCP:
		return "TCP"
	case types.UDP:
		return "UDP"
	case types.UDPLite:
		return "UDPLite"
	default:
		return fmt.Sprintf("%d", protocol)
	}
}

func GetDirectionSymbol(direction uint8) string {
	switch direction {
	case types.OUTBOUND:
		return "↗"
	case types.INBOUND:
		return "↙"
	default:
		return "?"
	}
}
