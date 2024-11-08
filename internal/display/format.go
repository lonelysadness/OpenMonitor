package display

import (
	"fmt"
	"strings"

	"github.com/lonelysadness/OpenMonitor/internal/netutils"
	"github.com/lonelysadness/OpenMonitor/internal/process"
	"github.com/lonelysadness/OpenMonitor/internal/types"
)

const (
	ColorReset = "\033[0m"
	ColorRed   = "\033[31m"
	ColorGreen = "\033[32m"
	ColorBlue  = "\033[34m"
	ColorWhite = "\033[37m"
)

func PrintHeader() {
	fmt.Println(strings.Repeat("=", 80))
	fmt.Println("Connection Events")
	fmt.Println(strings.Repeat("=", 80))
}

func PrintEvent(event types.Event) {
	srcIP := netutils.ConvertArrayToIP(event.Saddr, event.IpVersion == 6)
	dstIP := netutils.ConvertArrayToIP(event.Daddr, event.IpVersion == 6)
	protocol := netutils.GetProtocolName(event.Protocol)
	direction := netutils.GetDirectionSymbol(event.Direction)

	procName, owner, parentInfo := process.GetProcessDetails(event.Pid)
	color := getColor(event.Direction)

	// Print main connection info
	fmt.Printf("%s[%s:%d] %s:%d -> %s:%d (%s) %s%s\n",
		color, procName, event.Pid, srcIP, event.Sport, dstIP, event.Dport, protocol, direction, ColorReset)

	// Print minimal process details
	if owner != "unknown" || parentInfo != "unknown" {
		fmt.Printf("    └─ %s, Parent: %s\n", owner, parentInfo)
	}
}

func getColor(direction uint8) string {
	switch direction {
	case types.OUTBOUND:
		return ColorGreen
	case types.INBOUND:
		return ColorBlue
	default:
		return ColorWhite
	}
}
