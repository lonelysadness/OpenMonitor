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
	ColorGray  = "\033[90m"
	ColorBold  = "\033[1m"
)

func PrintHeader() {
	fmt.Printf("%s%s OpenMonitor %s\n", ColorBold, strings.Repeat("─", 30), strings.Repeat("─", 30))
}

func PrintEvent(event types.Event) {
	proc, err := process.GetOrFindProcess(event.Pid)
	if err != nil {
		return
	}

	// Basic connection info
	srcIP := netutils.ConvertArrayToIP(event.Saddr, event.IpVersion == 6)
	dstIP := netutils.ConvertArrayToIP(event.Daddr, event.IpVersion == 6)
	direction := event.Direction == types.OUTBOUND
	color := ColorGreen
	if !direction {
		color = ColorBlue
	}

	// Print one-line summary
	fmt.Printf("\n%s%s%s ", color, GetDirectionArrow(direction), ColorReset)
	if proc.IsContainer {
		fmt.Printf("[%s] ", proc.ContainerType)
	}
	fmt.Printf("%s (%d) %s", proc.Name, proc.Pid, getUserString(proc))

	// Connection details
	fmt.Printf("\n    %s%s:%d → %s:%d%s [%s]\n",
		color,
		srcIP, event.Sport,
		dstIP, event.Dport,
		ColorReset,
		netutils.GetProtocolName(event.Protocol),
	)

	// Process details (limited)
	fmt.Printf("    %s⤷ %s%s\n", ColorGray, proc.CmdLine, ColorReset)

	// Print resource usage if significant
	if proc.CPUUsage > 1.0 || proc.MemoryPercent > 1.0 {
		fmt.Printf("    %s⤷ CPU: %.1f%%, Mem: %.1f%% (%s)%s\n",
			ColorGray,
			proc.CPUUsage,
			proc.MemoryPercent,
			formatBytes(proc.MemoryUsage),
			ColorReset,
		)
	}
}

func GetDirectionArrow(outbound bool) string {
	if outbound {
		return "▶"
	}
	return "◀"
}

func getUserString(p *process.Process) string {
	if p.UserID == 0 {
		return ColorRed + "root" + ColorReset
	}
	return p.UserName
}

func formatBytes(bytes uint64) string {
	const unit = 1024
	if bytes < unit {
		return fmt.Sprintf("%dB", bytes)
	}
	div, exp := uint64(unit), 0
	for n := bytes / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f%cB", float64(bytes)/float64(div), "KMGTPE"[exp])
}
