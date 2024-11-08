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

	// Check container tag first
	if containerTag, ok := proc.GetTag("container-type"); ok {
		fmt.Printf("[%s] ", containerTag.Value)
	}

	// Print process info with any additional tags
	fmt.Printf("%s (%d) %s", proc.Name, proc.Pid, getUserString(proc))

	// Print any other relevant tags
	for _, tag := range proc.Tags {
		if tag.Key != "container-type" { // Skip container tag as it's already shown
			fmt.Printf(" [%s: %s]", tag.Key, tag.Value)
		}
	}

	// Connection details
	fmt.Printf("\n    %s%s:%d → %s:%d%s [%s]\n",
		color,
		srcIP, event.Sport,
		dstIP, event.Dport,
		ColorReset,
		netutils.GetProtocolName(event.Protocol),
	)

	// Process details
	if proc.CmdLine != "" {
		fmt.Printf("    %s⤷ %s%s\n", ColorGray, proc.CmdLine, ColorReset)
	}

	// Resource usage if available
	if proc.CPUUsage > 0 || proc.MemoryPercent > 0 {
		fmt.Printf("    %s⤷ CPU: %.1f%%, Mem: %.1f%%%s\n",
			ColorGray,
			proc.CPUUsage,
			proc.MemoryPercent,
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
