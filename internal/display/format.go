package display

import (
	"fmt"
	"strings"
	"time"

	"github.com/lonelysadness/OpenMonitor/internal/netutils"
	"github.com/lonelysadness/OpenMonitor/internal/process"
	"github.com/lonelysadness/OpenMonitor/internal/types"
)

const (
	ColorReset  = "\033[0m"
	ColorRed    = "\033[31m"
	ColorGreen  = "\033[32m"
	ColorYellow = "\033[33m"
	ColorBlue   = "\033[34m"
	ColorPurple = "\033[35m"
	ColorCyan   = "\033[36m"
	ColorWhite  = "\033[37m"
	ColorBold   = "\033[1m"
)

func formatBytes(bytes uint64) string {
	const unit = 1024
	if bytes < unit {
		return fmt.Sprintf("%d B", bytes)
	}
	div, exp := uint64(unit), 0
	for n := bytes / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %ciB", float64(bytes)/float64(div), "KMGTPE"[exp])
}

func formatDuration(d time.Duration) string {
	if d.Hours() > 24 {
		days := int(d.Hours() / 24)
		hours := int(d.Hours()) % 24
		return fmt.Sprintf("%dd%dh", days, hours)
	}
	return d.Round(time.Second).String()
}

func PrintHeader() {
	fmt.Println(ColorBold + strings.Repeat("=", 100) + ColorReset)
	fmt.Println(ColorBold + "OpenMonitor - Network Connection Monitor" + ColorReset)
	fmt.Println(ColorBold + strings.Repeat("=", 100) + ColorReset)
}

func PrintEvent(event types.Event) {
	proc, err := process.GetOrFindProcess(event.Pid)
	if err != nil {
		return
	}

	// Network connection info
	srcIP := netutils.ConvertArrayToIP(event.Saddr, event.IpVersion == 6)
	dstIP := netutils.ConvertArrayToIP(event.Daddr, event.IpVersion == 6)
	protocol := netutils.GetProtocolName(event.Protocol)
	direction := netutils.GetDirectionSymbol(event.Direction)
	color := getColor(event.Direction)

	// Print connection header
	fmt.Printf("\n%s%s=== New Connection ===%s\n", color, ColorBold, ColorReset)

	// Fix the connection details formatting
	fmt.Printf("%s↳ %s:%d → %s:%d%s\n",
		color,
		srcIP, uint16(event.Sport), // Explicitly cast to uint16
		dstIP, uint16(event.Dport), // Explicitly cast to uint16
		ColorReset)
	fmt.Printf("  Protocol: %s %s\n", protocol, direction)

	// Print process information
	fmt.Printf("\n%s=== Process Information ===%s\n", ColorYellow, ColorReset)
	fmt.Printf("  Name: %s (PID: %d)\n", proc.Name, proc.Pid)
	fmt.Printf("  User: %s (ID: %d)\n", proc.UserName, proc.UserID)
	fmt.Printf("  Path: %s\n", proc.Path)
	if proc.CmdLine != "" {
		fmt.Printf("  Command: %s\n", proc.CmdLine)
	}

	// Container information if available
	if proc.IsContainer {
		fmt.Printf("\n%s=== Container Information ===%s\n", ColorPurple, ColorReset)
		fmt.Printf("  Type: %s\n", proc.ContainerType)
		fmt.Printf("  ID: %s\n", proc.ContainerID)
		if proc.ContainerName != "" {
			fmt.Printf("  Name: %s\n", proc.ContainerName)
		}
	}

	// Process state and resource usage
	fmt.Printf("\n%s=== Process State ===%s\n", ColorCyan, ColorReset)
	fmt.Printf("  State: %s\n", proc.State)
	fmt.Printf("  Running for: %s\n", formatDuration(time.Since(proc.StartTime)))
	fmt.Printf("  CPU Usage: %.1f%%\n", proc.CPUUsage)
	fmt.Printf("  Memory: %s (%.1f%%)\n", formatBytes(proc.MemoryUsage), proc.MemoryPercent)
	fmt.Printf("  Threads: %d, FDs: %d\n", proc.NumThreads, proc.NumFDs)

	// IO Statistics
	if proc.IOCounters.ReadCount > 0 || proc.IOCounters.WriteCount > 0 {
		fmt.Printf("\n%s=== I/O Statistics ===%s\n", ColorBlue, ColorReset)
		fmt.Printf("  Read:  %s (%d operations)\n",
			formatBytes(proc.IOCounters.ReadBytes),
			proc.IOCounters.ReadCount)
		fmt.Printf("  Write: %s (%d operations)\n",
			formatBytes(proc.IOCounters.WriteBytes),
			proc.IOCounters.WriteCount)
	}

	fmt.Println(strings.Repeat("-", 100))
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
