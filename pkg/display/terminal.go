package display

import (
	"fmt"
	"strings"
	"time"

	"github.com/lonelysadness/OpenMonitor/pkg/nfq"
)

// ANSI color constants
const (
	colorReset  = "\033[0m"
	colorRed    = "\033[31m"
	colorGreen  = "\033[32m"
	colorYellow = "\033[33m"
	colorBlue   = "\033[34m"
	colorPurple = "\033[35m"
	colorCyan   = "\033[36m"
	colorWhite  = "\033[37m"
)

const (
	maxConnections = 10 // Maximum number of connections to display
	maxActivity    = 5  // Maximum number of activity lines to display
)

type Activity struct {
	Direction string
	Message   string
	Timestamp time.Time
}

type Terminal struct {
	connections map[string]time.Time
	activities  []Activity
	bandwidth   string
}

func NewTerminal() *Terminal {
	return &Terminal{
		connections: make(map[string]time.Time),
		activities:  make([]Activity, 0, maxActivity),
		bandwidth:   "No bandwidth data",
	}
}

func (t *Terminal) UpdateConnections(key string, timestamp time.Time) {
	t.connections[key] = timestamp
}

func (t *Terminal) CleanOldConnections(age time.Duration) {
	now := time.Now()
	for k, v := range t.connections {
		if now.Sub(v) > age {
			delete(t.connections, k)
		}
	}
}

func (t *Terminal) AddActivity(direction string, message string) {
	t.activities = append([]Activity{{
		Direction: direction,
		Message:   message,
		Timestamp: time.Now(),
	}}, t.activities...)
	if len(t.activities) > maxActivity {
		t.activities = t.activities[:maxActivity]
	}
}

func (t *Terminal) UpdateBandwidth(rx, tx uint64) {
	t.bandwidth = fmt.Sprintf("RX: %s  TX: %s",
		formatBytes(rx), formatBytes(tx))
}

func (t *Terminal) Display() {
	clear := "\033[H\033[2J"
	fmt.Print(clear)

	// Print header with current time
	now := time.Now().Format("15:04:05")
	fmt.Printf("=== %sOpenMonitor%s - %s%s%s ===\n\n",
		colorCyan, colorReset, colorYellow, now, colorReset)

	// Print bandwidth in a more detailed format
	if t.bandwidth == "No bandwidth data" {
		fmt.Printf("%sBandwidth Monitor%s\n", colorPurple, colorReset)
		fmt.Printf("├─ %sNo data available%s\n\n", colorYellow, colorReset)
	} else {
		fmt.Printf("%sBandwidth Monitor%s\n", colorPurple, colorReset)
		fmt.Printf("├─ %sDownload:%s %s\n", colorBlue, colorReset, strings.Split(t.bandwidth, "TX:")[0])
		fmt.Printf("└─ %sUpload:%s %s\n\n", colorGreen, colorReset, strings.Split(t.bandwidth, "TX:")[1])
	}

	// Print recent activity as a continuous log
	fmt.Printf("%sNetwork Activity Log%s\n", colorBlue, colorReset)
	if len(t.activities) == 0 {
		fmt.Printf("└─ %sNo recent activity%s\n", colorYellow, colorReset)
	} else {
		for i, act := range t.activities {
			prefix := "├─"
			if i == len(t.activities)-1 {
				prefix = "└─"
			}

			color := colorGreen
			if act.Direction == "IN" {
				color = colorCyan
			}

			age := time.Since(act.Timestamp).Round(time.Second)
			fmt.Printf("%s %s[%s]%s [%s ago] %s\n",
				prefix,
				color, act.Direction, colorReset,
				age, act.Message)
		}
	}

	// Print footer
	fmt.Printf("\n%s=== Press Ctrl+C to exit ===%s\n",
		colorYellow, colorReset)
}

func FormatPacketInfo(pkt nfq.Packet, isInbound bool) string {
	direction := "⇦"
	if !isInbound {
		direction = "⇨"
	}

	proto := "Unknown"
	switch pkt.Protocol {
	case nfq.ProtocolTCP:
		proto = "TCP"
	case nfq.ProtocolUDP:
		proto = "UDP"
	case nfq.ProtocolICMP:
		proto = "ICMPv4"
	case nfq.ProtocolICMP6:
		proto = "ICMPv6"
	case nfq.ProtocolIGMP:
		proto = "IGMP"
	}

	// For ICMP/IGMP packets, don't show ports
	if pkt.IsICMP() || pkt.IsIGMP() {
		return fmt.Sprintf("%s %s %s %s",
			proto,
			pkt.SrcIP,
			direction,
			pkt.DstIP)
	}

	return fmt.Sprintf("%s %s:%d %s %s:%d (%s)",
		proto,
		pkt.SrcIP, pkt.SrcPort,
		direction,
		pkt.DstIP, pkt.DstPort,
		getServiceName(pkt.DstPort))
}

// Helper function to format bytes
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
	return fmt.Sprintf("%.1f %cB", float64(bytes)/float64(div), "KMGTPE"[exp])
}

// Helper function to get common service names
func getServiceName(port uint16) string {
	services := map[uint16]string{
		53: "DNS", 80: "HTTP", 443: "HTTPS",
		22: "SSH", 25: "SMTP", 110: "POP3",
		143: "IMAP", 67: "DHCP", 68: "DHCP",
	}
	if name, ok := services[port]; ok {
		return name
	}
	return fmt.Sprintf("PORT-%d", port)
}
