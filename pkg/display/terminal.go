package display

import (
	"fmt"
	"strings"
	"time"

	"github.com/lonelysadness/OpenMonitor/pkg/netutils"
	"github.com/lonelysadness/OpenMonitor/pkg/nfq"
)

// ANSI color and style constants
const (
	colorReset   = "\033[0m"
	colorRed     = "\033[31m"
	colorGreen   = "\033[32m"
	colorBlue    = "\033[34m"
	colorCyan    = "\033[36m"
	colorGray    = "\033[90m"
	colorYellow  = "\033[33m"
	colorMagenta = "\033[35m"
	bold         = "\033[1m"
	dim          = "\033[2m"
)

// Box drawing characters
const (
	topLeft     = "┌"
	topRight    = "┐"
	bottomLeft  = "└"
	bottomRight = "┘"
	horizontal  = "─"
	vertical    = "│"
)

type Activity struct {
	Direction string
	Message   string
	Timestamp time.Time
}

type Terminal struct {
	connections map[string]time.Time // Add this field back
	activities  []Activity
	bandwidth   string
	queueStats  string
}

func NewTerminal() *Terminal {
	return &Terminal{
		connections: make(map[string]time.Time), // Initialize connections
		activities:  make([]Activity, 0, 5),
		bandwidth:   "No data",
	}
}

// Add these two missing methods
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
	if len(t.activities) > 5 {
		t.activities = t.activities[:5]
	}
}

func (t *Terminal) UpdateBandwidth(rx, tx uint64) {
	t.bandwidth = fmt.Sprintf("RX: %s  TX: %s",
		formatBytes(rx), formatBytes(tx))
}

type QueueStats struct {
	Total      uint64
	Accept     uint64
	Block      uint64
	Drop       uint64
	AcceptPerm uint64
	BlockPerm  uint64
	DropPerm   uint64
	Errors     uint64
}

func (t *Terminal) UpdateQueueStats(inQueue, outQueue *nfq.Queue) {
	inStats := inQueue.GetVerdictStats()
	outStats := outQueue.GetVerdictStats()

	t.queueStats = fmt.Sprintf(
		"IN Queue (#%d):\n"+
			"  Total: %d packets\n"+
			"  Accept: %d (Permanent: %d)\n"+
			"  Block: %d (Permanent: %d)\n"+
			"  Drop: %d (Permanent: %d)\n"+
			"  Errors: %d\n\n"+
			"OUT Queue (#%d):\n"+
			"  Total: %d packets\n"+
			"  Accept: %d (Permanent: %d)\n"+
			"  Block: %d (Permanent: %d)\n"+
			"  Drop: %d (Permanent: %d)\n"+
			"  Errors: %d",
		inQueue.ID(), inStats.Total,
		inStats.Accept, inStats.AcceptPerm,
		inStats.Block, inStats.BlockPerm,
		inStats.Drop, inStats.DropPerm,
		inStats.Errors,
		outQueue.ID(), outStats.Total,
		outStats.Accept, outStats.AcceptPerm,
		outStats.Block, outStats.BlockPerm,
		outStats.Drop, outStats.DropPerm,
		outStats.Errors,
	)
}

func (t *Terminal) Display() {
	// Clear screen
	fmt.Print("\033[H\033[2J")

	width := 80 // Assumed terminal width

	// Draw title box
	title := " Network Monitor "
	padding := (width - len(title)) / 2
	fmt.Printf("\n%s%s%s%s%s%s\n",
		colorCyan,
		topLeft+strings.Repeat(horizontal, padding-1),
		bold+title+colorReset+colorCyan,
		strings.Repeat(horizontal, padding-1),
		topRight,
		colorReset)

	// Bandwidth section
	fmt.Printf("\n%s%s Bandwidth Monitor %s\n", bold, colorYellow, colorReset)
	fmt.Printf("   %s%s%s\n\n", colorCyan, t.bandwidth, colorReset)

	// Add queue stats section after bandwidth
	fmt.Printf("\n%s%s Queue Statistics %s\n", bold, colorYellow, colorReset)
	fmt.Printf("%s%s%s\n\n", colorCyan, t.queueStats, colorReset)

	// Activity section
	fmt.Printf("%s%s Recent Activity %s\n", bold, colorYellow, colorReset)
	fmt.Printf("%s%s%s\n", colorCyan, strings.Repeat(horizontal, width-2), colorReset)

	for _, act := range t.activities {
		timestamp := act.Timestamp.Format("15:04:05")
		color := colorGreen
		if act.Direction == "IN" {
			color = colorBlue
		}

		fmt.Printf(" %s%s%s %s%s%s %s%s%s\n",
			colorGray, timestamp, colorReset,
			bold, act.Direction, colorReset,
			color, act.Message, colorReset)
	}

	// Footer
	fmt.Printf("\n%s%s%s\n",
		dim,
		"Press Ctrl+C to exit",
		colorReset)
}

func FormatPacketInfo(pkt nfq.Packet, isInbound bool) string {
	directionArrow := "↙" // inbound arrow
	if !isInbound {
		directionArrow = "↗" // outbound arrow
	}

	srcScope := netutils.GetIPScope(pkt.SrcIP)
	dstScope := netutils.GetIPScope(pkt.DstIP)

	return fmt.Sprintf("%s(%s):%d %s(%s):%d %s",
		pkt.SrcIP, srcScope, pkt.SrcPort,
		pkt.DstIP, dstScope, pkt.DstPort,
		directionArrow)
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
