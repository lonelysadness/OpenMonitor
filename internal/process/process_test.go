package process

import (
	"fmt"
	"net"
	"os"
	"testing"
	"time"
)

func TestProcessBasics(t *testing.T) {
	// Test getting current process
	currentPID := os.Getpid()
	proc, err := GetOrFindProcess(uint32(currentPID))
	if err != nil {
		t.Fatalf("Failed to get current process: %v", err)
	}

	// Verify basic process information
	if proc.Pid != currentPID {
		t.Errorf("Expected PID %d, got %d", currentPID, proc.Pid)
	}

	if proc.Name == "" {
		t.Error("Process name is empty")
	}

	if proc.Path == "" {
		t.Error("Process path is empty")
	}
}

func TestProcessCache(t *testing.T) {
	// Test cache operations
	pid := os.Getpid()
	proc, err := GetOrFindProcess(uint32(pid))
	if err != nil {
		t.Fatalf("Failed to get process: %v", err)
	}

	// Test cache hit
	cached, exists := globalCache.Get(proc.GetKey())
	if !exists {
		t.Error("Process not found in cache")
	}
	if cached.Pid != pid {
		t.Errorf("Cache returned wrong process: expected PID %d, got %d", pid, cached.Pid)
	}

	// Test cache cleanup
	proc.LastSeen = time.Now().Add(-10 * time.Minute).Unix()
	globalCache.Cleanup()

	_, exists = globalCache.Get(proc.GetKey())
	if exists {
		t.Error("Process should have been cleaned up")
	}
}

func TestContainerDetection(t *testing.T) {
	// This test requires running in a container
	isContainer, info := detectContainer(os.Getpid())
	t.Logf("Container detection results: isContainer=%v, info=%v", isContainer, info)
}

func TestProcessGroup(t *testing.T) {
	pid := os.Getpid()
	proc, err := GetOrFindProcess(uint32(pid))
	if err != nil {
		t.Fatalf("Failed to get process: %v", err)
	}

	if proc.LeaderPid <= 0 {
		t.Error("Process group leader PID not set")
	}

	group := proc.Group()
	if group == nil {
		t.Error("Process group is nil")
	}

	if group != nil && len(group.Members) == 0 {
		t.Error("Process group has no members")
	}
}

func TestSocketTracking(t *testing.T) {
	// Create a test server
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Failed to create test server: %v", err)
	}
	defer listener.Close()

	// Create a client connection to ensure socket exists
	conn, err := net.Dial("tcp", listener.Addr().String())
	if err != nil {
		t.Fatalf("Failed to create test connection: %v", err)
	}
	defer conn.Close()

	// Give some time for the socket to be established
	time.Sleep(100 * time.Millisecond)

	// Get process and verify socket tracking
	proc, err := GetOrFindProcess(uint32(os.Getpid()))
	if err != nil {
		t.Fatalf("Failed to get process: %v", err)
	}

	// Force socket information update
	if err := proc.updateSocketInformation(); err != nil {
		t.Fatalf("Failed to update socket information: %v", err)
	}

	if len(proc.Sockets) == 0 {
		t.Errorf("No sockets tracked for process (error: %s)", proc.Error)
		// Print additional debug information
		t.Logf("Process Info: PID=%d, Name=%s", proc.Pid, proc.Name)
		t.Logf("Socket Count: %d", len(proc.Sockets))
		t.Logf("Process Error: %s", proc.Error)
	}
}

// Add helper test function for socket tracking
func TestSocketInformation(t *testing.T) {
	pid := os.Getpid()
	fdPath := fmt.Sprintf("/proc/%d/fd", pid)

	// List file descriptors
	entries, err := os.ReadDir(fdPath)
	if err != nil {
		t.Skipf("Cannot access fd directory: %v", err)
		return
	}

	t.Logf("Found %d file descriptors", len(entries))

	for _, entry := range entries {
		link, err := os.Readlink(fmt.Sprintf("%s/%s", fdPath, entry.Name()))
		if err != nil {
			t.Logf("Cannot read link for fd %s: %v", entry.Name(), err)
			continue
		}
		t.Logf("FD %s -> %s", entry.Name(), link)
	}
}
