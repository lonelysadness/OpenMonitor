package process

import (
	"fmt"
	"sync"
	"time"
	// for logging
)

const (
	UndefinedProcessID    = -1
	UnidentifiedProcessID = -2
	SystemProcessID       = -3
	UnsolicitedProcessID  = -4
)

// Process represents a process running on the operating system
type Process struct {
	sync.Mutex

	// Process attributes
	Name     string
	UserID   int
	UserName string
	UserHome string

	Pid       int
	CreatedAt int64

	ParentPid       int
	ParentCreatedAt int64

	Path     string
	ExecName string
	Cwd      string
	CmdLine  string
	FirstArg string
	Env      map[string]string

	// Process identification
	processKey string

	// Additional info
	Tags     []string
	ExecHash string
	Error    string

	FirstSeen int64
	LastSeen  int64

	// New fields
	LeaderPid int
	leader    *Process
	IsSpecial bool // For system/unidentified processes

	// Container/VM info
	IsContainer   bool
	ContainerID   string
	ContainerName string
	ContainerType string            // docker, containerd, podman, lxc, etc
	Namespaces    map[string]string // mnt, pid, net, etc
	CgroupPath    string

	// Process state information
	State         string    // Running, Sleeping, Zombie, etc
	CPUUsage      float64   // CPU usage percentage
	MemoryUsage   uint64    // Memory usage in bytes
	MemoryPercent float64   // Memory usage percentage
	IOCounters    IOStats   // IO statistics
	NumThreads    int32     // Number of threads
	NumFDs        int32     // Number of file descriptors
	StartTime     time.Time // Process start time
	CPUAffinity   []int32   // CPU affinity
	Nice          int32     // Nice value

	// Socket tracking
	Sockets    map[string]int // Map of socket inode to FD
	SocketUIDs map[string]int // Map of socket inode to UID

	// Process group
	group    *ProcessGroup
	isLeader bool

	// Tracking metadata
	isValid    bool
	updateLock sync.Mutex
	lastUpdate time.Time
}

type IOStats struct {
	ReadCount  uint64
	WriteCount uint64
	ReadBytes  uint64
	WriteBytes uint64
}

type ProcessGroup struct {
	sync.RWMutex
	Leader    *Process
	Members   map[int]*Process
	FirstSeen int64
	LastSeen  int64
}

func (p *Process) String() string {
	return fmt.Sprintf("%s:%s:%d", p.UserName, p.Path, p.Pid)
}

func (p *Process) GetKey() string {
	return p.processKey
}

func getProcessKey(pid int, createdAt int64) string {
	return fmt.Sprintf("%d-%d", pid, createdAt)
}

// New methods
func GetSystemProcess() *Process {
	return &Process{
		Pid:       SystemProcessID,
		Name:      "System",
		UserName:  "root",
		IsSpecial: true,
	}
}

func GetUnidentifiedProcess() *Process {
	return &Process{
		Pid:       UnidentifiedProcessID,
		Name:      "Unknown",
		UserName:  "unknown",
		IsSpecial: true,
	}
}

func (p *Process) Leader() *Process {
	p.Lock()
	defer p.Unlock()
	return p.leader
}

func (p *Process) Group() *ProcessGroup {
	p.Lock()
	defer p.Unlock()
	return p.group
}

func (p *Process) IsLeader() bool {
	p.Lock()
	defer p.Unlock()
	return p.isLeader
}
