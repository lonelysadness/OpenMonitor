package process

import (
	"fmt"
	"sync"
	"time"
)

const (
	UndefinedProcessID = -1
)

type Tag struct {
	Key   string
	Value string
}

type Process struct {
	sync.Mutex

	// Essential fields
	Name     string
	UserID   int
	UserName string
	UserHome string
	Pid      int
	Path     string
	CmdLine  string

	// Process identification
	CreatedAt  int64
	LastSeen   int64
	processKey string

	// Parent and leader process info
	ParentPid       int
	ParentCreatedAt int64
	LeaderPid       int
	leader          *Process

	// Container info (minimal)
	IsContainer   bool
	ContainerType string

	// Resource usage (minimal)
	CPUUsage      float64
	MemoryUsage   uint64
	MemoryPercent float64

	// Environment variables
	Env map[string]string

	// Add fields for tags
	Tags []Tag

	// Add a field for alternative paths
	MatchingPath string
}

func (p *Process) GetKey() string {
	if p.processKey == "" {
		p.processKey = fmt.Sprintf("%d-%d", p.Pid, p.CreatedAt)
	}
	return p.processKey
}

func (p *Process) String() string {
	return fmt.Sprintf("%s:%s:%d", p.UserName, p.Path, p.Pid)
}

func (p *Process) UpdateLastSeen() {
	p.Lock()
	defer p.Unlock()
	p.LastSeen = time.Now().Unix()
}

func (p *Process) SetLeader(leader *Process) {
	p.Lock()
	defer p.Unlock()
	p.leader = leader
}

func (p *Process) GetLeader() *Process {
	p.Lock()
	defer p.Unlock()
	return p.leader
}

// Add method to get tag
func (p *Process) GetTag(tagID string) (Tag, bool) {
	for _, t := range p.Tags {
		if t.Key == tagID {
			return t, true
		}
	}
	return Tag{}, false
}
