package process

import (
	"fmt"
	"sync"
	"time"
)

const (
	UndefinedProcessID = -1
)

type Process struct {
	sync.Mutex

	// Essential fields
	Name     string
	UserID   int
	UserName string
	Pid      int
	Path     string
	CmdLine  string

	// Process identification
	CreatedAt  int64
	LastSeen   int64
	processKey string

	// Container info (minimal)
	IsContainer   bool
	ContainerType string

	// Resource usage (minimal)
	CPUUsage      float64
	MemoryUsage   uint64
	MemoryPercent float64
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
