package process

import (
	"sync"
	"time"
)

const (
	cacheTTL        = 5 * time.Minute
	updateThreshold = 30 * time.Second
	cleanupInterval = 1 * time.Minute
	maxCacheSize    = 10000
)

type ProcessCache struct {
	sync.RWMutex
	processes   map[string]*Process
	groups      map[int]*ProcessGroup
	lastCleanup time.Time
}

var (
	globalCache = &ProcessCache{
		processes:   make(map[string]*Process),
		groups:      make(map[int]*ProcessGroup),
		lastCleanup: time.Now(),
	}
)

func (c *ProcessCache) Get(key string) (*Process, bool) {
	c.RLock()
	proc, exists := c.processes[key]
	c.RUnlock()

	if !exists {
		return nil, false
	}

	// Validate process and update if needed
	if time.Since(proc.lastUpdate) > updateThreshold {
		proc.updateLock.Lock()
		defer proc.updateLock.Unlock()

		if time.Since(proc.lastUpdate) > updateThreshold {
			if err := proc.Update(); err != nil {
				return nil, false
			}
		}
	}

	return proc, true
}

func (c *ProcessCache) Put(proc *Process) {
	c.Lock()
	defer c.Unlock()

	// Check cache size limit
	if len(c.processes) >= maxCacheSize {
		c.evictOldest()
	}

	c.processes[proc.GetKey()] = proc

	// Update process group
	if proc.LeaderPid > 0 {
		group, exists := c.groups[proc.LeaderPid]
		if !exists {
			group = &ProcessGroup{
				Members:   make(map[int]*Process),
				FirstSeen: time.Now().Unix(),
			}
			c.groups[proc.LeaderPid] = group
		}

		group.Lock()
		group.Members[proc.Pid] = proc
		group.LastSeen = time.Now().Unix()
		if proc.Pid == proc.LeaderPid {
			group.Leader = proc
			proc.isLeader = true
		}
		proc.group = group
		group.Unlock()
	}
}

func (c *ProcessCache) evictOldest() {
	var oldestKey string
	var oldestTime int64 = time.Now().Unix()

	for key, proc := range c.processes {
		if proc.LastSeen < oldestTime {
			oldestTime = proc.LastSeen
			oldestKey = key
		}
	}

	if oldestKey != "" {
		delete(c.processes, oldestKey)
	}
}

func (c *ProcessCache) Cleanup() {
	c.Lock()
	defer c.Unlock()

	now := time.Now().Unix()
	deadline := now - int64(cacheTTL.Seconds())

	// Cleanup processes
	for key, proc := range c.processes {
		if proc.LastSeen < deadline || !proc.isValid {
			delete(c.processes, key)
		}
	}

	// Cleanup groups
	for gid, group := range c.groups {
		group.Lock()
		if group.LastSeen < deadline {
			delete(c.groups, gid)
		} else {
			// Cleanup invalid members
			for pid, member := range group.Members {
				if member.LastSeen < deadline || !member.isValid {
					delete(group.Members, pid)
				}
			}
		}
		group.Unlock()
	}

	c.lastCleanup = time.Now()
}
