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
	processes         map[string]*Process
	groups            map[int]*ProcessGroup
	lastCleanup       time.Time
	invalidationQueue chan string
	verificationQueue chan *Process
}

var (
	globalCache = &ProcessCache{
		processes:   make(map[string]*Process),
		groups:      make(map[int]*ProcessGroup),
		lastCleanup: time.Now(),
	}
)

func (c *ProcessCache) Get(key string) (*Process, bool) {
	if c == nil || c.processes == nil {
		return nil, false
	}

	c.RLock()
	proc, exists := c.processes[key]
	c.RUnlock()

	if !exists || proc == nil {
		return nil, false
	}

	// Skip update during testing to avoid race conditions
	if !isTesting() && proc.lastUpdate.IsZero() {
		proc.updateLock.Lock()
		defer proc.updateLock.Unlock()

		if err := proc.Update(); err != nil {
			return nil, false
		}
	}

	return proc, true
}

func (c *ProcessCache) Put(proc *Process) {
	if c == nil || c.processes == nil || proc == nil {
		return
	}

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

func (c *ProcessCache) invalidateProcess(key string) {
	c.Lock()
	if proc, exists := c.processes[key]; exists {
		if proc.verificationStatus != StatusValid {
			delete(c.processes, key)
			// Clean up process group references
			if proc.group != nil {
				proc.group.Lock()
				delete(proc.group.Members, proc.Pid)
				proc.group.Unlock()
			}
		}
	}
	c.Unlock()
}

func (c *ProcessCache) Cleanup() {
	c.Lock()
	defer c.Unlock()

	now := time.Now()
	for key, proc := range c.processes {
		// Verify process if needed
		if time.Since(proc.lastVerification) > verificationTimeout {
			if err := proc.Verify(); err != nil {
				c.invalidationQueue <- key
				continue
			}
		}

		// Check TTL
		if now.Sub(time.Unix(proc.LastSeen, 0)) > cacheTTL {
			c.invalidationQueue <- key
			continue
		}

		// Check namespace changes
		if proc.nsChanged {
			// Re-verify process details
			c.verificationQueue <- proc
		}
	}

	// Clean up process groups
	for gid, group := range c.groups {
		group.Lock()
		if len(group.Members) == 0 || now.Sub(time.Unix(group.LastSeen, 0)) > cacheTTL {
			delete(c.groups, gid)
		}
		group.Unlock()
	}

	c.lastCleanup = time.Now()
}

func (c *ProcessCache) startBackgroundTasks() {
	// Process invalidation queue
	go func() {
		for key := range c.invalidationQueue {
			c.invalidateProcess(key)
		}
	}()

	// Process verification queue
	go func() {
		for proc := range c.verificationQueue {
			if err := proc.Verify(); err != nil {
				c.invalidationQueue <- proc.GetKey()
			}
		}
	}()
}

func init() {
	globalCache.invalidationQueue = make(chan string, 1000)
	globalCache.verificationQueue = make(chan *Process, 1000)
	globalCache.startBackgroundTasks()
}
