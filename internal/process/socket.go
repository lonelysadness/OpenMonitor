package process

import (
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Socket cache to reduce filesystem reads
var (
	socketCache     = make(map[string]*socketInfo)
	socketCacheLock sync.RWMutex
	socketTTL       = 5 * time.Second
)

type socketInfo struct {
	pid       int
	fd        int
	timestamp time.Time
}

func getAllProcessesByUID(uid int) ([]*Process, error) {
	var processes []*Process

	entries, err := ioutil.ReadDir("/proc")
	if err != nil {
		return nil, err
	}

	for _, entry := range entries {
		// Skip non-numeric entries
		pid, err := strconv.Atoi(entry.Name())
		if err != nil {
			continue
		}

		proc, err := GetOrFindProcess(uint32(pid))
		if err != nil {
			continue
		}

		if proc.UserID == uid {
			processes = append(processes, proc)
		}
	}

	return processes, nil
}

func FindProcessBySocket(uid int, inode string) (*Process, error) {
	// Check socket cache first
	socketCacheLock.RLock()
	if info, exists := socketCache[inode]; exists && time.Since(info.timestamp) < socketTTL {
		socketCacheLock.RUnlock()
		if proc, err := GetOrFindProcess(uint32(info.pid)); err == nil {
			return proc, nil
		}
	}
	socketCacheLock.RUnlock()

	// Get processes by UID in parallel
	processes, err := getAllProcessesByUID(uid)
	if err != nil {
		return nil, err
	}

	// Use worker pool for parallel socket scanning
	const numWorkers = 4
	jobs := make(chan *Process, len(processes))
	results := make(chan *Process, 1)
	wg := sync.WaitGroup{}

	// Start workers
	for i := 0; i < numWorkers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			socketScanner(jobs, results, inode)
		}()
	}

	// Send jobs
	go func() {
		for _, proc := range processes {
			jobs <- proc
		}
		close(jobs)
	}()

	// Wait for completion or result
	go func() {
		wg.Wait()
		close(results)
	}()

	// Get first result
	if proc, ok := <-results; ok {
		return proc, nil
	}

	return nil, fmt.Errorf("no process found for socket %s", inode)
}

func socketScanner(jobs <-chan *Process, results chan<- *Process, inode string) {
	socketName := fmt.Sprintf("socket:[%s]", inode)
	for proc := range jobs {
		if proc.hasSocket(socketName) {
			results <- proc
			return
		}
	}
}

func (p *Process) hasSocket(socketName string) bool {
	fdPath := fmt.Sprintf("/proc/%d/fd", p.Pid)
	entries, err := os.ReadDir(fdPath)
	if err != nil {
		return false
	}

	// Using filepath.Join for better path handling
	for _, entry := range entries {
		fdPath := filepath.Join(fdPath, entry.Name())
		if link, err := os.Readlink(fdPath); err == nil {
			if link == socketName {
				fd, _ := strconv.Atoi(entry.Name())

				// Update socket cache
				socketCacheLock.Lock()
				socketCache[strings.Trim(socketName[8:], "[]")] = &socketInfo{
					pid:       p.Pid,
					fd:        fd,
					timestamp: time.Now(),
				}
				socketCacheLock.Unlock()

				// Update process socket maps
				p.Lock()
				p.Sockets[socketName] = fd
				p.SocketUIDs[socketName] = p.UserID
				p.Unlock()

				return true
			}
		}
	}

	return false
}

func cleanupSocketCache() {
	socketCacheLock.Lock()
	defer socketCacheLock.Unlock()

	now := time.Now()
	for inode, info := range socketCache {
		if now.Sub(info.timestamp) > socketTTL {
			delete(socketCache, inode)
		}
	}
}

func init() {
	// Start socket cache cleanup
	go func() {
		ticker := time.NewTicker(socketTTL)
		defer ticker.Stop()

		for range ticker.C {
			cleanupSocketCache()
		}
	}()
}
