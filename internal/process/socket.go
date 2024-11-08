package process

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"time"

	"golang.org/x/sync/singleflight"
)

var (
	pidsByUserCache     map[int][]int
	pidsByUserCacheMux  sync.RWMutex
	pidCacheUpdateTime  time.Time
	pidCacheUpdateLimit = time.Second * 1
	findProcessGroup    singleflight.Group
)

// Add this function to maintain a PID cache
func updatePidCache() {
	pidsByUserCacheMux.Lock()
	defer pidsByUserCacheMux.Unlock()

	// Only update once per second
	if time.Since(pidCacheUpdateTime) < pidCacheUpdateLimit {
		return
	}

	newCache := make(map[int][]int)
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return
	}

	for _, entry := range entries {
		pid, err := strconv.Atoi(entry.Name())
		if err != nil {
			continue
		}

		proc, err := GetOrFindProcess(uint32(pid))
		if err != nil {
			continue
		}

		newCache[proc.UserID] = append(newCache[proc.UserID], pid)
	}

	pidsByUserCache = newCache
	pidCacheUpdateTime = time.Now()
}

// FindProcessBySocket returns process info for a socket with improved caching
func FindProcessBySocket(uid, inode int) (*Process, error) {
	socketName := fmt.Sprintf("socket:[%d]", inode)

	// Use singleflight to prevent duplicate searches
	proc, err, _ := findProcessGroup.Do(socketName, func() (interface{}, error) {
		return findProcessBySocketInternal(uid, socketName)
	})

	if err != nil {
		return nil, err
	}

	return proc.(*Process), nil
}

func findProcessBySocketInternal(uid int, socketName string) (*Process, error) {
	// Update cache with backoff
	if time.Since(pidCacheUpdateTime) >= pidCacheUpdateLimit {
		updatePidCache()
	}

	// Get PIDs for user from cache
	pidsByUserCacheMux.RLock()
	pids := pidsByUserCache[uid]
	pidsByUserCacheMux.RUnlock()

	// Search in reverse order (newer PIDs first)
	for i := len(pids) - 1; i >= 0; i-- {
		pid := pids[i]
		if hasSocket(pid, socketName) {
			return GetOrFindProcess(uint32(pid))
		}
	}

	return nil, fmt.Errorf("no process found for socket %s", socketName)
}

func hasSocket(pid int, socketName string) bool {
	fdPath := fmt.Sprintf("/proc/%d/fd", pid)
	entries, err := os.ReadDir(fdPath)
	if err != nil {
		return false
	}

	for _, entry := range entries {
		if link, err := os.Readlink(filepath.Join(fdPath, entry.Name())); err == nil && link == socketName {
			return true
		}
	}
	return false
}
