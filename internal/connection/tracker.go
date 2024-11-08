package connection

import (
	"sync"
	"time"
)

type ConnKey struct {
	Saddr     [4]uint32
	Daddr     [4]uint32
	Sport     uint16
	Dport     uint16
	Protocol  uint8
	Direction uint8
}

var (
	recentConns     = make(map[ConnKey]time.Time)
	connMutex       sync.Mutex
	cleanupInterval = 10 * time.Second
)

func IsRecentConnection(key ConnKey) bool {
	connMutex.Lock()
	defer connMutex.Unlock()

	if lastSeen, exists := recentConns[key]; exists {
		if time.Since(lastSeen) < 5*time.Second {
			return true
		}
		delete(recentConns, key)
	}
	recentConns[key] = time.Now()
	return false
}

func CleanupOldConnections() {
	for {
		time.Sleep(cleanupInterval)
		connMutex.Lock()
		now := time.Now()
		for key, lastSeen := range recentConns {
			if now.Sub(lastSeen) > 5*time.Second {
				delete(recentConns, key)
			}
		}
		connMutex.Unlock()
	}
}
