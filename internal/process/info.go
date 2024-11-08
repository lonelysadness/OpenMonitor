package process

import (
	"fmt"
	"os/user"
	"strings"
	"sync"
	"time"

	"github.com/shirou/gopsutil/process"
	"golang.org/x/sync/singleflight"
)

var (
	getProcessGroup   singleflight.Group
	processStorage    = make(map[string]*Process)
	processStorageMux sync.RWMutex
)

// GetProcessFromStorage retrieves a process from storage
func GetProcessFromStorage(key string) (*Process, bool) {
	processStorageMux.RLock()
	defer processStorageMux.RUnlock()
	proc, ok := processStorage[key]
	return proc, ok
}

// SaveProcess stores a process in the storage
func (p *Process) Save() {
	processStorageMux.Lock()
	defer processStorageMux.Unlock()
	processStorage[p.GetKey()] = p
}

func GetProcessDetails(pid uint32) (string, string, string) {
	proc, err := GetOrFindProcess(pid)
	if err != nil {
		return "unknown", "unknown", "unknown"
	}
	return proc.Name, proc.UserName, proc.Path
}

func GetOrFindProcess(pid uint32) (*Process, error) {
	pInfo, err := process.NewProcess(int32(pid))
	if err != nil {
		return nil, err
	}

	createdAt, err := pInfo.CreateTime()
	if err != nil {
		return nil, err
	}

	key := fmt.Sprintf("%d-%d", pid, createdAt)

	// Check storage first
	if proc, ok := GetProcessFromStorage(key); ok {
		proc.UpdateLastSeen()
		return proc, nil
	}

	// Use singleflight for loading
	p, err, _ := getProcessGroup.Do(key, func() (interface{}, error) {
		return loadProcess(pInfo, key, createdAt)
	})
	if err != nil {
		return nil, err
	}

	proc := p.(*Process)
	proc.Save()
	return proc, nil
}

func loadProcess(pInfo *process.Process, key string, createdAt int64) (*Process, error) {
	proc := &Process{
		Pid:        int(pInfo.Pid),
		CreatedAt:  createdAt,
		processKey: key,
		LastSeen:   time.Now().Unix(),
	}

	if name, err := pInfo.Name(); err == nil {
		proc.Name = name
	}

	if exe, err := pInfo.Exe(); err == nil {
		proc.Path = exe
	}

	if uids, err := pInfo.Uids(); err == nil && len(uids) > 0 {
		proc.UserID = int(uids[0])
		if u, err := user.LookupId(fmt.Sprintf("%d", uids[0])); err == nil {
			proc.UserName = u.Username
		}
	}

	if cmdline, err := pInfo.Cmdline(); err == nil {
		proc.CmdLine = cmdline
	}

	// Basic resource usage
	if cpuPercent, err := pInfo.CPUPercent(); err == nil {
		proc.CPUUsage = float64(cpuPercent)
	}

	if memInfo, err := pInfo.MemoryInfo(); err == nil {
		proc.MemoryUsage = memInfo.RSS
	}

	if memPercent, err := pInfo.MemoryPercent(); err == nil {
		proc.MemoryPercent = float64(memPercent)
	}

	// Process parent relationships
	if ppid, err := pInfo.Ppid(); err == nil {
		proc.ParentPid = int(ppid)
		if parentPInfo, err := process.NewProcess(ppid); err == nil {
			if parentCreatedAt, err := parentPInfo.CreateTime(); err == nil {
				proc.ParentCreatedAt = parentCreatedAt

				// Try to get parent process
				if parent, err := GetOrFindProcess(uint32(ppid)); err == nil {
					// Inherit container properties from parent if applicable
					if parent.IsContainer {
						proc.IsContainer = true
						proc.ContainerType = parent.ContainerType
						// Fix: Remove process. prefix since we're in the same package
						proc.Tags = append(proc.Tags, Tag{
							Key:   "container-type",
							Value: parent.ContainerType,
						})
					}

					// Process group leader handling
					if parent.LeaderPid > 0 {
						proc.LeaderPid = parent.LeaderPid
						if leader, err := GetOrFindProcess(uint32(parent.LeaderPid)); err == nil {
							proc.SetLeader(leader)
						}
					}
				}
			}
		}
	}

	// Process group leader detection
	if proc.Pid == proc.ParentPid || proc.ParentPid <= 1 {
		proc.LeaderPid = proc.Pid
		proc.SetLeader(proc)
	}

	// Run all registered tag handlers
	proc.processTags()

	// Current working directory
	if cwd, err := pInfo.Cwd(); err == nil {
		proc.UserHome = cwd
	}

	// Environment variables
	if env, err := pInfo.Environ(); err == nil {
		proc.Env = make(map[string]string)
		for _, entry := range env {
			parts := strings.SplitN(entry, "=", 2)
			if len(parts) == 2 {
				proc.Env[parts[0]] = parts[1]
			}
		}
	}

	return proc, nil
}
