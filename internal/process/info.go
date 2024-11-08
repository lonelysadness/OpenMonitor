package process

import (
	"fmt"
	"os"
	"os/user"
	"time"

	"github.com/shirou/gopsutil/process"
	"golang.org/x/sync/singleflight"
)

var getProcessGroup singleflight.Group

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

	p, err, _ := getProcessGroup.Do(key, func() (interface{}, error) {
		return loadProcess(pInfo, key, createdAt)
	})
	if err != nil {
		return nil, err
	}

	return p.(*Process), nil
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

	// Minimal container detection
	if _, err := os.Stat(fmt.Sprintf("/proc/%d/root/.dockerenv", proc.Pid)); err == nil {
		proc.IsContainer = true
		proc.ContainerType = "docker"
	}

	return proc, nil
}
