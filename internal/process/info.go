/*
Process Information Collection System
===================================

This system handles process discovery, monitoring, and caching in OpenMonitor. Here's how it works:

1. Process Discovery Flow:
   - When a network event occurs, we receive a PID
   - GetProcessDetails() or GetOrFindProcess() is called with this PID
   - System checks the process cache first using a unique process key (PID + creation time)
   - If not in cache, loadProcess() collects comprehensive information about the process

2. Process Finding Methods:
   a) Direct Process Access (/proc/<pid>/...):
      - /proc/<pid>/stat     -> Process status, PPID, process group
      - /proc/<pid>/status   -> Process name, state, UIDs
      - /proc/<pid>/cmdline  -> Full command line
      - /proc/<pid>/environ  -> Environment variables
      - /proc/<pid>/exe      -> Executable path (via readlink)
      - /proc/<pid>/cwd      -> Working directory
      - /proc/<pid>/fd/      -> Open file descriptors
      - /proc/<pid>/cgroup   -> Container information

   b) Container Detection:
      - Check /.dockerenv in process root
      - Inspect cgroup information
      - Check namespaces in /proc/<pid>/ns/
      - Parse environment for container variables

   c) Socket to Process Mapping:
      - For network connections: /proc/<pid>/fd/* for socket inodes
      - Match socket inodes with network connections
      - Track process group leader for better identification

3. Process Information Sources:
   Primary: gopsutil library which reads from:
   - /proc filesystem on Linux
   - GetProcessTimes() on Windows
   - proc_pidinfo() on MacOS

   Secondary: Direct /proc filesystem access for:
   - Container detection
   - Namespace information
   - Additional metadata

4. Process Identification Strategy:
   1. Try cache lookup first (PID + creation time)
   2. If not found, create new process entry:
      - Get basic info via gopsutil
      - Collect additional info from /proc
      - Check for container/VM context
      - Calculate file hashes
      - Get resource usage stats
   3. Validate process information:
      - Ensure process still exists
      - Verify creation time matches
      - Update process information if needed
   4. Cache the result for future lookups

5. Special Process Handling:
   - System processes (PID < 1)
   - Kernel threads
   - Containerized processes
   - Zombie processes
   - Unidentified processes

6. Data Freshness:
   - Cache timeout: 5 minutes
   - Last seen timestamp updates
   - Periodic cache cleanup
   - Resource stats updated on each lookup
*/

package process

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/shirou/gopsutil/process"
	"golang.org/x/sync/singleflight"
)

var (
	getProcessGroup singleflight.Group
)

func GetProcessDetails(pid uint32) (string, string, string) {
	proc, err := GetOrFindProcess(pid)
	if err != nil {
		return "unknown", "unknown", "unknown"
	}
	return proc.Name, proc.UserName, fmt.Sprintf("%s(%d)", proc.Path, proc.ParentPid)
}

// Modify GetOrFindProcess
func GetOrFindProcess(pid uint32) (*Process, error) {
	// Get process info for key generation
	pInfo, err := process.NewProcess(int32(pid))
	if err != nil {
		return nil, err
	}

	createdAt, err := pInfo.CreateTime()
	if err != nil {
		return nil, err
	}

	key := getProcessKey(int(pid), createdAt)

	// Use singleflight for concurrent loading
	p, err, _ := getProcessGroup.Do(key, func() (interface{}, error) {
		return loadProcess(pInfo, key, createdAt)
	})
	if err != nil {
		return nil, err
	}

	return p.(*Process), nil
}

// Modify loadProcess to include socket information
func loadProcess(pInfo *process.Process, key string, createdAt int64) (*Process, error) {
	proc := &Process{
		Pid:        int(pInfo.Pid),
		CreatedAt:  createdAt,
		processKey: key,
		FirstSeen:  time.Now().Unix(),
		LastSeen:   time.Now().Unix(),
		Env:        make(map[string]string),
	}

	// Basic info
	if name, err := pInfo.Name(); err == nil {
		proc.Name = name
	}

	if exe, err := pInfo.Exe(); err == nil {
		proc.Path = exe
		proc.ExecName = filepath.Base(exe)
		// Calculate executable hash
		if hash, err := calculateFileHash(exe); err == nil {
			proc.ExecHash = hash
		}
	}

	// User info
	if uids, err := pInfo.Uids(); err == nil && len(uids) > 0 {
		proc.UserID = int(uids[0])
		if u, err := user.LookupId(fmt.Sprintf("%d", uids[0])); err == nil {
			proc.UserName = u.Username
			proc.UserHome = u.HomeDir
		}
	}

	// Parent process
	if ppid, err := pInfo.Ppid(); err == nil {
		proc.ParentPid = int(ppid)
		if parent, err := process.NewProcess(ppid); err == nil {
			if parentCreatedAt, err := parent.CreateTime(); err == nil {
				proc.ParentCreatedAt = parentCreatedAt
			}
		}
	}

	// Command line and environment
	if cmdline, err := pInfo.Cmdline(); err == nil {
		proc.CmdLine = cmdline
		args := strings.Fields(cmdline)
		if len(args) > 0 {
			proc.FirstArg = args[0]
		}
	}

	if environ, err := pInfo.Environ(); err == nil {
		for _, env := range environ {
			parts := strings.SplitN(env, "=", 2)
			if len(parts) == 2 {
				proc.Env[parts[0]] = parts[1]
			}
		}
	}

	// Working directory
	if cwd, err := pInfo.Cwd(); err == nil {
		proc.Cwd = cwd
	}

	// Add container detection
	isContainer, containerInfo := detectContainer(proc.Pid)
	proc.IsContainer = isContainer
	if isContainer {
		proc.ContainerType = containerInfo["type"]
		proc.ContainerID = containerInfo["id"]
		proc.Namespaces = parseNamespaces(containerInfo["namespaces"])
	}

	// Add process state information
	if status, err := pInfo.Status(); err == nil && len(status) > 0 {
		proc.State = string(status[0]) // Convert byte to string
	}

	if times, err := pInfo.Times(); err == nil {
		proc.CPUUsage = times.User + times.System
	}

	if mem, err := pInfo.MemoryInfo(); err == nil {
		proc.MemoryUsage = mem.RSS
	}

	if memPercent, err := pInfo.MemoryPercent(); err == nil {
		proc.MemoryPercent = float64(memPercent) // Convert float32 to float64
	}

	if ioCounters, err := pInfo.IOCounters(); err == nil {
		proc.IOCounters = IOStats{
			ReadCount:  ioCounters.ReadCount,
			WriteCount: ioCounters.WriteCount,
			ReadBytes:  ioCounters.ReadBytes,
			WriteBytes: ioCounters.WriteBytes,
		}
	}

	if numThreads, err := pInfo.NumThreads(); err == nil {
		proc.NumThreads = numThreads
	}

	if numFDs, err := pInfo.NumFDs(); err == nil {
		proc.NumFDs = numFDs
	}

	if cpuAffinity, err := pInfo.CPUAffinity(); err == nil {
		proc.CPUAffinity = cpuAffinity
	}

	if nice, err := pInfo.Nice(); err == nil {
		proc.Nice = nice
	}

	proc.StartTime = time.Unix(0, createdAt*int64(time.Millisecond))

	// Get cgroup information
	if cgroupPath, err := os.Readlink(fmt.Sprintf("/proc/%d/cgroup", proc.Pid)); err == nil {
		proc.CgroupPath = cgroupPath
	}

	// Add process group leader tracking
	if leaderPid, err := GetProcessGroupID(proc.Pid); err == nil {
		proc.LeaderPid = leaderPid
		if leaderPid != proc.Pid {
			if leader, err := GetOrFindProcess(uint32(leaderPid)); err == nil {
				proc.leader = leader
			}
		}
	}

	// Initialize socket maps
	proc.Sockets = make(map[string]int)
	proc.SocketUIDs = make(map[string]int)

	// Load current socket information
	if err := proc.updateSocketInformation(); err != nil {
		// Don't fail the whole process load if socket info fails
		proc.Error = fmt.Sprintf("socket info error: %v", err)
	}

	return proc, nil
}

// Add this method to Process
func (p *Process) Update() error {
	pInfo, err := process.NewProcess(int32(p.Pid))
	if err != nil {
		p.isValid = false
		return fmt.Errorf("process no longer exists: %v", err)
	}

	// Check if it's the same process (creation time matches)
	createdAt, err := pInfo.CreateTime()
	if err != nil {
		p.isValid = false
		return fmt.Errorf("failed to get creation time: %v", err)
	}

	if createdAt != p.CreatedAt {
		p.isValid = false
		return fmt.Errorf("process has been replaced")
	}

	// Update process information
	//if err := p.updateProcessInfo(pInfo); err != nil {
	//log.Warningf("partial update of process %d: %v", p.Pid, err)
	//}

	p.lastUpdate = time.Now()
	p.LastSeen = time.Now().Unix()
	p.isValid = true

	return nil
}

func (p *Process) updateSocketInformation() error {
	// Read /proc/PID/fd directory for socket information
	fdPath := fmt.Sprintf("/proc/%d/fd", p.Pid)
	entries, err := os.ReadDir(fdPath)
	if err != nil {
		return err
	}

	for _, entry := range entries {
		link, err := os.Readlink(fmt.Sprintf("%s/%s", fdPath, entry.Name()))
		if err != nil {
			continue
		}

		if strings.HasPrefix(link, "socket:[") {
			inode := strings.Trim(link[8:], "[]")
			fd, _ := strconv.Atoi(entry.Name())
			p.Sockets[inode] = fd
			p.SocketUIDs[inode] = p.UserID
		}
	}

	return nil
}

func calculateFileHash(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()

	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}

	return hex.EncodeToString(h.Sum(nil)), nil
}

func GetProcessGroupID(pid int) (int, error) {
	file, err := os.Open(fmt.Sprintf("/proc/%d/stat", pid))
	if err != nil {
		return UndefinedProcessID, err
	}
	defer file.Close()

	var stat struct {
		Pid     int
		Comm    string
		State   string
		Ppid    int
		Pgrp    int
		Session int
	}

	_, err = fmt.Fscanf(file, "%d %s %s %d %d %d",
		&stat.Pid, &stat.Comm, &stat.State, &stat.Ppid, &stat.Pgrp, &stat.Session)
	if err != nil {
		return UndefinedProcessID, err
	}

	return stat.Pgrp, nil
}

func parseNamespaces(nsString string) map[string]string {
	namespaces := make(map[string]string)
	if nsString == "" {
		return namespaces
	}

	for _, ns := range strings.Split(nsString, ",") {
		parts := strings.Split(ns, ":")
		if len(parts) == 2 {
			namespaces[parts[0]] = parts[1]
		}
	}
	return namespaces
}

// Add background cleanup
func init() {
	go func() {
		ticker := time.NewTicker(cleanupInterval)
		defer ticker.Stop()

		for range ticker.C {
			globalCache.Cleanup()
		}
	}()
}
