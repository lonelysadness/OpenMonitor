package process

import (
	"fmt"
	"io/ioutil"
	"os"
	"strconv"
	"strings"
)

// Add this function at the top of the file
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

// FindProcessBySocket finds a process that owns the given socket inode
func FindProcessBySocket(uid int, inode string) (*Process, error) {
	socketName := fmt.Sprintf("socket:[%s]", inode)

	// Get all processes for the UID
	processes, err := getAllProcessesByUID(uid)
	if err != nil {
		return nil, err
	}

	// Search through processes in reverse (newer PIDs first)
	for i := len(processes) - 1; i >= 0; i-- {
		proc := processes[i]
		if proc.hasSocket(socketName) {
			return proc, nil
		}
	}

	return nil, fmt.Errorf("no process found for socket %s", inode)
}

// Update hasSocket to be more thorough
func (p *Process) hasSocket(socketName string) bool {
	fdPath := fmt.Sprintf("/proc/%d/fd", p.Pid)
	entries, err := os.ReadDir(fdPath)
	if err != nil {
		return false
	}

	for _, entry := range entries {
		link, err := os.Readlink(fmt.Sprintf("%s/%s", fdPath, entry.Name()))
		if err != nil {
			continue
		}

		// Check both exact match and contains for socket inode
		if link == socketName || strings.Contains(link, "socket:[") {
			fd, _ := strconv.Atoi(entry.Name())
			p.Sockets[socketName] = fd
			p.SocketUIDs[socketName] = p.UserID
			return true
		}
	}

	return false
}
