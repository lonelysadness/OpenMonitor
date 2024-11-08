package process

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
)

func FindProcessBySocket(uid, inode int) (*Process, error) {
	socketName := fmt.Sprintf("socket:[%d]", inode)
	processes, err := getAllProcessesByUID(uid)
	if err != nil {
		return nil, err
	}

	for _, proc := range processes {
		if hasSocket(proc.Pid, socketName) {
			return proc, nil
		}
	}

	return nil, fmt.Errorf("no process found for socket %d", inode)
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

func getAllProcessesByUID(uid int) ([]*Process, error) {
	var processes []*Process
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return nil, err
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

		if proc.UserID == uid {
			processes = append(processes, proc)
		}
	}

	return processes, nil
}
