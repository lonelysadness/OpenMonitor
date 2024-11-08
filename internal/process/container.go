package process

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

func getDockerID(procPath string) string {
	cgroupFile := filepath.Join(procPath, "cgroup")
	data, err := os.ReadFile(cgroupFile)
	if err != nil {
		return ""
	}

	for _, line := range strings.Split(string(data), "\n") {
		// Look for the docker container ID pattern
		if strings.Contains(line, "docker-") {
			parts := strings.Split(line, "docker-")
			if len(parts) > 1 {
				// Extract the ID and remove any trailing content
				id := strings.Split(parts[1], ".")[0]
				// Clean up the ID by removing any path components
				if strings.Contains(id, "/") {
					pathParts := strings.Split(id, "/")
					id = pathParts[len(pathParts)-1]
				}
				// Verify it's a valid docker ID (64 hex chars)
				if len(id) == 64 && isHexString(id) {
					return id
				}
			}
		}
	}
	return ""
}

// Add this helper function
func isHexString(s string) bool {
	for _, r := range s {
		if !strings.ContainsRune("0123456789abcdef", r) {
			return false
		}
	}
	return true
}

func detectContainer(pid int) (bool, map[string]string) {
	info := make(map[string]string)
	procPath := filepath.Join("/proc", fmt.Sprintf("%d", pid))

	// 1. Check for container specific files
	if _, err := os.Stat(filepath.Join(procPath, "root/.dockerenv")); err == nil {
		info["type"] = "docker"
		// Get container ID from cgroup
		if id := getDockerID(procPath); id != "" {
			info["id"] = id
		}
		return true, info
	}

	// 2. Check cgroup information
	cgroupInfo, err := readCgroupInfo(pid)
	if err == nil {
		for _, cgroup := range cgroupInfo {
			// Docker
			if strings.Contains(cgroup, "docker-") {
				info["type"] = "docker"
				parts := strings.Split(cgroup, "docker-")
				if len(parts) > 1 {
					info["id"] = strings.Split(parts[1], ".")[0]
				}
				return true, info
			}
			// Kubernetes pod
			if strings.Contains(cgroup, "kubepods") {
				info["type"] = "kubernetes"
				return true, info
			}
			// LXC container
			if strings.Contains(cgroup, "lxc") {
				info["type"] = "lxc"
				return true, info
			}
			// systemd-nspawn
			if strings.Contains(cgroup, ".slice/machine-") {
				info["type"] = "systemd-nspawn"
				return true, info
			}
		}
	}

	// 3. Check namespaces
	namespaces, err := readNamespaces(pid)
	if err == nil {
		info["namespaces"] = strings.Join(namespaces, ",")
		// Check if namespaces are different from parent
		if isNamespaceDifferent(pid, namespaces) {
			info["type"] = "container"
			return true, info
		}
	}

	// 4. Check environment variables
	environ := filepath.Join(procPath, "environ")
	if data, err := os.ReadFile(environ); err == nil {
		env := string(data)
		if strings.Contains(env, "container=") ||
			strings.Contains(env, "KUBERNETES_") ||
			strings.Contains(env, "DOCKER_") {
			info["type"] = "container"
			return true, info
		}
	}

	return false, info
}

func readCgroupInfo(pid int) ([]string, error) {
	cgroupFile := filepath.Join("/proc", fmt.Sprintf("%d", pid), "cgroup")
	file, err := os.Open(cgroupFile)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var cgroups []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		cgroups = append(cgroups, scanner.Text())
	}
	return cgroups, scanner.Err()
}

func readNamespaces(pid int) ([]string, error) {
	nsPath := filepath.Join("/proc", fmt.Sprintf("%d", pid), "ns")
	entries, err := os.ReadDir(nsPath)
	if err != nil {
		return nil, err
	}

	var namespaces []string
	for _, entry := range entries {
		if link, err := os.Readlink(filepath.Join(nsPath, entry.Name())); err == nil {
			namespaces = append(namespaces, entry.Name()+":"+link)
		}
	}
	return namespaces, nil
}

func isNamespaceDifferent(pid int, childNs []string) bool {
	ppid, err := GetParentPID(pid)
	if err != nil {
		return false
	}

	parentNs, err := readNamespaces(ppid)
	if err != nil {
		return false
	}

	// Compare namespaces
	childMap := make(map[string]string)
	for _, ns := range childNs {
		parts := strings.Split(ns, ":")
		if len(parts) == 2 {
			childMap[parts[0]] = parts[1]
		}
	}

	for _, ns := range parentNs {
		parts := strings.Split(ns, ":")
		if len(parts) == 2 {
			if childMap[parts[0]] != parts[1] {
				return true
			}
		}
	}

	return false
}

func GetParentPID(pid int) (int, error) {
	file, err := os.Open(filepath.Join("/proc", fmt.Sprintf("%d", pid), "status"))
	if err != nil {
		return 0, err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		if strings.HasPrefix(scanner.Text(), "PPid:") {
			var ppid int
			_, err := fmt.Sscanf(scanner.Text(), "PPid:\t%d", &ppid)
			if err != nil {
				return 0, err
			}
			return ppid, nil
		}
	}
	return 0, fmt.Errorf("PPid not found")
}
