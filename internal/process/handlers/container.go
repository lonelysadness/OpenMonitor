package handlers

import (
	"fmt"
	"os"
	"strings"

	"github.com/lonelysadness/OpenMonitor/internal/process"
)

func init() {
	process.RegisterTagHandler(new(ContainerHandler))
}

const (
	containerTagKey = "container-type"
)

type ContainerHandler struct{}

func (h *ContainerHandler) Name() string {
	return "Container"
}

func (h *ContainerHandler) TagDescriptions() []process.TagDescription {
	return []process.TagDescription{
		{
			ID:          containerTagKey,
			Name:        "Container Type",
			Description: "Type of container runtime",
		},
	}
}

func (h *ContainerHandler) AddTags(p *process.Process) {
	// Docker detection
	if _, err := os.Stat(fmt.Sprintf("/proc/%d/root/.dockerenv", p.Pid)); err == nil {
		p.Tags = append(p.Tags, process.Tag{
			Key:   containerTagKey,
			Value: "docker",
		})
		p.IsContainer = true
		p.ContainerType = "docker"
		return
	}

	// Podman detection
	if cgroup, err := os.ReadFile(fmt.Sprintf("/proc/%d/cgroup", p.Pid)); err == nil {
		if strings.Contains(string(cgroup), "libpod") {
			p.Tags = append(p.Tags, process.Tag{
				Key:   containerTagKey,
				Value: "podman",
			})
			p.IsContainer = true
			p.ContainerType = "podman"
			return
		}
	}
}
