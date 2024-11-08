package handlers

import (
	"strings"

	"github.com/lonelysadness/OpenMonitor/internal/process"
)

func init() {
	process.RegisterTagHandler(new(FlatpakHandler))
}

const (
	flatpakTagKey = "flatpak-id"
)

type FlatpakHandler struct{}

func (h *FlatpakHandler) Name() string {
	return "Flatpak"
}

func (h *FlatpakHandler) TagDescriptions() []process.TagDescription {
	return []process.TagDescription{
		{
			ID:          flatpakTagKey,
			Name:        "Flatpak ID",
			Description: "ID of the flatpak application",
		},
	}
}

func (h *FlatpakHandler) AddTags(p *process.Process) {
	// Check if binary lives in the /app space
	if !strings.HasPrefix(p.Path, "/app/") {
		return
	}

	// Get the Flatpak ID from environment
	flatpakID, ok := p.Env["FLATPAK_ID"]
	if !ok || flatpakID == "" {
		return
	}

	p.Tags = append(p.Tags, process.Tag{
		Key:   flatpakTagKey,
		Value: flatpakID,
	})
}
