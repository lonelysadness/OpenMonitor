package process

import (
	"sync"
)

var (
	tagRegistry     []TagHandler
	tagRegistryLock sync.RWMutex
)

// TagHandler is a collection of process tag related interfaces
type TagHandler interface {
	Name() string
	TagDescriptions() []TagDescription
	AddTags(p *Process)
}

// TagDescription describes a tag
type TagDescription struct {
	ID          string
	Name        string
	Description string
}

// RegisterTagHandler registers a new tag handler
func RegisterTagHandler(th TagHandler) error {
	tagRegistryLock.Lock()
	defer tagRegistryLock.Unlock()
	tagRegistry = append(tagRegistry, th)
	return nil
}

// processTags runs all registered tag handlers on a process
func (p *Process) processTags() {
	tagRegistryLock.RLock()
	defer tagRegistryLock.RUnlock()

	for _, handler := range tagRegistry {
		handler.AddTags(p)
	}
}
