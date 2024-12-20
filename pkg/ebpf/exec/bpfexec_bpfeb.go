// Code generated by bpf2go; DO NOT EDIT.
//go:build arm64be || armbe || mips || mips64 || mips64p32 || ppc64 || s390 || s390x || sparc || sparc64

package exec

import (
	"bytes"
	_ "embed"
	"fmt"
	"io"

	"github.com/cilium/ebpf"
)

// loadBpfexec returns the embedded CollectionSpec for bpfexec.
func loadBpfexec() (*ebpf.CollectionSpec, error) {
	reader := bytes.NewReader(_BpfexecBytes)
	spec, err := ebpf.LoadCollectionSpecFromReader(reader)
	if err != nil {
		return nil, fmt.Errorf("can't load bpfexec: %w", err)
	}

	return spec, err
}

// loadBpfexecObjects loads bpfexec and converts it into a struct.
//
// The following types are suitable as obj argument:
//
//	*bpfexecObjects
//	*bpfexecPrograms
//	*bpfexecMaps
//
// See ebpf.CollectionSpec.LoadAndAssign documentation for details.
func loadBpfexecObjects(obj interface{}, opts *ebpf.CollectionOptions) error {
	spec, err := loadBpfexec()
	if err != nil {
		return err
	}

	return spec.LoadAndAssign(obj, opts)
}

// bpfexecSpecs contains maps and programs before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type bpfexecSpecs struct {
	bpfexecProgramSpecs
	bpfexecMapSpecs
}

// bpfexecSpecs contains programs before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type bpfexecProgramSpecs struct {
	EnterExecve *ebpf.ProgramSpec `ebpf:"enter_execve"`
}

// bpfexecMapSpecs contains maps before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type bpfexecMapSpecs struct {
	OmExecMap *ebpf.MapSpec `ebpf:"om_exec_map"`
}

// bpfexecObjects contains all objects after they have been loaded into the kernel.
//
// It can be passed to loadBpfexecObjects or ebpf.CollectionSpec.LoadAndAssign.
type bpfexecObjects struct {
	bpfexecPrograms
	bpfexecMaps
}

func (o *bpfexecObjects) Close() error {
	return _BpfexecClose(
		&o.bpfexecPrograms,
		&o.bpfexecMaps,
	)
}

// bpfexecMaps contains all maps after they have been loaded into the kernel.
//
// It can be passed to loadBpfexecObjects or ebpf.CollectionSpec.LoadAndAssign.
type bpfexecMaps struct {
	OmExecMap *ebpf.Map `ebpf:"om_exec_map"`
}

func (m *bpfexecMaps) Close() error {
	return _BpfexecClose(
		m.OmExecMap,
	)
}

// bpfexecPrograms contains all programs after they have been loaded into the kernel.
//
// It can be passed to loadBpfexecObjects or ebpf.CollectionSpec.LoadAndAssign.
type bpfexecPrograms struct {
	EnterExecve *ebpf.Program `ebpf:"enter_execve"`
}

func (p *bpfexecPrograms) Close() error {
	return _BpfexecClose(
		p.EnterExecve,
	)
}

func _BpfexecClose(closers ...io.Closer) error {
	for _, closer := range closers {
		if err := closer.Close(); err != nil {
			return err
		}
	}
	return nil
}

// Do not access this directly.
//
//go:embed bpfexec_bpfeb.o
var _BpfexecBytes []byte
