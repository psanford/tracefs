package tracefs

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
)

type Instance struct {
	isRoot bool
	path   string
	name   string
}

var (
	rootPath        = "/sys/kernel/tracing"
	DefaultInstance = RootInstance(rootPath)
)

func (i *Instance) Name() string {
	return i.name
}

func RootInstance(path string) Instance {
	return Instance{
		isRoot: true,
		name:   "*Default*",
		path:   path,
	}
}

func (i Instance) ChildInstances() ([]Instance, error) {
	if !i.isRoot {
		return nil, fmt.Errorf("Cannot get ChildInstances for non-root instance")
	}

	instanceDir := filepath.Join(i.path, "instances")
	entries, err := os.ReadDir(instanceDir)
	if err != nil {
		return nil, err
	}
	out := make([]Instance, len(entries))
	for i, e := range entries {
		out[i] = Instance{
			name: e.Name(),
			path: filepath.Join(instanceDir, e.Name()),
		}
	}

	return out, nil
}

func ListInstances() ([]Instance, error) {
	return DefaultInstance.ChildInstances()
}

type Tracer string

const (
	NopTracer           Tracer = "nop"
	FunctionTracer      Tracer = "function"
	WakeupTracer        Tracer = "wakeup"
	WakeupRTTracer      Tracer = "wakeup_rt"
	WakeupDLTracer      Tracer = "wakup_dl"
	FunctionGraphTracer Tracer = "function_graph"
	MMIOTraceTracer     Tracer = "mmiotrace"
	BlkTracer           Tracer = "blk"
	HWLatTracer         Tracer = "hwlat"
)

func (i *Instance) readFile(name string) ([]byte, error) {
	data, err := ioutil.ReadFile(filepath.Join(i.path, name))
	if err != nil {
		return nil, err
	}
	return bytes.TrimSpace(data), nil
}

func (i *Instance) writeFile(name string, b []byte) error {
	return ioutil.WriteFile(filepath.Join(i.path, name), b, 0777)
}

var (
	curTracerPath = "current_tracer"
	tracingOnPath = "tracing_on"
)

// CurrentTracer returns the current_tracer value.
func (i *Instance) CurrentTracer() (Tracer, error) {
	tracer, err := i.readFile(curTracerPath)
	if err != nil {
		return "", err
	}

	return Tracer(tracer), nil
}

// SetTracer sets current_tracer to t.
func (i *Instance) SetTracer(t Tracer) error {
	return i.writeFile(curTracerPath, []byte(t))
}

// On returns true if tracing_on is set to 1.
func (i Instance) On() (bool, error) {
	result, err := i.readFile(tracingOnPath)
	if err != nil {
		return false, err
	}
	switch string(result) {
	case "0":
		return false, nil
	case "1":
		return true, nil
	}

	return false, fmt.Errorf("unknown on value: %s", result)
}

// Enable sets tracing_on to 1. If tracing is already enabled this is a no-op.
func (i Instance) Enable() error {
	return i.writeFile(tracingOnPath, []byte("1"))
}

// Disable sets tracing_on to 0. If tracing is already disabled this is a no-op.
func (i Instance) Disable() error {
	return i.writeFile(tracingOnPath, []byte("0"))
}

type UprobeEvent struct {
	ReturnProbe bool
	Group       string
	Event       string
	Path        string
	Offset      string
	FetchArgs   []FetchArg
}

type FetchArg interface {
	Type() string
	String() string
}

type fetchRegister struct {
	register string
}

func (f fetchRegister) String() string {
	return f.register
}
