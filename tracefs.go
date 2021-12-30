package tracefs

import (
	"bytes"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"
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

// Create a new child tracer instance. This only works when called on the root instance.
func NewInstance(name string) (*Instance, error) {
	return DefaultInstance.NewInstance(name)
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
func (i *Instance) On() (bool, error) {
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
func (i *Instance) Enable() error {
	return i.writeFile(tracingOnPath, []byte("1"))
}

// Disable sets tracing_on to 0. If tracing is already disabled this is a no-op.
func (i *Instance) Disable() error {
	return i.writeFile(tracingOnPath, []byte("0"))
}

// Create a new child tracer instance. This only works when called on the root instance.
func (i *Instance) NewInstance(name string) (*Instance, error) {
	if !i.isRoot {
		return nil, fmt.Errorf("must be called on a root instance")
	}

	childPath := filepath.Join(i.path, "instances", name)
	err := os.Mkdir(childPath, 0777)
	if err != nil {
		return nil, err
	}

	return &Instance{
		path: childPath,
		name: name,
	}, nil
}

// Destory tracer instance. This does not work on the root instance
func (i *Instance) Destroy() error {
	if i.isRoot {
		return fmt.Errorf("cannot destroy the root tracer instance")
	}

	return os.Remove(i.path)
}

func (i *Instance) AddUprobeEvent(e *UprobeEvent) error {
	f, err := os.OpenFile(filepath.Join(i.path, "uprobe_events"), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return err
	}
	defer f.Close()

	_, err = fmt.Fprintln(f, e.Rule())
	if err != nil {
		return err
	}

	return f.Close()
}

func (i *Instance) TracePipe() (io.ReadCloser, error) {
	return os.Open(filepath.Join(i.path, "trace_pipe"))
}

type UprobeEvent struct {
	ReturnProbe bool
	Group       string
	Event       string
	Path        string
	Offset      uint64
	FetchArgs   []FetchArg
}

func (e *UprobeEvent) Rule() string {
	typ := "p"
	if e.ReturnProbe {
		typ = "r"
	}

	var builder strings.Builder

	builder.Write([]byte(typ))
	if e.Group != "" && e.Event != "" {
		fmt.Fprintf(&builder, ":%s/%s", e.Group, e.Event)
	} else if e.Event != "" {
		fmt.Fprintf(&builder, ":%s", e.Event)
	}

	fmt.Fprintf(&builder, " %s:0x%016x", e.Path, e.Offset)

	for _, arg := range e.FetchArgs {
		fmt.Fprintf(&builder, " %s", arg.String())
	}

	return builder.String()
}

func (i *Instance) UprobeEnablePath(e *UprobeEvent) string {
	if e.Group != "" && e.Event != "" {
		return filepath.Join(i.path, "events", e.Group, e.Event, "enable")
	} else if e.Event != "" {
		return filepath.Join(i.path, "events", "uprobes", e.Event, "enable")
	}

	return filepath.Join(i.path, "events", "uprobes", "enable")
}

func (i *Instance) EnableUprobe(e *UprobeEvent) error {
	return i.writeFile(i.UprobeEnablePath(e), []byte("1"))
}

func (i *Instance) DisableUprobe(e *UprobeEvent) error {
	return i.writeFile(i.UprobeEnablePath(e), []byte("0"))
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
