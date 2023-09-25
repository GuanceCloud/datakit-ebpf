package sysmonitor

import (
	"context"
	"fmt"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	manager "github.com/DataDog/ebpf-manager"
	"github.com/DataDog/gopsutil/process/so"
	pr "github.com/shirou/gopsutil/v3/process"
)

type UprobeRegRule struct {
	Re         *regexp.Regexp
	Register   func(string) error
	UnRegister func(string) error
}

type UprobeConf struct {
	AttachDynamicLib bool
	DynamicLibName   *regexp.Regexp

	FuncName           string
	UprobeProgFuncName string
}
type ProcessUprobeRegister struct {
	manager *manager.Manager
	Symbols []UprobeConf

	DynamicLibs              []UprobeConf
	AttchDynamicLibOrProcess bool

	// binpathAttached map[string]bool
}

func (reg *ProcessUprobeRegister) Register(p *pr.Process) {

}

func (reg *ProcessUprobeRegister) Unregister() {

}

func NewProcessUProbeRegister(m *manager.Manager) *ProcessUprobeRegister {
	return &ProcessUprobeRegister{
		manager: m,
	}
}

func NewUprobeDyncLibRegister(rules []UprobeRegRule) (*UprobeRegister, error) {
	r := &UprobeRegister{}
	r.rules = append(r.rules, rules...)
	allRe := []string{}
	if len(rules) == 0 {
		return nil, fmt.Errorf("len(rules) == 0")
	}
	for _, v := range rules {
		if v.Re == nil {
			return nil, fmt.Errorf("%#v", v)
		}
		allRe = append(allRe, fmt.Sprintf("(%s)", v.Re.String()))
	}
	var err error
	r.re, err = regexp.Compile(strings.Join(allRe, "|"))
	if err != nil {
		return nil, err
	}
	return r, nil
}

type UprobeRegister struct {
	rules []UprobeRegRule
	re    *regexp.Regexp

	libPaths map[string]struct{}

	scanInterval time.Duration

	run int32 // 0 or 1(true)

	sync.Mutex
}

func (register *UprobeRegister) ScanAndUpdate() {
	register.Lock()
	defer register.Unlock()
	allLibs := map[string]struct{}{}
	for _, v := range so.Find(register.re) {
		allLibs[v.HostPath] = struct{}{}
	}
	del, add := diff(register.libPaths, allLibs)
	if len(del) == 0 && len(add) == 0 {
		return
	}

	register.libPaths = allLibs

	for k := range del {
		for _, r := range register.rules {
			if r.Re.MatchString(k) {
				if err := r.UnRegister(k); err != nil {
					l.Error(err)
				}
			}
		}
	}

	for k := range add {
		for _, r := range register.rules {
			if r.Re.MatchString(k) {
				l.Info(k)
				if err := r.Register(k); err != nil {
					l.Error(err)
				}
			}
		}
	}
}

func (register *UprobeRegister) CleanAll() {
	register.Lock()
	defer register.Unlock()

	allLibs := map[string]struct{}{}
	for _, v := range so.Find(register.re) {
		allLibs[v.HostPath] = struct{}{}
	}

	for k := range allLibs {
		for _, r := range register.rules {
			if r.Re.MatchString(k) {
				if err := r.UnRegister(k); err != nil {
					l.Debug(err)
				}
			}
		}
	}
}

func (register *UprobeRegister) Monitor(ctx context.Context, scanInterval time.Duration) {
	if old := atomic.SwapInt32(&register.run, 1); old == 1 {
		l.Warn(".so monitor started")
		return
	}
	register.scanInterval = scanInterval
	ticker := time.NewTicker(register.scanInterval)
	go func() {
		for {
			select {
			case <-ticker.C:
				register.ScanAndUpdate()
			case <-ctx.Done():
				register.CleanAll()
				return
			}
		}
	}()
}

type (
	registerFunc   func(string) error
	unregisterFunc func(string) error
)

func NewRegisterFunc(m *manager.Manager, bpfFuncName []string) registerFunc {
	bfunc := []string{}
	bfunc = append(bfunc, bpfFuncName...)
	return func(binPath string) error {
		uid := ShortID(binPath)
		l.Info("AddHook: ", binPath, " ShortID: ", uid)
		for _, fnName := range bfunc {
			if err := m.AddHook("", &manager.Probe{
				ProbeIdentificationPair: manager.ProbeIdentificationPair{
					UID:          uid,
					EBPFFuncName: fnName,
				},
				BinaryPath: binPath,
			}); err != nil {
				l.Warn(err)
			}
		}
		return nil
	}
}

func NewUnRegisterFunc(m *manager.Manager, bpfFuncName []string) unregisterFunc {
	bfunc := []string{}
	bfunc = append(bfunc, bpfFuncName...)
	return func(binPath string) error {
		uid := ShortID(binPath)
		l.Info("DetachHook: ", binPath, " ShortID: ", uid)
		for _, fnName := range bfunc {
			p, ok := m.GetProbe(manager.ProbeIdentificationPair{
				UID:          uid,
				EBPFFuncName: fnName,
			})
			if !ok {
				continue
			}
			pp := p.Program()
			if err := m.DetachHook(manager.ProbeIdentificationPair{
				UID:          uid,
				EBPFFuncName: fnName,
			}); err != nil {
				l.Error(err)
			}
			if pp != nil {
				if err := pp.Close(); err != nil {
					l.Warn(err)
				}
			}
		}
		return nil
	}
}
