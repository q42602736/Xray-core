package tun

import (
	"context"
	"net"
	"sync"

	"github.com/xtls/xray-core/common/errors"
)

type InterfaceUpdater struct {
	sync.Mutex

	tunIndex  int
	fixedName string
	iface     *net.Interface
}

var updater *InterfaceUpdater

var DiagnosticLogger func(format string, args ...any)

func emitDiagnostic(format string, args ...any) {
	if DiagnosticLogger != nil {
		DiagnosticLogger(format, args...)
	}
}

func (updater *InterfaceUpdater) Get() *net.Interface {
	updater.Lock()
	defer updater.Unlock()

	return updater.iface
}

func (updater *InterfaceUpdater) Update() {
	updater.Lock()
	defer updater.Unlock()

	if updater.iface != nil {
		iface, err := net.InterfaceByIndex(updater.iface.Index)
		if err == nil && iface.Name == updater.iface.Name {
			return
		}
	}

	updater.iface = nil

	interfaces, err := net.Interfaces()
	if err != nil {
		errors.LogInfoInner(context.Background(), err, "[tun] failed to update interface")
		return
	}

	var got *net.Interface
	for _, iface := range interfaces {
		if iface.Index == updater.tunIndex {
			continue
		}
		if updater.fixedName != "" {
			if iface.Name == updater.fixedName {
				got = &iface
				break
			}
		} else {
			addrs, err := iface.Addrs()
			if err != nil {
				continue
			}
			if (iface.Flags&net.FlagUp != 0) &&
				(iface.Flags&net.FlagLoopback == 0) &&
				len(addrs) > 0 {
				got = &iface
				break
			}
		}
	}

	if got == nil {
		errors.LogInfo(context.Background(), "[tun] failed to update interface > got == nil")
		emitDiagnostic("xray tun outbound interface empty fixed=%s tunIndex=%d", updater.fixedName, updater.tunIndex)
		return
	}

	updater.iface = got
	errors.LogInfo(context.Background(), "[tun] update interface ", got.Name, " ", got.Index)
	emitDiagnostic("xray tun outbound interface selected name=%s index=%d fixed=%s", got.Name, got.Index, updater.fixedName)
}
