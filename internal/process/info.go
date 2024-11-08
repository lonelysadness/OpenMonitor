package process

import (
	"fmt"
	"os/user"

	"github.com/shirou/gopsutil/process"
)

func GetProcessDetails(pid uint32) (name string, owner string, parentInfo string) {
	p, err := process.NewProcess(int32(pid))
	if err != nil {
		return "unknown", "unknown", "unknown"
	}

	name, err = p.Name()
	if err != nil {
		name = "unknown"
	}

	uids, err := p.Uids()
	if err != nil || len(uids) == 0 {
		owner = "unknown"
	} else {
		if u, err := user.LookupId(fmt.Sprintf("%d", uids[0])); err == nil {
			owner = u.Username
		} else {
			owner = fmt.Sprintf("uid:%d", uids[0])
		}
	}

	ppid, err := p.Ppid()
	if err != nil {
		parentInfo = "none"
	} else {
		parent, err := process.NewProcess(ppid)
		if err == nil {
			parentName, _ := parent.Name()
			parentInfo = fmt.Sprintf("%s(%d)", parentName, ppid)
		} else {
			parentInfo = fmt.Sprintf("pid:%d", ppid)
		}
	}

	return
}
