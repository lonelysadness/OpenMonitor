//go:build linux

package nfq

import (
	"errors"
	"fmt"
	"net"

	ct "github.com/florianl/go-conntrack"
)

var nfct *ct.Nfct

func InitConntrack() error {
	var err error
	nfct, err = ct.Open(&ct.Config{})
	if err != nil {
		return fmt.Errorf("failed to open conntrack: %w", err)
	}
	return nil
}

func CloseConntrack() {
	if nfct != nil {
		nfct.Close()
		nfct = nil
	}
}

func DeleteAllMarkedConnection() error {
	if nfct == nil {
		return errors.New("conntrack not initialized")
	}

	// Delete IPv4 marked connections
	deleted := deleteMarkedConnections(nfct, ct.IPv4)
	fmt.Printf("deleted %d conntrack entries\n", deleted)
	return nil
}

func deleteMarkedConnections(nfct *ct.Nfct, f ct.Family) (deleted int) {
	permanentFlags := []uint32{MarkAcceptAlways, MarkBlockAlways, MarkDropAlways}
	filter := ct.Con{}
	mark := uint32(0)
	filter.Mark = &mark

	for _, markValue := range permanentFlags {
		*filter.Mark = markValue
		conns, err := nfct.Dump(ct.Conntrack, f)
		if err != nil {
			fmt.Printf("error on conntrack query: %s\n", err)
			continue
		}

		for _, conn := range conns {
			if err := nfct.Delete(ct.Conntrack, f, conn); err != nil {
				fmt.Printf("failed to delete connection: %s\n", err)
				continue
			}
			deleted++
		}
	}

	return deleted
}

type Connection struct {
	SrcIP    net.IP
	DstIP    net.IP
	Protocol uint8
	SrcPort  uint16
	DstPort  uint16
}

func DeleteConnection(conn *Connection) error {
	if nfct == nil {
		return errors.New("conntrack not initialized")
	}

	con := ct.Con{
		Origin: &ct.IPTuple{
			Src: &conn.SrcIP,
			Dst: &conn.DstIP,
			Proto: &ct.ProtoTuple{
				Number:  &conn.Protocol,
				SrcPort: &conn.SrcPort,
				DstPort: &conn.DstPort,
			},
		},
	}

	return nfct.Delete(ct.Conntrack, ct.IPv4, con)
}
