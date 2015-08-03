package netlink

import (
	"fmt"
	"net"
	"strings"
	"syscall"
	"unsafe"
)

type IfAddrmsg struct {
	syscall.IfAddrmsg
}

func NewIfAddrmsg(family int) *IfAddrmsg {
	return &IfAddrmsg{
		IfAddrmsg: syscall.IfAddrmsg{
			Family: uint8(family),
		},
	}
}

func DeserializeIfAddrmsg(b []byte) *IfAddrmsg {
	return (*IfAddrmsg)(unsafe.Pointer(&b[0:syscall.SizeofIfAddrmsg][0]))
}

func (msg *IfAddrmsg) Serialize() []byte {
	return (*(*[syscall.SizeofIfAddrmsg]byte)(unsafe.Pointer(msg)))[:]
}

func (msg *IfAddrmsg) Len() int {
	return syscall.SizeofIfAddrmsg
}

// AddrAdd will add an IP address to a link device.
// Equivalent to: `ip addr add $addr dev $link`
func AddrAdd(s *NetlinkSocket, link Link, addr *Addr) error {

	req := NewNetlinkRequest(syscall.RTM_NEWADDR, syscall.NLM_F_CREATE|syscall.NLM_F_EXCL|syscall.NLM_F_ACK)
	return addrHandle(s, link, addr, req)
}

// AddrDel will delete an IP address from a link device.
// Equivalent to: `ip addr del $addr dev $link`
func AddrDel(s *NetlinkSocket, link Link, addr *Addr) error {
	req := NewNetlinkRequest(syscall.RTM_DELADDR, syscall.NLM_F_ACK)
	return addrHandle(s, link, addr, req)
}

func addrHandle(s *NetlinkSocket, link Link, addr *Addr, req *NetlinkRequest) error {
	base := link.Attrs()
	if addr.Label != "" && !strings.HasPrefix(addr.Label, base.Name) {
		return fmt.Errorf("label must begin with interface name")
	}
	ensureIndex(s, base)

	family := GetIPFamily(addr.IP)

	msg := NewIfAddrmsg(family)
	msg.Index = uint32(base.Index)
	prefixlen, _ := addr.Mask.Size()
	msg.Prefixlen = uint8(prefixlen)
	req.AddData(msg)

	var addrData []byte
	if family == FAMILY_V4 {
		addrData = addr.IP.To4()
	} else {
		addrData = addr.IP.To16()
	}

	localData := NewRtAttr(syscall.IFA_LOCAL, addrData)
	req.AddData(localData)

	addressData := NewRtAttr(syscall.IFA_ADDRESS, addrData)
	req.AddData(addressData)

	if addr.Label != "" {
		labelData := NewRtAttr(syscall.IFA_LABEL, ZeroTerminated(addr.Label))
		req.AddData(labelData)
	}

	_, err := req.Execute(s, 0)
	return err
}

func AddressDeserialize(m []byte) (*Addr, uint32, error) {
	msg := DeserializeIfAddrmsg(m)

	attrs, err := ParseRouteAttr(m[msg.Len():])
	if err != nil {
		return nil, 0, err
	}

	addr := &Addr{}
	for _, attr := range attrs {
		switch attr.Attr.Type {
		case syscall.IFA_ADDRESS:
			addr.IPNet = &net.IPNet{
				IP:   attr.Value,
				Mask: net.CIDRMask(int(msg.Prefixlen), 8*len(attr.Value)),
			}
		case syscall.IFA_LABEL:
			addr.Label = string(attr.Value[:len(attr.Value)-1])
		}
	}
	return addr, msg.Index, nil
}

// AddrList gets a list of IP addresses in the system.
// Equivalent to: `ip addr show`.
// The list can be filtered by link and ip family.
func AddrList(s *NetlinkSocket, link Link, family int) ([]Addr, error) {
	req := NewNetlinkRequest(syscall.RTM_GETADDR, syscall.NLM_F_DUMP)
	msg := NewIfInfomsg(family)
	req.AddData(msg)

	msgs, err := req.Execute(s, syscall.RTM_NEWADDR)
	if err != nil {
		return nil, err
	}

	index := 0
	if link != nil {
		base := link.Attrs()
		ensureIndex(s, base)
		index = base.Index
	}

	res := make([]Addr, 0)
	for _, m := range msgs {
		if addr, aidx, err := AddressDeserialize(m); err != nil {
			return nil, err
		} else {
			if link != nil && aidx != uint32(index) {
				// Ignore messages from other interfaces
				continue
			}
			res = append(res, *addr)
		}
	}

	return res, nil
}
