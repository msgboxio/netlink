package netlink

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net"
	"syscall"
)

var native = NativeEndian()
var lookupByDump = false

type vxlanPortRange struct {
	Lo, Hi uint16
}

func ensureIndex(s *NetlinkSocket, link *LinkAttrs) {
	if link != nil && link.Index == 0 {
		newlink, _ := LinkByName(s, link.Name)
		if newlink != nil {
			link.Index = newlink.Attrs().Index
		}
	}
}

// LinkSetUp enables the link device.
// Equivalent to: `ip link set $link up`
func LinkSetUp(s *NetlinkSocket, link Link) error {
	base := link.Attrs()
	ensureIndex(s, base)
	req := NewNetlinkRequest(syscall.RTM_NEWLINK, syscall.NLM_F_ACK)

	msg := NewIfInfomsg(syscall.AF_UNSPEC)
	msg.Change = syscall.IFF_UP
	msg.Flags = syscall.IFF_UP
	msg.Index = int32(base.Index)
	req.AddData(msg)

	_, err := req.Execute(s, 0)
	return err
}

// LinkAdd adds a new link device. The type and features of the device
// are taken fromt the parameters in the link object.
// Equivalent to: `ip link add $link`
func LinkAdd(s *NetlinkSocket, link Link) error {
	// TODO: set mtu and hardware address
	// TODO: support extra data for macvlan
	base := link.Attrs()

	if base.Name == "" {
		return fmt.Errorf("LinkAttrs.Name cannot be empty!")
	}

	req := NewNetlinkRequest(syscall.RTM_NEWLINK, syscall.NLM_F_CREATE|syscall.NLM_F_EXCL|syscall.NLM_F_ACK)

	msg := NewIfInfomsg(syscall.AF_UNSPEC)
	req.AddData(msg)

	// dont handle parent index

	nameData := NewRtAttr(syscall.IFLA_IFNAME, ZeroTerminated(base.Name))
	req.AddData(nameData)

	if base.MTU > 0 {
		mtu := NewRtAttr(syscall.IFLA_MTU, Uint32Attr(uint32(base.MTU)))
		req.AddData(mtu)
	}

	// dont handle namespace

	linkInfo := NewRtAttr(syscall.IFLA_LINKINFO, nil)
	NewRtAttrChild(linkInfo, IFLA_INFO_KIND, NonZeroTerminated(link.Type()))

	NewRtAttrChild(linkInfo, syscall.IFLA_TXQLEN, Uint32Attr(base.TxQLen))

	// dont handle vlan, veth, vxlan, ipvlan, macvlan

	req.AddData(linkInfo)

	_, err := req.Execute(s, 0)
	if err != nil {
		return err
	}

	ensureIndex(s, base)

	// dont handle setting master
	return nil
}

// LinkList gets a list of link devices.
// Equivalent to: `ip link show`
func LinkList(s *NetlinkSocket) ([]Link, error) {
	// NOTE(vish): This duplicates functionality in net/iface_linux.go, but we need
	//             to get the message ourselves to parse link type.
	req := NewNetlinkRequest(syscall.RTM_GETLINK, syscall.NLM_F_DUMP)

	msg := NewIfInfomsg(syscall.AF_UNSPEC)
	req.AddData(msg)

	msgs, err := req.Execute(s, syscall.RTM_NEWLINK)
	if err != nil {
		return nil, err
	}

	res := make([]Link, 0)

	for _, m := range msgs {
		link, err := linkDeserialize(m)
		if err != nil {
			return nil, err
		}
		res = append(res, link)
	}

	return res, nil
}

func linkByNameDump(s *NetlinkSocket, name string) (Link, error) {
	links, err := LinkList(s)
	if err != nil {
		return nil, err
	}

	for _, link := range links {
		if link.Attrs().Name == name {
			return link, nil
		}
	}
	return nil, fmt.Errorf("Link %s not found", name)
}

// LinkByName finds a link by name and returns a pointer to the object.
func LinkByName(s *NetlinkSocket, name string) (link Link, err error) {
	req := NewNetlinkRequest(syscall.RTM_GETLINK, syscall.NLM_F_ACK)

	msg := NewIfInfomsg(syscall.AF_UNSPEC)
	req.AddData(msg)

	nameData := NewRtAttr(syscall.IFLA_IFNAME, ZeroTerminated(name))
	req.AddData(nameData)

	link, err = execGetLink(s, req)
	if err == syscall.EINVAL {
		// older kernels don't support looking up via IFLA_IFNAME
		// so fall back to dumping all links
		lookupByDump = true
		return linkByNameDump(s, name)
	}

	return
}

func execGetLink(s *NetlinkSocket, req *NetlinkRequest) (Link, error) {
	msgs, err := req.Execute(s, 0)
	if err != nil {
		if errno, ok := err.(syscall.Errno); ok {
			if errno == syscall.ENODEV {
				return nil, fmt.Errorf("Link not found")
			}
		}
		return nil, err
	}

	switch {
	case len(msgs) == 0:
		return nil, fmt.Errorf("Link not found")

	case len(msgs) == 1:
		return linkDeserialize(msgs[0])

	default:
		return nil, fmt.Errorf("More than one link found")
	}
}

// linkDeserialize deserializes a raw message received from netlink into
// a link object.
func linkDeserialize(m []byte) (Link, error) {
	msg := DeserializeIfInfomsg(m)

	attrs, err := ParseRouteAttr(m[msg.Len():])
	if err != nil {
		return nil, err
	}

	base := LinkAttrs{Index: int(msg.Index), Flags: linkFlags(msg.Flags)}
	var link Link
	linkType := ""
	for _, attr := range attrs {
		switch attr.Attr.Type {
		case syscall.IFLA_LINKINFO:
			infos, err := ParseRouteAttr(attr.Value)
			if err != nil {
				return nil, err
			}
			for _, info := range infos {
				switch info.Attr.Type {
				case IFLA_INFO_KIND:
					linkType = string(info.Value[:len(info.Value)-1])
					switch linkType {
					case "dummy":
						link = &Dummy{}
					case "bridge":
						link = &Bridge{}
					case "vlan":
						link = &Vlan{}
					case "veth":
						link = &Veth{}
					case "vxlan":
						link = &Vxlan{}
					case "ipvlan":
						link = &IPVlan{}
					case "macvlan":
						link = &Macvlan{}
					default:
						link = &Generic{LinkType: linkType}
					}
				case IFLA_INFO_DATA:
					data, err := ParseRouteAttr(info.Value)
					if err != nil {
						return nil, err
					}
					switch linkType {
					case "vlan":
						parseVlanData(link, data)
					case "vxlan":
						parseVxlanData(link, data)
					case "ipvlan":
						parseIPVlanData(link, data)
					case "macvlan":
						parseMacvlanData(link, data)
					}
				}
			}
		case syscall.IFLA_ADDRESS:
			var nonzero bool
			for _, b := range attr.Value {
				if b != 0 {
					nonzero = true
				}
			}
			if nonzero {
				base.HardwareAddr = attr.Value[:]
			}
		case syscall.IFLA_IFNAME:
			base.Name = string(attr.Value[:len(attr.Value)-1])
		case syscall.IFLA_MTU:
			base.MTU = int(native.Uint32(attr.Value[0:4]))
		case syscall.IFLA_LINK:
			base.ParentIndex = int(native.Uint32(attr.Value[0:4]))
		case syscall.IFLA_MASTER:
			base.MasterIndex = int(native.Uint32(attr.Value[0:4]))
		case syscall.IFLA_TXQLEN:
			base.TxQLen = native.Uint32(attr.Value[0:4])
		}
	}
	// Links that don't have IFLA_INFO_KIND are hardware devices
	if link == nil {
		link = &Device{}
	}
	*link.Attrs() = base

	return link, nil
}

func parseVlanData(link Link, data []syscall.NetlinkRouteAttr) {
	vlan := link.(*Vlan)
	for _, datum := range data {
		switch datum.Attr.Type {
		case IFLA_VLAN_ID:
			vlan.VlanId = int(native.Uint16(datum.Value[0:2]))
		}
	}
}

func parseVxlanData(link Link, data []syscall.NetlinkRouteAttr) {
	vxlan := link.(*Vxlan)
	for _, datum := range data {
		switch datum.Attr.Type {
		case IFLA_VXLAN_ID:
			vxlan.VxlanId = int(native.Uint32(datum.Value[0:4]))
		case IFLA_VXLAN_LINK:
			vxlan.VtepDevIndex = int(native.Uint32(datum.Value[0:4]))
		case IFLA_VXLAN_LOCAL:
			vxlan.SrcAddr = net.IP(datum.Value[0:4])
		case IFLA_VXLAN_LOCAL6:
			vxlan.SrcAddr = net.IP(datum.Value[0:16])
		case IFLA_VXLAN_GROUP:
			vxlan.Group = net.IP(datum.Value[0:4])
		case IFLA_VXLAN_GROUP6:
			vxlan.Group = net.IP(datum.Value[0:16])
		case IFLA_VXLAN_TTL:
			vxlan.TTL = int(datum.Value[0])
		case IFLA_VXLAN_TOS:
			vxlan.TOS = int(datum.Value[0])
		case IFLA_VXLAN_LEARNING:
			vxlan.Learning = int8(datum.Value[0]) != 0
		case IFLA_VXLAN_PROXY:
			vxlan.Proxy = int8(datum.Value[0]) != 0
		case IFLA_VXLAN_RSC:
			vxlan.RSC = int8(datum.Value[0]) != 0
		case IFLA_VXLAN_L2MISS:
			vxlan.L2miss = int8(datum.Value[0]) != 0
		case IFLA_VXLAN_L3MISS:
			vxlan.L3miss = int8(datum.Value[0]) != 0
		case IFLA_VXLAN_AGEING:
			vxlan.Age = int(native.Uint32(datum.Value[0:4]))
			vxlan.NoAge = vxlan.Age == 0
		case IFLA_VXLAN_LIMIT:
			vxlan.Limit = int(native.Uint32(datum.Value[0:4]))
		case IFLA_VXLAN_PORT:
			vxlan.Port = int(native.Uint16(datum.Value[0:2]))
		case IFLA_VXLAN_PORT_RANGE:
			buf := bytes.NewBuffer(datum.Value[0:4])
			var pr vxlanPortRange
			if binary.Read(buf, binary.BigEndian, &pr) != nil {
				vxlan.PortLow = int(pr.Lo)
				vxlan.PortHigh = int(pr.Hi)
			}
		}
	}
}

func parseIPVlanData(link Link, data []syscall.NetlinkRouteAttr) {
	ipv := link.(*IPVlan)
	for _, datum := range data {
		if datum.Attr.Type == IFLA_IPVLAN_MODE {
			ipv.Mode = IPVlanMode(native.Uint32(datum.Value[0:4]))
			return
		}
	}
}

func parseMacvlanData(link Link, data []syscall.NetlinkRouteAttr) {
	macv := link.(*Macvlan)
	for _, datum := range data {
		if datum.Attr.Type == IFLA_MACVLAN_MODE {
			switch MacvlanMode(native.Uint32(datum.Value[0:4])) {
			case MACVLAN_MODE_PRIVATE:
				macv.Mode = MACVLAN_MODE_PRIVATE
			case MACVLAN_MODE_VEPA:
				macv.Mode = MACVLAN_MODE_VEPA
			case MACVLAN_MODE_BRIDGE:
				macv.Mode = MACVLAN_MODE_BRIDGE
			case MACVLAN_MODE_PASSTHRU:
				macv.Mode = MACVLAN_MODE_PASSTHRU
			case MACVLAN_MODE_SOURCE:
				macv.Mode = MACVLAN_MODE_SOURCE
			}
			return
		}
	}
}

// copied from pkg/net_linux.go
func linkFlags(rawFlags uint32) net.Flags {
	var f net.Flags
	if rawFlags&syscall.IFF_UP != 0 {
		f |= net.FlagUp
	}
	if rawFlags&syscall.IFF_BROADCAST != 0 {
		f |= net.FlagBroadcast
	}
	if rawFlags&syscall.IFF_LOOPBACK != 0 {
		f |= net.FlagLoopback
	}
	if rawFlags&syscall.IFF_POINTOPOINT != 0 {
		f |= net.FlagPointToPoint
	}
	if rawFlags&syscall.IFF_MULTICAST != 0 {
		f |= net.FlagMulticast
	}
	return f
}
