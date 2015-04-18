package netlink

import (
	"fmt"
	"net"
	"syscall"
	"unsafe"
)

const (
	SCOPE_UNIVERSE Scope = syscall.RT_SCOPE_UNIVERSE
	SCOPE_SITE     Scope = syscall.RT_SCOPE_SITE
	SCOPE_LINK     Scope = syscall.RT_SCOPE_LINK
	SCOPE_HOST     Scope = syscall.RT_SCOPE_HOST
	SCOPE_NOWHERE  Scope = syscall.RT_SCOPE_NOWHERE
)

type RtMsg struct {
	syscall.RtMsg
}

func NewRtMsg() *RtMsg {
	return &RtMsg{
		RtMsg: syscall.RtMsg{
			Table:    syscall.RT_TABLE_MAIN,
			Scope:    syscall.RT_SCOPE_UNIVERSE,
			Protocol: syscall.RTPROT_BOOT,
			Type:     syscall.RTN_UNICAST,
		},
	}
}

func (msg *RtMsg) Len() int {
	return syscall.SizeofRtMsg
}

func DeserializeRtMsg(b []byte) *RtMsg {
	return (*RtMsg)(unsafe.Pointer(&b[0:syscall.SizeofRtMsg][0]))
}

func (msg *RtMsg) Serialize() []byte {
	return (*(*[syscall.SizeofRtMsg]byte)(unsafe.Pointer(msg)))[:]
}

// RtAttr is shared so it is in netlink_linux.go

// RouteAdd will add a route to the system.
// Equivalent to: `ip route add $route`
func RouteAdd(s *NetlinkSocket, route *Route) error {
	req := NewNetlinkRequest(syscall.RTM_NEWROUTE, syscall.NLM_F_CREATE|syscall.NLM_F_EXCL|syscall.NLM_F_ACK)
	return routeHandle(s, route, req)
}

// RouteAdd will delete a route from the system.
// Equivalent to: `ip route del $route`
func RouteDel(s *NetlinkSocket, route *Route) error {
	req := NewNetlinkRequest(syscall.RTM_DELROUTE, syscall.NLM_F_ACK)
	return routeHandle(s, route, req)
}

func routeHandle(s *NetlinkSocket, route *Route, req *NetlinkRequest) error {
	if (route.Dst == nil || route.Dst.IP == nil) && route.Src == nil && route.Gw == nil {
		return fmt.Errorf("one of Dst.IP, Src, or Gw must not be nil")
	}

	msg := NewRtMsg()
	msg.Scope = uint8(route.Scope)
	family := -1
	var rtAttrs []*RtAttr
	// address
	if route.Dst != nil && route.Dst.IP != nil {
		dstLen, _ := route.Dst.Mask.Size()
		msg.Dst_len = uint8(dstLen)
		dstFamily := GetIPFamily(route.Dst.IP)
		family = dstFamily
		var dstData []byte
		if dstFamily == FAMILY_V4 {
			dstData = route.Dst.IP.To4()
		} else {
			dstData = route.Dst.IP.To16()
		}
		rtAttrs = append(rtAttrs, NewRtAttr(syscall.RTA_DST, dstData))
	}
	// src : source address to prefer
	if route.Src != nil {
		srcFamily := GetIPFamily(route.Src)
		if family != -1 && family != srcFamily {
			return fmt.Errorf("source and destination ip are not the same IP family")
		}
		family = srcFamily
		var srcData []byte
		if srcFamily == FAMILY_V4 {
			srcData = route.Src.To4()
		} else {
			srcData = route.Src.To16()
		}
		// The commonly used src ip for routes is actually PREFSRC
		rtAttrs = append(rtAttrs, NewRtAttr(syscall.RTA_PREFSRC, srcData))
	}
	// via
	if route.Gw != nil {
		gwFamily := GetIPFamily(route.Gw)
		if family != -1 && family != gwFamily {
			return fmt.Errorf("gateway, source, and destination ip are not the same IP family")
		}
		family = gwFamily
		var gwData []byte
		if gwFamily == FAMILY_V4 {
			gwData = route.Gw.To4()
		} else {
			gwData = route.Gw.To16()
		}
		rtAttrs = append(rtAttrs, NewRtAttr(syscall.RTA_GATEWAY, gwData))
	}
	// metric
	rtAttrs = append(rtAttrs, NewRtAttr(syscall.RTA_PRIORITY, Uint32Attr(route.Metric)))

	msg.Family = uint8(family)

	req.AddData(msg)
	for _, attr := range rtAttrs {
		req.AddData(attr)
	}
	req.AddData(NewRtAttr(syscall.RTA_OIF, Uint32Attr(uint32(route.LinkIndex))))

	_, err := req.Execute(s, 0)
	return err
}

// RouteGet gets a route to a specific destination from the host system.
// Equivalent to: 'ip route show match <addr>'.
func RouteGet(s *NetlinkSocket, destination net.IP) ([]Route, error) {
	req := NewNetlinkRequest(syscall.RTM_GETROUTE, syscall.NLM_F_ROOT)
	family := GetIPFamily(destination)
	var destinationData []byte
	var bitlen uint8
	if family == FAMILY_V4 {
		destinationData = destination.To4()
		bitlen = 32
	} else {
		destinationData = destination.To16()
		bitlen = 128
	}
	msg := &RtMsg{}
	msg.Family = uint8(family)
	msg.Dst_len = bitlen
	// msg.Flags |= syscall.RTM_F_CLONED
	req.AddData(msg)

	rtaDst := NewRtAttr(syscall.RTA_DST, destinationData)
	req.AddData(rtaDst)

	msgs, err := req.Execute(s, syscall.RTM_NEWROUTE)
	if err != nil {
		return nil, err
	}

	native := NativeEndian()
	res := make([]Route, 0)
	for _, m := range msgs {
		msg := DeserializeRtMsg(m)
		attrs, err := ParseRouteAttr(m[msg.Len():])
		if err != nil {
			return nil, err
		}

		var table uint32
		route := Route{}
		for _, attr := range attrs {
			switch attr.Attr.Type {
			case syscall.RTA_TABLE:
				table = native.Uint32(attr.Value[0:4])
			case syscall.RTA_GATEWAY:
				route.Gw = net.IP(attr.Value)
			case syscall.RTA_PREFSRC:
				route.Src = net.IP(attr.Value)
			case syscall.RTA_DST:
				route.Dst = &net.IPNet{
					IP:   attr.Value,
					Mask: net.CIDRMask(int(msg.Dst_len), 8*len(attr.Value)),
				}
			case syscall.RTA_OIF:
				routeIndex := int(native.Uint32(attr.Value[0:4]))
				route.LinkIndex = routeIndex
			case syscall.RTA_PRIORITY:
				route.Metric = native.Uint32(attr.Value[0:4])
			default:
				fmt.Printf("unknown attr %v\n", attr.Attr.Type)
			}
		}
		if table == syscall.RT_TABLE_MAIN {
			res = append(res, route)
		}
	}
	return res, nil

}
