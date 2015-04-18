package netlink

import "net"

// Scope is an enum representing a route scope.
type Scope uint8

// Route represents a netlink route. A route is associated with a link,
// has a destination network, an optional source ip, and optional
// gateway. Advanced route parameters and non-main routing tables are
// currently not supported.
type Route struct {
	LinkIndex int
	Scope     Scope
	Dst       *net.IPNet
	Src       net.IP
	Gw        net.IP
	Metric    uint32
}
