package netlink

import (
	"fmt"
	"net"
	"syscall"
)

// Proto is an enum representing an ipsec protocol.
type Proto uint8

const (
	XFRM_PROTO_ROUTE2    Proto = syscall.IPPROTO_ROUTING
	XFRM_PROTO_ESP       Proto = syscall.IPPROTO_ESP
	XFRM_PROTO_AH        Proto = syscall.IPPROTO_AH
	XFRM_PROTO_HAO       Proto = syscall.IPPROTO_DSTOPTS
	XFRM_PROTO_COMP      Proto = syscall.IPPROTO_COMP
	XFRM_PROTO_IPSEC_ANY Proto = syscall.IPPROTO_RAW
)

func (p Proto) String() string {
	switch p {
	case XFRM_PROTO_ROUTE2:
		return "route2"
	case XFRM_PROTO_ESP:
		return "esp"
	case XFRM_PROTO_AH:
		return "ah"
	case XFRM_PROTO_HAO:
		return "hao"
	case XFRM_PROTO_COMP:
		return "comp"
	case XFRM_PROTO_IPSEC_ANY:
		return "ipsec-any"
	}
	return fmt.Sprintf("%d", p)
}

// Mode is an enum representing an ipsec transport.
type Mode uint8

const (
	XFRM_MODE_TRANSPORT Mode = iota
	XFRM_MODE_TUNNEL
	XFRM_MODE_ROUTEOPTIMIZATION
	XFRM_MODE_IN_TRIGGER
	XFRM_MODE_BEET
	XFRM_MODE_MAX
)

func (m Mode) String() string {
	switch m {
	case XFRM_MODE_TRANSPORT:
		return "transport"
	case XFRM_MODE_TUNNEL:
		return "tunnel"
	case XFRM_MODE_ROUTEOPTIMIZATION:
		return "ro"
	case XFRM_MODE_IN_TRIGGER:
		return "in_trigger"
	case XFRM_MODE_BEET:
		return "beet"
	}
	return fmt.Sprintf("%d", m)
}

// Dir is an enum representing an ipsec template direction.
type Dir uint8

const (
	XFRM_DIR_IN Dir = iota
	XFRM_DIR_OUT
	XFRM_DIR_FWD
	XFRM_SOCKET_IN
	XFRM_SOCKET_OUT
	XFRM_SOCKET_FWD
)

func (d Dir) String() string {
	switch d {
	case XFRM_DIR_IN:
		return "dir in"
	case XFRM_DIR_OUT:
		return "dir out"
	case XFRM_DIR_FWD:
		return "dir fwd"
	case XFRM_SOCKET_IN:
		return "socket in"
	case XFRM_SOCKET_OUT:
		return "socket out"
	case XFRM_SOCKET_FWD:
		return "socket fwd"
	}
	return fmt.Sprintf("socket %d", d-XFRM_SOCKET_IN)
}

// XfrmPolicyTmpl encapsulates a rule for the base addresses of an ipsec
// policy. These rules are matched with XfrmState to determine encryption
// and authentication algorithms.
type XfrmPolicyTmpl struct {
	Dst   net.IP
	Src   net.IP
	Proto Proto
	Mode  Mode
	Reqid int
}

// XfrmPolicy represents an ipsec policy. It represents the overlay network
// and has a list of XfrmPolicyTmpls representing the base addresses of
// the policy.
type XfrmPolicy struct {
	Dst      *net.IPNet
	Src      *net.IPNet
	Dir      Dir
	Priority int
	Index    int
	Tmpls    []XfrmPolicyTmpl
}

// XfrmStateAlgo represents the algorithm to use for the ipsec encryption.
type XfrmStateAlgo struct {
	Name        string
	Key         []byte
	TruncateLen int // Auth only
}

// EncapType is an enum representing an ipsec template direction.
type EncapType uint8

const (
	XFRM_ENCAP_ESPINUDP_NONIKE EncapType = iota + 1
	XFRM_ENCAP_ESPINUDP
)

func (e EncapType) String() string {
	switch e {
	case XFRM_ENCAP_ESPINUDP_NONIKE:
		return "espinudp-nonike"
	case XFRM_ENCAP_ESPINUDP:
		return "espinudp"
	}
	return "unknown"
}

// XfrmEncap represents the encapsulation to use for the ipsec encryption.
type XfrmStateEncap struct {
	Type            EncapType
	SrcPort         int
	DstPort         int
	OriginalAddress net.IP
}

// XfrmState represents the state of an ipsec policy. It optionally
// contains an XfrmStateAlgo for encryption and one for authentication.
type XfrmState struct {
	Sel          *XfrmSelector
	Dst          net.IP
	Src          net.IP
	Proto        Proto
	Mode         Mode
	Spi          int
	Reqid        int
	ReplayWindow int
	Flags        uint8
	Auth         *XfrmStateAlgo
	Crypt        *XfrmStateAlgo
	Aead         *XfrmStateAlgo
	Encap        *XfrmStateEncap
}
