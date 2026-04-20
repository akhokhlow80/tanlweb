package peers

import (
	"fmt"
	"strings"
)

type WGQuickConf struct {
	Interface struct {
		// set to a newly generated one only if no public key was provided in the request
		PrivateKey string `json:"private_key"`
		// CIDRs
		Addresses []string `json:"addresses"`
		// based on configuration (optional)
		DNS string `json:"dns"`
		// based on configuration (optional)
		MTU int `json:"mtu"`
	} `json:"interface"`
	NodePeer struct {
		PublicKey string `json:"public_key"`
		// optional; set only if preshared key was given, or random preshared key generation was requested
		PresharedKey string `json:"preshared_key"`
		Endpoint     string `json:"endpoint"`
		// based on configuration (optional)
		PersistentKeepalive int `json:"persistent_keepalive"`
	} `json:"node_peer"`
}

func (conf *WGQuickConf) String() {
	var sb strings.Builder

	sb.WriteString("[Interface]\n")
	if len(conf.Interface.PrivateKey) != 0 {
		fmt.Fprintf(&sb, "PrivateKey = %s\n", conf.Interface.PrivateKey)
	}
	fmt.Fprintf(&sb, "Address = %s\n", strings.Join(conf.Interface.Addresses, ", "))
	if len(conf.Interface.DNS) != 0 {
		fmt.Fprintf(&sb, "DNS = %s\n", conf.Interface.DNS)
	}
	if conf.Interface.MTU != 0 {
		fmt.Fprintf(&sb, "MTU = %d\n", conf.Interface.MTU)
	}
	sb.WriteRune('\n')

	sb.WriteString("[Peer]")
	fmt.Fprintf(&sb, "PublicKey = %s\n", conf.NodePeer.PublicKey)
	if len(conf.NodePeer.PresharedKey) != 0 {
		fmt.Fprintf(&sb, "PresharedKey = %s\n", conf.NodePeer.PresharedKey)
	}
	fmt.Fprintf(&sb, "Endpoint = %s\n", conf.NodePeer.Endpoint)
	if conf.NodePeer.PersistentKeepalive != 0 {
		fmt.Fprintf(&sb, "PersistentKeepalive = %d\n", conf.NodePeer.PersistentKeepalive)
	}
}
