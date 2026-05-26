package peers

import "time"

type Peer struct {
	PublicKey       string     `json:"public_key_base64"`
	PresharedKey    string     `json:"preshared_key_base64"` // optional
	UserUUID        string     `json:"owner"`
	Endpoint        string     `json:"endpoint"` // optional
	IsEnabled       bool       `json:"is_enabled"`
	LatestHandshake *time.Time `json:"latest_handshake"` // optional
	LatestEndpoint  string     `json:"latest_endpoint"`  // optional
}

type TransStat struct {
	Tx int64
	Rx int64
}

func (peer *Peer) ShortenPublicKey() string {
	if len(peer.PublicKey) != 44 {
		// ???
		return peer.PublicKey
	}
	return peer.PublicKey[0:4] + "…" + peer.PublicKey[39:43]
}
