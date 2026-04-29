package peers

type Peer struct {
	PublicKey    string `json:"public_key_base64"`
	PresharedKey string `json:"preshared_key_base64"` // optional
	UserUUID     string `json:"owner"`
	Endpoint     string `json:"endpoint"`
	IsEnabled    bool   `json:"is_enabled"`
}

func (peer *Peer) ShortenPublicKey() string {
	if len(peer.PublicKey) != 44 {
		// ???
		return peer.PublicKey
	}
	return peer.PublicKey[0:4] + "…" + peer.PublicKey[39:43]
}
