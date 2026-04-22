package peers

type Peer struct {
	PublicKey    string `json:"public_key_base64"`
	PresharedKey string `json:"preshared_key_base64"` // optional
	UserUUID     string `json:"owner"`
	Endpoint     string `json:"endpoint"`
	IsEnabled    bool   `json:"is_enabled"`
}
