package peers

type Peer struct {
	PublicKey    string
	PresharedKey string // optional
	UserUUID     string
	Endpoint     string
	Enabled      bool
}
