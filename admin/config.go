package admin

type Config struct {
	BaseURI                    string
	HTTPBind                   string
	AuthPrivateKey             string
	LoginTokenLifetime         int
	RefreshTokenLifetime       int
	AccessTokenLifetime        int
	RequestKeyRotationInterval int
	DebugMode                  bool
}
