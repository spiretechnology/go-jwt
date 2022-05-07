package jwt

// Header is the header to the JWT token. With the current implementation, the
// header is always the same: HS256 and JWT.
type Header struct {
	Alg string `json:"alg"`
	Typ string `json:"typ"`
}
