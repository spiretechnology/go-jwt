package jwt

// Header is the header to a JWT token.
type Header struct {
	Alg string `json:"alg"`
	Typ string `json:"typ"`
}
