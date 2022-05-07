package jwt

import (
	"encoding/base64"
	"encoding/json"
	"strings"
)

// implToken represents a new or a parsed JWT token.
type implToken struct {
	header       Header
	headerBase64 string
	claims       []byte
	claimsBase64 string
	signature    []byte
}

func Parse(str string) (Token, error) {

	// Split up the string into three parts
	parts := strings.Split(str, ".")
	if len(parts) != 3 {
		return nil, ErrMalformedJwtTokenString
	}

	// Decode the header from base64
	headerJSON, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, err
	}
	var header Header
	if err := json.Unmarshal(headerJSON, &header); err != nil {
		return nil, err
	}

	// Decode the claims from base64
	claimsJSON, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, err
	}

	// Decode the signature from base64
	signature, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return nil, err
	}

	// Return the token
	return &implToken{
		header:       header,
		headerBase64: parts[0],
		claims:       claimsJSON,
		claimsBase64: parts[1],
		signature:    signature,
	}, nil

}

func (t *implToken) Header() *Header {
	return &t.header
}

func (t *implToken) Claims(claims any) error {
	return json.Unmarshal(t.claims, claims)
}

func (t *implToken) Verify(verifier Verifier) (bool, error) {
	if t.header.Alg != verifier.Alg() {
		return false, ErrSignatureAlgMismatch
	}
	return verifier.Verify([]byte(t.headerBase64+"."+t.claimsBase64), t.signature)
}
