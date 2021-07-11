package jwt

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
)

var (
	ErrMalformedJwtTokenString  = errors.New("malformed JWT token string")
	ErrInvalidJwtTokenSignature = errors.New("invalid JWT token signature")
)

// Claims is a type alias that represents the payload data included
// in a JWT token
type Claims interface{}

// Header is the header to the JWT token. With the current implementation, the
// header is always the same: HS256 and JWT.
type Header struct {
	Alg string `json:"alg"`
	Typ string `json:"typ"`
}

// Token represents a new or a parsed JWT token
type Token struct {
	header    Header
	claims    Claims
	parsedCtx *parsedTokenContext
}

// New constructs a new token with a set of claims
func New(claims Claims) (*Token, error) {

	// Create the token instance
	token := Token{
		header: Header{
			Alg: "HS256",
			Typ: "JWT",
		},
		claims:    claims,
		parsedCtx: nil,
	}

	// Get the header JSON string
	headerJSON, err := json.Marshal(token.header)
	if err != nil {
		return nil, err
	}

	// Get the claims JSON string
	claimsJSON, err := json.Marshal(token.claims)
	if err != nil {
		return nil, err
	}

	// Create the parsed token context
	token.parsedCtx = &parsedTokenContext{
		HeaderBase64: base64.URLEncoding.EncodeToString(headerJSON),
		ClaimsBase64: base64.URLEncoding.EncodeToString(claimsJSON),
	}

	// Return the token
	return &token, nil

}

// Parse parses a JWT string into a token instance
func Parse(str string) (*Token, error) {

	// Split up the string into three parts
	parts := strings.Split(str, ".")
	if len(parts) != 3 {
		return nil, ErrMalformedJwtTokenString
	}

	// Decode the header from base64
	headerJSON, err := base64.URLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, err
	}

	// Create the token instance
	token := Token{
		header: Header{},
		claims: nil,
		parsedCtx: &parsedTokenContext{
			HeaderBase64:    parts[0],
			ClaimsBase64:    parts[1],
			SignatureBase64: parts[2],
		},
	}

	// Unmarshal the header into the token
	if err := json.Unmarshal(headerJSON, &token.header); err != nil {
		return nil, err
	}

	// Return the token instance
	return &token, nil

}

// SignedString formats the JWT token as a string, signed by the secret provided. For best security,
// the secret should be 256 bits.
func (t *Token) SignedString(secret []byte) string {

	// Return the combined parts
	return strings.Join([]string{
		t.parsedCtx.HeaderBase64,
		t.parsedCtx.ClaimsBase64,
		t.parsedCtx.Sign(secret),
	}, ".")

}

// Claims unmarshals the token claims into the provided destination.
func (t *Token) Claims(claims interface{}) error {

	// Decode the claims from base64
	claimsJSON, err := base64.URLEncoding.DecodeString(t.parsedCtx.ClaimsBase64)
	if err != nil {
		return err
	}

	// Unmarshal the JSON into the destination
	return json.Unmarshal(claimsJSON, claims)

}

// Verify verifies the token signature against a secret key
func (t *Token) Verify(secret []byte) bool {
	return t.parsedCtx.Verify(secret)
}
