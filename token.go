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
	ErrCannotUnmarshalJwtClaims = errors.New("cannot unmarshal claims from newly created token")
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
func New(claims Claims) *Token {
	return &Token{
		header: Header{
			Alg: "HS256",
			Typ: "JWT",
		},
		claims:    claims,
		parsedCtx: nil,
	}
}

// ParseAndVerify parses AND verifies a JWT token string using the provided secret.
// If the signature is invalid, the parsed token will still be returned, but an error
// will also be returned. If some other kind of error occurs than simply a verification
// error, nil will be returned in the place of the token.
func ParseAndVerify(
	str string,
	secret []byte,
) (*Token, error) {

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

	// If there is a secret provided, and it's invalid
	if secret != nil && !token.parsedCtx.Verify(secret) {
		return &token, ErrInvalidJwtTokenSignature
	}

	// Return the token instance
	return &token, nil

}

// Parse parses and does NOT verify a JWT token string
func Parse(str string) (*Token, error) {
	return ParseAndVerify(str, nil)
}

// SignedString formats the JWT token as a string, signed by the secret provided. For best security,
// the secret should be 256 bits.
func (t *Token) SignedString(secret []byte) (string, error) {

	// Get the header JSON string
	header, err := json.Marshal(t.header)
	if err != nil {
		return "", err
	}

	// Get the claims JSON string
	claims, err := json.Marshal(t.claims)
	if err != nil {
		return "", err
	}

	// Create the parsed token context
	ctx := parsedTokenContext{
		HeaderBase64: base64.URLEncoding.EncodeToString(header),
		ClaimsBase64: base64.URLEncoding.EncodeToString(claims),
	}

	// Return the combined parts
	return strings.Join([]string{
		ctx.HeaderBase64,
		ctx.ClaimsBase64,
		ctx.Sign(secret),
	}, "."), nil

}

// Claims unmarshals the token claims into the provided destination.
func (t *Token) Claims(claims interface{}) error {

	// If there is no parsed context
	if t.parsedCtx == nil {
		return ErrCannotUnmarshalJwtClaims
	}

	// Decode the claims from base64
	claimsJSON, err := base64.URLEncoding.DecodeString(t.parsedCtx.ClaimsBase64)
	if err != nil {
		return err
	}

	// Unmarshal the JSON into the destination
	return json.Unmarshal(claimsJSON, claims)
}
