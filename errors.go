package jwt

import "errors"

var (
	ErrMalformedJwtTokenString  = errors.New("malformed JWT token string")
	ErrSignatureAlgMismatch     = errors.New("mismatched JWT token signature algorithm")
	ErrInvalidJwtTokenSignature = errors.New("invalid JWT token signature")
)
