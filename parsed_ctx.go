package jwt

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
)

type parsedTokenContext struct {
	HeaderBase64    string
	ClaimsBase64    string
	SignatureBase64 string
}

func (ctx *parsedTokenContext) Sign(secret []byte) string {

	// Convert the secret to a base64 buffer
	secretBytes := make([]byte, base64.RawURLEncoding.EncodedLen(len(secret)))
	base64.RawURLEncoding.Encode(secretBytes, secret)

	// Calculate the signature
	hmacSha256 := hmac.New(sha256.New, secret)
	hmacSha256.Write([]byte(ctx.HeaderBase64 + "." + ctx.ClaimsBase64))
	signature := hmacSha256.Sum(nil)

	// Return the signature as a base64 encoded string
	return base64.RawURLEncoding.EncodeToString(signature)

}

func (ctx *parsedTokenContext) Verify(secret []byte) bool {

	// Calculate the signature
	return ctx.SignatureBase64 == ctx.Sign(secret)

}
