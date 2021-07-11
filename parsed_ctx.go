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

	// Calculate the signature
	hmacSha256 := hmac.New(sha256.New, secret)
	signature := hmacSha256.Sum([]byte(ctx.HeaderBase64 + "." + ctx.ClaimsBase64))
	signatureBase64 := base64.URLEncoding.EncodeToString(signature)

	// Return the signature
	return signatureBase64

}

func (ctx *parsedTokenContext) Verify(secret []byte) bool {

	// Calculate the signature
	return ctx.SignatureBase64 == ctx.Sign(secret)

}
