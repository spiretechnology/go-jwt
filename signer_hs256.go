package jwt

import (
	"crypto/hmac"
	"crypto/sha256"
)

func HS256Signer(secret []byte) Signer {
	return signerFunc(HS256, func(data []byte) ([]byte, error) {
		return signHS256(data, secret), nil
	})
}

func signHS256(data []byte, secret []byte) []byte {
	hmacSha256 := hmac.New(sha256.New, secret)
	hmacSha256.Write(data)
	return hmacSha256.Sum(nil)
}
