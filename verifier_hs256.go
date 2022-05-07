package jwt

import (
	"bytes"
)

func HS256Verifier(secret []byte) Verifier {
	return verifierFunc("HS256", func(data []byte, signature []byte) (bool, error) {
		expectedSignature := signHS256(data, secret)
		return bytes.Equal(signature, expectedSignature), nil
	})
}
