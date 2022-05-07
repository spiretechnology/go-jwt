package jwt

import (
	"bytes"
	"crypto"
	"fmt"
)

func HS256Verifier(secret []byte) Verifier {
	return hsVerifier(crypto.SHA256, secret)
}

func HS384Verifier(secret []byte) Verifier {
	return hsVerifier(crypto.SHA384, secret)
}

func HS512Verifier(secret []byte) Verifier {
	return hsVerifier(crypto.SHA512, secret)
}

func hsVerifier(hash crypto.Hash, secret []byte) Verifier {
	return verifierFunc(fmt.Sprintf("HS%d", hash.Size()<<3), func(data []byte, signature []byte) (bool, error) {
		expectedSignature := signHS(hash, data, secret)
		return bytes.Equal(signature, expectedSignature), nil
	})
}
