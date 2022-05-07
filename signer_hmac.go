package jwt

import (
	"crypto"
	"crypto/hmac"
	"fmt"
)

func HS256Signer(secret []byte) Signer {
	return hsSigner(crypto.SHA256, secret)
}

func HS384Signer(secret []byte) Signer {
	return hsSigner(crypto.SHA384, secret)
}

func HS512Signer(secret []byte) Signer {
	return hsSigner(crypto.SHA512, secret)
}

func hsSigner(hash crypto.Hash, secret []byte) Signer {
	return signerFunc(fmt.Sprintf("HS%d", hash.Size()<<3), func(data []byte) ([]byte, error) {
		return signHS(hash, data, secret), nil
	})
}

func signHS(hash crypto.Hash, data, secret []byte) []byte {
	hmacSha256 := hmac.New(hash.New, secret)
	hmacSha256.Write(data)
	return hmacSha256.Sum(nil)
}
