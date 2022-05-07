package jwt

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"fmt"
)

func PS256Signer(kid string, privateKey *rsa.PrivateKey) Signer {
	return rsaPssSigner(kid, crypto.SHA256, privateKey)
}

func PS384Signer(kid string, privateKey *rsa.PrivateKey) Signer {
	return rsaPssSigner(kid, crypto.SHA384, privateKey)
}

func PS512Signer(kid string, privateKey *rsa.PrivateKey) Signer {
	return rsaPssSigner(kid, crypto.SHA512, privateKey)
}

func rsaPssSigner(kid string, hash crypto.Hash, privateKey *rsa.PrivateKey) Signer {
	return signerFunc(fmt.Sprintf("PS%d", hash.Size()<<3), kid, func(data []byte) ([]byte, error) {
		return signRSAPSS(data, privateKey, hash)
	})
}

func signRSAPSS(data []byte, privateKey *rsa.PrivateKey, hash crypto.Hash) ([]byte, error) {

	// Compute the hash of the input data
	hasher := hash.New()
	hasher.Reset()
	hasher.Write(data)
	digest := hasher.Sum(nil)

	// Sign the digest with the private key
	return rsa.SignPSS(rand.Reader, privateKey, hash, digest, nil)

}
