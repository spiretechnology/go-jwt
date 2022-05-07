package jwt

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"fmt"
)

func ES256Signer(kid string, privateKey *ecdsa.PrivateKey) Signer {
	return ecdsaSigner(kid, crypto.SHA256, privateKey)
}

func ES384Signer(kid string, privateKey *ecdsa.PrivateKey) Signer {
	return ecdsaSigner(kid, crypto.SHA384, privateKey)
}

func ES512Signer(kid string, privateKey *ecdsa.PrivateKey) Signer {
	return ecdsaSigner(kid, crypto.SHA512, privateKey)
}

func ecdsaSigner(kid string, hash crypto.Hash, privateKey *ecdsa.PrivateKey) Signer {
	return signerFunc(fmt.Sprintf("ES%d", hash.Size()<<3), kid, func(data []byte) ([]byte, error) {
		return signECDSA(data, privateKey, hash)
	})
}

func signECDSA(data []byte, privateKey *ecdsa.PrivateKey, hash crypto.Hash) ([]byte, error) {

	// Compute the hash of the input data
	hasher := hash.New()
	hasher.Reset()
	hasher.Write(data)
	digest := hasher.Sum(nil)

	// Sign the digest with the private key
	return ecdsa.SignASN1(rand.Reader, privateKey, digest)

}
