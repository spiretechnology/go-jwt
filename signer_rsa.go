package jwt

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"fmt"
)

func RS256Signer(privateKey *rsa.PrivateKey) Signer {
	return rsaSigner(crypto.SHA256, privateKey)
}

func rsaSigner(hash crypto.Hash, privateKey *rsa.PrivateKey) Signer {
	return signerFunc(fmt.Sprintf("RS%d", hash.Size()<<3), func(data []byte) ([]byte, error) {
		return signRSA(data, privateKey, hash)
	})
}

func signRSA(data []byte, privateKey *rsa.PrivateKey, hash crypto.Hash) ([]byte, error) {

	// Compute the hash of the input data
	hasher := hash.New()
	hasher.Reset()
	hasher.Write(data)
	digest := hasher.Sum(nil)

	// Sign the digest with the private key
	return rsa.SignPKCS1v15(rand.Reader, privateKey, hash, digest)

}
