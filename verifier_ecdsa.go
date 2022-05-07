package jwt

import (
	"crypto"
	"crypto/ecdsa"
	"fmt"
)

func ES256Verifier(publicKey *ecdsa.PublicKey) Verifier {
	return ecdsaVerifier(crypto.SHA256, publicKey)
}

func ES384Verifier(publicKey *ecdsa.PublicKey) Verifier {
	return ecdsaVerifier(crypto.SHA384, publicKey)
}

func ES512Verifier(publicKey *ecdsa.PublicKey) Verifier {
	return ecdsaVerifier(crypto.SHA512, publicKey)
}

func ecdsaVerifier(hash crypto.Hash, publicKey *ecdsa.PublicKey) Verifier {
	return verifierFunc(fmt.Sprintf("ES%d", hash.Size()<<3), func(data, signature []byte) (bool, error) {
		return verifyECDSA(data, signature, publicKey, hash)
	})
}

func verifyECDSA(data, signature []byte, publicKey *ecdsa.PublicKey, hash crypto.Hash) (bool, error) {

	// Compute the hash of the input data
	hasher := hash.New()
	hasher.Reset()
	hasher.Write(data)
	digest := hasher.Sum(nil)

	// Verify the signature
	return ecdsa.VerifyASN1(publicKey, digest, signature), nil

}
