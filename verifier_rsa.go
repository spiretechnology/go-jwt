package jwt

import (
	"crypto"
	"crypto/rsa"
	"errors"
	"fmt"
)

func RS256Verifier(publicKey *rsa.PublicKey) Verifier {
	return rsaVerifier(crypto.SHA256, publicKey)
}

func rsaVerifier(hash crypto.Hash, publicKey *rsa.PublicKey) Verifier {
	return verifierFunc(fmt.Sprintf("RS%d", hash.Size()<<3), func(data, signature []byte) (bool, error) {
		return verifyRSA(data, signature, publicKey, hash)
	})
}

func verifyRSA(data, signature []byte, publicKey *rsa.PublicKey, hash crypto.Hash) (bool, error) {

	// Compute the hash of the input data
	hasher := hash.New()
	hasher.Reset()
	hasher.Write(data)
	digest := hasher.Sum(nil)

	// Verify the signature
	if err := rsa.VerifyPKCS1v15(publicKey, hash, digest, signature); err != nil {
		if errors.Is(err, rsa.ErrVerification) {
			return false, nil
		}
		return false, err
	}
	return true, nil

}
