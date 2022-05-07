package jwt

import (
	"crypto"
	"crypto/rsa"
	"errors"
	"fmt"
)

func PS256Verifier(publicKey *rsa.PublicKey) Verifier {
	return rsaPssVerifier(crypto.SHA256, publicKey)
}

func PS384Verifier(publicKey *rsa.PublicKey) Verifier {
	return rsaPssVerifier(crypto.SHA384, publicKey)
}

func PS512Verifier(publicKey *rsa.PublicKey) Verifier {
	return rsaPssVerifier(crypto.SHA512, publicKey)
}

func rsaPssVerifier(hash crypto.Hash, publicKey *rsa.PublicKey) Verifier {
	return verifierFunc(fmt.Sprintf("PS%d", hash.Size()<<3), func(data, signature []byte) (bool, error) {
		return verifyRSAPSS(data, signature, publicKey, hash)
	})
}

func verifyRSAPSS(data, signature []byte, publicKey *rsa.PublicKey, hash crypto.Hash) (bool, error) {

	// Compute the hash of the input data
	hasher := hash.New()
	hasher.Reset()
	hasher.Write(data)
	digest := hasher.Sum(nil)

	// Verify the signature
	if err := rsa.VerifyPSS(publicKey, hash, digest, signature, nil); err != nil {
		if errors.Is(err, rsa.ErrVerification) {
			return false, nil
		}
		return false, err
	}
	return true, nil

}
