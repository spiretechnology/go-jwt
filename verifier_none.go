package jwt

func NoneVerifier() Verifier {
	return verifierFunc(None, func(data []byte, signature []byte) (bool, error) {
		return len(signature) == 0, nil
	})
}
