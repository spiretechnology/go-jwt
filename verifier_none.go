package jwt

func NoneVerifier() Verifier {
	return verifierFunc("none", func(data []byte, signature []byte) (bool, error) {
		return len(signature) == 0, nil
	})
}
