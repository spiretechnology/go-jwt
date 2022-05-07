package jwt

func NoneSigner() Signer {
	return signerFunc("none", func(data []byte) ([]byte, error) {
		return []byte{}, nil
	})
}
