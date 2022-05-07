package jwt

func NoneSigner() Signer {
	return signerFunc(None, func(data []byte) ([]byte, error) {
		return []byte{}, nil
	})
}
