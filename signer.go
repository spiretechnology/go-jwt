package jwt

type Signer interface {
	Alg() Alg
	Sign(data []byte) ([]byte, error)
}

type implSigner struct {
	alg      Alg
	signFunc func(data []byte) ([]byte, error)
}

func (s *implSigner) Alg() Alg {
	return s.alg
}

func (s *implSigner) Sign(data []byte) ([]byte, error) {
	return s.signFunc(data)
}

func signerFunc(alg Alg, fn func(data []byte) ([]byte, error)) Signer {
	return &implSigner{
		alg:      alg,
		signFunc: fn,
	}
}
