package jwt

type Signer interface {
	Alg() string
	Sign(data []byte) ([]byte, error)
}

type implSigner struct {
	alg      string
	signFunc func(data []byte) ([]byte, error)
}

func (s *implSigner) Alg() string {
	return s.alg
}

func (s *implSigner) Sign(data []byte) ([]byte, error) {
	return s.signFunc(data)
}

func signerFunc(alg string, fn func(data []byte) ([]byte, error)) Signer {
	return &implSigner{
		alg:      alg,
		signFunc: fn,
	}
}
