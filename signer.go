package jwt

// Signer defines the interface for signing a JWT token with a given algorithm.
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

// signerFunc is a utility for creating a Signer from a signature function.
func signerFunc(alg string, fn func(data []byte) ([]byte, error)) Signer {
	return &implSigner{
		alg:      alg,
		signFunc: fn,
	}
}
