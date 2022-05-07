package jwt

type Verifier interface {
	Alg() string
	Verify(data, signature []byte) (bool, error)
}

type implVerifier struct {
	alg        string
	verifyFunc func(data, signature []byte) (bool, error)
}

func (s *implVerifier) Alg() string {
	return s.alg
}

func (s *implVerifier) Verify(data, signature []byte) (bool, error) {
	return s.verifyFunc(data, signature)
}

func verifierFunc(alg string, fn func(data, signature []byte) (bool, error)) Verifier {
	return &implVerifier{
		alg:        alg,
		verifyFunc: fn,
	}
}
