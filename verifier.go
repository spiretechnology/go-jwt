package jwt

type Verifier interface {
	Alg() Alg
	Verify(data, signature []byte) (bool, error)
}

type implVerifier struct {
	alg        Alg
	verifyFunc func(data, signature []byte) (bool, error)
}

func (s *implVerifier) Alg() Alg {
	return s.alg
}

func (s *implVerifier) Verify(data, signature []byte) (bool, error) {
	return s.verifyFunc(data, signature)
}

func verifierFunc(alg Alg, fn func(data, signature []byte) (bool, error)) Verifier {
	return &implVerifier{
		alg:        alg,
		verifyFunc: fn,
	}
}
