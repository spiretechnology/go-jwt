package jwt

type Token interface {
	Header() *Header
	Claims(claims any) error
	Verify(verifier Verifier) (bool, error)
}
