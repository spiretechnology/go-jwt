package jwt

import (
	"errors"
	"testing"
)

type testClaims struct {
	Name string `json:"name"`
	Age  uint   `json:"age"`
}

var (
	Secret1 = []byte("0eff92br0ifyg09oji2brpwokweihfbs")
	Secret2 = []byte("hgor39rhr02jyrbwpoejriwhbefnxp4g")
)

func TestToken(t *testing.T) {

	// Create a new token
	token := New(testClaims{
		Name: "John Smith",
		Age:  10,
	})

	// Create the signed string for the token
	tokenStr, err := token.SignedString(Secret1)
	if err != nil {
		t.Error(err)
	}

	// Parse the token
	parsedToken, err := ParseAndVerify(tokenStr, Secret1)
	if err != nil {
		t.Error(err)
	}

	// Unmarshal the claims
	var claims testClaims
	if err := parsedToken.Claims(&claims); err != nil {
		t.Error(err)
	}

	// Check that the claims are the same
	if claims.Age != 10 || claims.Name != "John Smith" {
		t.Fatal("Parsed claim is not identical to original claims")
	}

	// Parse the token string against an invalid secret string
	_, err = ParseAndVerify(tokenStr, Secret2)
	if err == nil {
		t.Fatal("ParseAndVerify reported true when false was expected")
	}
	if err != nil && !errors.Is(err, ErrInvalidJwtTokenSignature) {
		t.Error(err)
	}

}
