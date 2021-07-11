package jwt

import (
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
	token, err := New(testClaims{
		Name: "John Smith",
		Age:  10,
	})
	if err != nil {
		t.Error(err)
	}

	// Create the signed string for the token
	tokenStr := token.SignedString(Secret1)

	// Parse the token
	parsedToken, err := Parse(tokenStr)
	if err != nil {
		t.Error(err)
	}
	if !parsedToken.Verify(Secret1) {
		t.Fatal("Failed to validate parsed token using original secret")
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

	// Parse the token string
	badParsedToken, err := Parse(tokenStr)
	if err != nil {
		t.Error(err)
	}

	// Validate the token against an invalid secret string
	if badParsedToken.Verify(Secret2) {
		t.Fatal("Verification passed for invalid secret key")
	}

}
