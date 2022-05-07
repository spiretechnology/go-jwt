package jwt_test

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/spiretechnology/go-jwt"
	"github.com/stretchr/testify/assert"
)

type testClaims struct {
	Name string `json:"name"`
	Age  int    `json:"age"`
}

var (
	Secret1 = []byte("0eff92br0ifyg09oji2brpwokweihfbs")
	Secret2 = []byte("hgor39rhr02jyrbwpoejriwhbefnxp4g")
)

func TestToken(t *testing.T) {

	t.Run("create and parse valid token", func(t *testing.T) {

		// Create a new token
		token, err := jwt.Create(
			testClaims{
				Name: "John Smith",
				Age:  36,
			},
			jwt.HS256Signer(Secret1),
		)
		assert.NoError(t, err, "error creating token")
		assert.Equal(t, "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJuYW1lIjoiSm9obiBTbWl0aCIsImFnZSI6MzZ9.kM_p4cZCFlLDjqfTXcriO5J2v9fjomdZP0Ki3Ya0_xg", token, "incorrect signed token string")

		// Parse the token
		parsed, err := jwt.Parse(token)
		assert.NoError(t, err, "error parsing token")
		assert.NotNil(t, parsed, "parsed token is nil")
		assert.Equal(t, "HS256", parsed.Header().Alg, "incorrect alg in parsed token")
		assert.Equal(t, "JWT", parsed.Header().Typ)

		// Unmarshal the claims from the token
		var claims testClaims
		err = parsed.Claims(&claims)
		assert.NoError(t, err, "error unmarshalling parsed token claims")
		assert.Equal(t, "John Smith", claims.Name)
		assert.Equal(t, 36, claims.Age)

		// Verify the token
		ok, err := parsed.Verify(jwt.HS256Verifier(Secret1))
		assert.NoError(t, err, "error verifying token signature")
		assert.True(t, ok, "signature verify returned false")

	})

	t.Run("verify token with incorrect signature", func(t *testing.T) {

		// Create a new token
		token, _ := jwt.Create(
			testClaims{
				Name: "John Smith",
				Age:  36,
			},
			jwt.HS256Signer(Secret1),
		)

		// Parse the token
		parsed, err := jwt.Parse(token)
		assert.NoError(t, err, "error parsing token")
		assert.NotNil(t, parsed, "parsed token is nil")
		assert.Equal(t, "HS256", parsed.Header().Alg, "incorrect alg in parsed token")
		assert.Equal(t, "JWT", parsed.Header().Typ)

		// Verify the token using an invalid secret
		ok, err := parsed.Verify(jwt.HS256Verifier(Secret2))
		assert.NoError(t, err, "error verifying token signature")
		assert.False(t, ok, "signature verify returned true for incorrect secret")

	})

	t.Run("verify should reject hijacked token", func(t *testing.T) {

		// Create a new token
		token, _ := jwt.Create(
			testClaims{
				Name: "John Smith",
				Age:  36,
			},
			jwt.HS256Signer(Secret1),
		)

		// Edit the claims without re-signing
		hijackedToken := spliceClaims(token, testClaims{
			Name: "Jimmy Neutron",
			Age:  14,
		})

		// Parse the hijacked token
		parsed, err := jwt.Parse(hijackedToken)
		assert.NoError(t, err, "error parsing token")
		assert.NotNil(t, parsed, "parsed token is nil")
		assert.Equal(t, "HS256", parsed.Header().Alg, "incorrect alg in parsed token")
		assert.Equal(t, "JWT", parsed.Header().Typ)

		// Unmarshal the claims from the hijacked token. The claims should still be unmarshalled
		// correctly, even though they were changed by a man-in-the-middle attack.
		var claims testClaims
		err = parsed.Claims(&claims)
		assert.NoError(t, err, "error unmarshalling parsed token claims")
		assert.Equal(t, "Jimmy Neutron", claims.Name)
		assert.Equal(t, 14, claims.Age)

		// Verify the token using an invalid secret. This should fail, even though the secret is the same.
		ok, err := parsed.Verify(jwt.HS256Verifier(Secret1))
		assert.NoError(t, err, "error verifying token signature")
		assert.False(t, ok, "signature verify returned true for hijacked token")

	})

	t.Run("signature - none", func(t *testing.T) {

		// Create a new token
		token, _ := jwt.Create(
			testClaims{
				Name: "John Smith",
				Age:  36,
			},
			jwt.NoneSigner(),
		)

		// The none signature type will result in a token with a trailing . and no signature string
		assert.True(t, strings.HasSuffix(token, "."), "none signature type token should end with \".\"")

		// Parse the token
		parsed, err := jwt.Parse(token)
		assert.NoError(t, err, "error parsing token")
		assert.NotNil(t, parsed, "parsed token is nil")
		assert.Equal(t, "none", parsed.Header().Alg, "incorrect alg in parsed token")
		assert.Equal(t, "JWT", parsed.Header().Typ)

		// Verify the token
		ok, err := parsed.Verify(jwt.NoneVerifier())
		assert.NoError(t, err, "error verifying token signature")
		assert.True(t, ok, "signature verify failed for none type")

	})

	type algRsa struct {
		alg      string
		signer   func(*rsa.PrivateKey) jwt.Signer
		verifier func(*rsa.PublicKey) jwt.Verifier
	}

	rsaAlgs := []algRsa{
		{
			alg:      "RS256",
			signer:   jwt.RS256Signer,
			verifier: jwt.RS256Verifier,
		},
		{
			alg:      "RS384",
			signer:   jwt.RS384Signer,
			verifier: jwt.RS384Verifier,
		},
		{
			alg:      "RS512",
			signer:   jwt.RS512Signer,
			verifier: jwt.RS512Verifier,
		},
	}

	for _, tc := range rsaAlgs {

		t.Run(fmt.Sprintf("sign and verify valid %s signatures", tc.alg), func(t *testing.T) {

			// Generate an RSA keypair
			privKey, _ := rsa.GenerateKey(rand.Reader, 2048)
			pubKey := &privKey.PublicKey

			// Create a new token
			token, err := jwt.Create(
				testClaims{
					Name: "John Smith",
					Age:  36,
				},
				tc.signer(privKey),
			)
			assert.NoError(t, err, "error creating token")
			assert.NotEmpty(t, token, "token using %s signature should not be empty", tc.alg)

			// Parse the token
			parsed, err := jwt.Parse(token)
			assert.NoError(t, err, "error parsing token")
			assert.NotNil(t, parsed, "parsed token is nil")
			assert.Equal(t, tc.alg, parsed.Header().Alg, "incorrect alg in parsed token")
			assert.Equal(t, "JWT", parsed.Header().Typ)

			// Verify the token
			ok, err := parsed.Verify(tc.verifier(pubKey))
			assert.NoError(t, err, "error verifying token signature")
			assert.True(t, ok, "signature verify failed for %s type", tc.alg)

		})

		t.Run(fmt.Sprintf("sign and verify invalid %s signatures", tc.alg), func(t *testing.T) {

			// Generate an RSA keypair
			privKey, _ := rsa.GenerateKey(rand.Reader, 2048)

			// Create a new token
			token, err := jwt.Create(
				testClaims{
					Name: "John Smith",
					Age:  36,
				},
				tc.signer(privKey),
			)
			assert.NoError(t, err, "error creating token")
			assert.NotEmpty(t, token, "token using %s signature should not be empty", tc.alg)

			// Parse the token
			parsed, err := jwt.Parse(token)
			assert.NoError(t, err, "error parsing token")
			assert.NotNil(t, parsed, "parsed token is nil")
			assert.Equal(t, tc.alg, parsed.Header().Alg, "incorrect alg in parsed token")
			assert.Equal(t, "JWT", parsed.Header().Typ)

			// Generate another keypair for verification
			invalidPrivKey, _ := rsa.GenerateKey(rand.Reader, 2018)
			invalidPubKey := &invalidPrivKey.PublicKey

			// Verify the token
			ok, err := parsed.Verify(tc.verifier(invalidPubKey))
			assert.NoError(t, err, "error verifying token signature")
			assert.False(t, ok, "signature verify should have failed for invalid %s pubkey", tc.alg)

		})

	}

}

func spliceClaims(token string, newClaims any) string {
	parts := strings.Split(token, ".")
	jsonBytes, _ := json.Marshal(newClaims)
	parts[1] = base64.RawURLEncoding.EncodeToString(jsonBytes)
	return strings.Join(parts, ".")
}
