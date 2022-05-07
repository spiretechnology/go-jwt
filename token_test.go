package jwt_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/spiretechnology/go-jwt/v2"
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

	type algHs struct {
		alg      string
		signer   func([]byte) jwt.Signer
		verifier func([]byte) jwt.Verifier
	}

	hsAlgs := []algHs{
		{
			alg:      "HS256",
			signer:   jwt.HS256Signer,
			verifier: jwt.HS256Verifier,
		},
		{
			alg:      "HS384",
			signer:   jwt.HS384Signer,
			verifier: jwt.HS384Verifier,
		},
		{
			alg:      "HS512",
			signer:   jwt.HS512Signer,
			verifier: jwt.HS512Verifier,
		},
	}

	for _, tc := range hsAlgs {

		t.Run(fmt.Sprintf("%s - create and parse valid token", tc.alg), func(t *testing.T) {

			// Create a new token
			token, err := jwt.Create(
				testClaims{
					Name: "John Smith",
					Age:  36,
				},
				tc.signer(Secret1),
			)
			assert.NoError(t, err, "error creating token")

			// Parse the token
			parsed, err := jwt.Parse(token)
			assert.NoError(t, err, "error parsing token")
			assert.NotNil(t, parsed, "parsed token is nil")
			assert.Equal(t, tc.alg, parsed.Header().Alg, "incorrect alg in parsed token")
			assert.Equal(t, "JWT", parsed.Header().Typ)

			// Unmarshal the claims from the token
			var claims testClaims
			err = parsed.Claims(&claims)
			assert.NoError(t, err, "error unmarshalling parsed token claims")
			assert.Equal(t, "John Smith", claims.Name)
			assert.Equal(t, 36, claims.Age)

			// Verify the token
			ok, err := parsed.Verify(tc.verifier(Secret1))
			assert.NoError(t, err, "error verifying token signature")
			assert.True(t, ok, "signature verify returned false")

		})

		t.Run(fmt.Sprintf("%s - verify token with incorrect signature", tc.alg), func(t *testing.T) {

			// Create a new token
			token, _ := jwt.Create(
				testClaims{
					Name: "John Smith",
					Age:  36,
				},
				tc.signer(Secret1),
			)

			// Parse the token
			parsed, err := jwt.Parse(token)
			assert.NoError(t, err, "error parsing token")
			assert.NotNil(t, parsed, "parsed token is nil")
			assert.Equal(t, tc.alg, parsed.Header().Alg, "incorrect alg in parsed token")
			assert.Equal(t, "JWT", parsed.Header().Typ)

			// Verify the token using an invalid secret
			ok, err := parsed.Verify(tc.verifier(Secret2))
			assert.NoError(t, err, "error verifying token signature")
			assert.False(t, ok, "signature verify returned true for incorrect secret")

		})

		t.Run(fmt.Sprintf("%s - verify should reject hijacked token", tc.alg), func(t *testing.T) {

			// Create a new token
			token, _ := jwt.Create(
				testClaims{
					Name: "John Smith",
					Age:  36,
				},
				tc.signer(Secret1),
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
			assert.Equal(t, tc.alg, parsed.Header().Alg, "incorrect alg in parsed token")
			assert.Equal(t, "JWT", parsed.Header().Typ)

			// Unmarshal the claims from the hijacked token. The claims should still be unmarshalled
			// correctly, even though they were changed by a man-in-the-middle attack.
			var claims testClaims
			err = parsed.Claims(&claims)
			assert.NoError(t, err, "error unmarshalling parsed token claims")
			assert.Equal(t, "Jimmy Neutron", claims.Name)
			assert.Equal(t, 14, claims.Age)

			// Verify the token using an invalid secret. This should fail, even though the secret is the same.
			ok, err := parsed.Verify(tc.verifier(Secret1))
			assert.NoError(t, err, "error verifying token signature")
			assert.False(t, ok, "signature verify returned true for hijacked token")

		})

	}

	t.Run("none - sign and verify", func(t *testing.T) {

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
		{
			alg:      "PS256",
			signer:   jwt.PS256Signer,
			verifier: jwt.PS256Verifier,
		},
		{
			alg:      "PS384",
			signer:   jwt.PS384Signer,
			verifier: jwt.PS384Verifier,
		},
		{
			alg:      "PS512",
			signer:   jwt.PS512Signer,
			verifier: jwt.PS512Verifier,
		},
	}

	for _, tc := range rsaAlgs {

		t.Run(fmt.Sprintf("%s - sign and verify valid signatures", tc.alg), func(t *testing.T) {

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

		t.Run(fmt.Sprintf("%s - sign and verify invalid signatures", tc.alg), func(t *testing.T) {

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

	type algEcdsa struct {
		alg      string
		signer   func(*ecdsa.PrivateKey) jwt.Signer
		verifier func(*ecdsa.PublicKey) jwt.Verifier
	}

	ecdsaAlgs := []algEcdsa{
		{
			alg:      "ES256",
			signer:   jwt.ES256Signer,
			verifier: jwt.ES256Verifier,
		},
		{
			alg:      "ES384",
			signer:   jwt.ES384Signer,
			verifier: jwt.ES384Verifier,
		},
		{
			alg:      "ES512",
			signer:   jwt.ES512Signer,
			verifier: jwt.ES512Verifier,
		},
	}

	for _, tc := range ecdsaAlgs {

		t.Run(fmt.Sprintf("%s - sign and verify valid signatures", tc.alg), func(t *testing.T) {

			// Generate an RSA keypair
			privKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
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

		t.Run(fmt.Sprintf("%s - sign and verify invalid signatures", tc.alg), func(t *testing.T) {

			// Generate an RSA keypair
			privKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

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
			invalidPrivKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
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
