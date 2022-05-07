package jwt

import (
	"encoding/base64"
	"encoding/json"
	"strings"
)

// Create creates a JWT token string from a set of claims and a Signer. An error is
// returned if something goes wrong in the JSON marshalling process for the claims,
// or in the signing process.
func Create(claims any, signer Signer) (string, error) {

	// Create the header and marshal to JSON bytes
	header := Header{
		Alg: signer.Alg(),
		Typ: "JWT",
		Kid: signer.Kid(),
	}
	headerBytes, err := json.Marshal(header)
	if err != nil {
		return "", err
	}

	// Marshal the claims to JSON bytes
	claimsBytes, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}

	// Encode the header and claims to base64 URL encoded
	headerBase64URL := base64.RawURLEncoding.EncodeToString(headerBytes)
	claimsBase64URL := base64.RawURLEncoding.EncodeToString(claimsBytes)

	// Sign the joined string of the two
	signatureBytes, err := signer.Sign([]byte(headerBase64URL + "." + claimsBase64URL))
	if err != nil {
		return "", err
	}
	signatureBase64URL := base64.RawURLEncoding.EncodeToString(signatureBytes)

	// Return the joined segments
	return strings.Join([]string{
		headerBase64URL,
		claimsBase64URL,
		signatureBase64URL,
	}, "."), nil

}
