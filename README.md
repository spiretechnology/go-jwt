# go-jwt

This repository contains a JSON Web Tokens library written in Go. The library implements JWT creation, parsing, signing, and verification.

### Create a JWT

Creating a JWT is simple. The `Create(...)` function takes two arguments, the claims to include as the payload to the JWT and the `Signer` to use to sign the JWT. The claims can be any value, as long as that value can be serialized to JSON using `json.Marshal`. The signed JWT string is returned.

```go
// Create a new JWT token
token, err := jwt.Create(
    myClaims{
        Name: "John Smith",
        Age:  25,
    },
    jwt.HS256Signer([]byte("my secret")),
)
```

### Parsing a JWT

Parsing a JWT from a string into a `jwt.Token` instance:

```go
// Parse the token
token, err := jwt.Parse(tokenStr)

// Unmarshal the claims
var claims testClaims
err := parsedToken.Claims(&claims)
```

### Verifying a JWT

To verify a parsed token's signature, call `token.Verify(...)` and provide a verifier corresponding to the signature algorithm you're using.

```go
ok, err := token.Verify(
    jwt.HS256Verifier([]byte("my secret")),
)
```

An error is returned if something actually goes wrong while verifying the signature. An invalid signature isn't itself an error. When the signature is invalid, but nothing else goes wrong, the return values of the function are `(false, nil)`.

If the signature is valid, the return values are `(true, nil)`.

### Signature algorithms

This library implements the following signature algorithms:

- HS256
- HS384
- HS512
- RS256
- RS384
- RS512
- ES256
- ES384
- ES512
