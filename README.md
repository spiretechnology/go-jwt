# go-jwt

This repository contains a JSON Web Tokens library written in Go. The library implements JWT creation, parsing, signing, and verification.

### Create a JWT

Creating a JWT is simple. The `New(...)` function takes a single argument, the claims to include as the payload to the JWT. The claims can be any value, as long as that value can be serialized to JSON using `json.Marshal`

```go
// Create a new JWT token
token, err := jwt.New(testClaims{
    Name: "John Smith",
    Age:  10,
})

// Create the signed string for the token
tokenStr := token.SignedString(SECRET)
```

### Parsing a JWT

Parsing a JWT from a string into a `jwt.Token` instance:

```go
// Parse the token
parsedToken, err := Parse(tokenStr)

// Unmarshal the claims
var claims testClaims
err := parsedToken.Claims(&claims)
```

### Verifying a JWT

Verifying that a JWT is genuine and was signed by a known secret:

```go
verified := parsedToken.Verify(SECRET)
```
