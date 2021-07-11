# go-jwt

This repository contains a JSON Web Tokens library written in Go. The library implements JWT creation, parsing, signing, and verification.

### Create a JWT

Creating a JWT is simple. The `New(...)` function takes a single argument, the claims to include as the payload to the JWT. The claims can be any value, as long as that value can be serialized to JSON using `json.Marshal`

```go
// Create a new JWT token
token := jwt.New(testClaims{
    Name: "John Smith",
    Age:  10,
})

// Create the signed string for the token
tokenStr, err := token.SignedString(SECRET)
```

### Parsing a JWT

Parsing a JWT from a string into a `jwt.Token` instance is equally simple:

```go
// Parse the token
parsedToken, err := ParseAndVerify(tokenStr, SECRET)

// Unmarshal the claims
var claims testClaims
err := parsedToken.Claims(&claims)
```
