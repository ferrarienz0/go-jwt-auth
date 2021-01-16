# Go-JWT-Auth

Simplify JWT handling in Go. Based on <github.com/dgrijalva/jwt-go>

# Install

Add this import to your code:

```go
jwtAuth import "github.com/ferrarienz0/go-auth"
```

To provide intelissense and download the module run on terminal:

```go
go mod tidy
```

# Usage

Creating a JWT with claims:

```go
claims := map[string]interface{}{
	"_id":  "someid",
	"name": "test",
}

secret := "test"

token, tokenString, err := jwtAuth.CreateTokenWithClaims(claims, secret)
```

You can also provide a custom signing method:

```go
claims := map[string]interface{}{
	"_id":  "someid",
	"name": "test",
}

secret := "test"

token, tokenString, err := jwtAuth.CreateTokenWithClaims(claims, secret, jwtAuth.HS512)
```

To parse a JWT and get it's claims with the default signing method:

```go
claims, err := jwtAuth.ParseTokenAndGetClaims(tokenString, secret)
```

To parse a JWT and get it's claims with a custom signing method:

```go
claims, err := jwtAuth.ParseTokenAndGetClaims(tokenString, secret, jwtAuth.HS512)
```
