package auth

import (
	"reflect"
	"testing"

	"github.com/dgrijalva/jwt-go"
)

// Should create a token with a provided set
// of claims + the default signing method
func TestShouldCreateTokenWithDefaultSigninMethod(t *testing.T) {
	claims := map[string]interface{}{
		"_id":  "someid",
		"name": "test",
	}

	secret := "test"

	_, tokenString, err := CreateTokenWithClaims(claims, secret)

	if tokenString == "" {
		t.Errorf("Token was empty")
	} else if err != nil {
		t.Errorf("Error on token creation, %s", err)
	}

	t.Logf("Token created with success: %s", tokenString)
}

// Should create a token with a costum signin method
func TestShouldCreateTokenWithCustomSigninMethod(t *testing.T) {
	claims := map[string]interface{}{
		"_id":  "someid",
		"name": "test",
	}

	secret := "test"

	token, tokenString, err := CreateTokenWithClaims(claims, secret, jwt.SigningMethodHS512)

	tokenHasTheSameSigninMethod := validateTokenSignInMethod(*token, jwt.SigningMethodHS512)

	if tokenString == "" || token == nil {
		t.Errorf("Token was empty")
	} else if err != nil {
		t.Errorf("Error on token creation, %s", err)
	}

	if !tokenHasTheSameSigninMethod {
		t.Errorf("Token had incorred signing method, expected %#v, got %#v", jwt.SigningMethodHS512, token.Method)
	}

	t.Logf("Token had the correct signing method, expected: %#v, got: %#v", jwt.SigningMethodHS512, token.Method)

}

// Should parse a token string and get it's claims
func TestShouldParseTokenStringAndGetClaims(t *testing.T) {
	originalClaims := map[string]interface{}{
		"_id":  "someid",
		"name": "test",
	}

	secret := "test"

	_, tokenString, _ := CreateTokenWithClaims(originalClaims, secret)

	claims, err := ParseTokenAndGetClaims(tokenString, secret)

	if claims == nil {
		t.Errorf("Claims was empty")
	} else if err != nil {
		t.Errorf("A error happened during parsing: %#v", err)
	}

	if reflect.DeepEqual(claims, originalClaims) {
		t.Logf("Token was successfully parsed and got correct claims: %#v", claims)
	} else {
		t.Errorf("Parsing was successfull but got incorrect claims")
	}
}

// Should return an error when trying to parse a token with
// incorrect secret
func TestShouldReturnErrorWhenWrongSecret(t *testing.T) {
	originalClaims := map[string]interface{}{
		"_id":  "someid",
		"name": "test",
	}

	secret := "test"

	_, tokenString, _ := CreateTokenWithClaims(originalClaims, secret)

	_, err := ParseTokenAndGetClaims(tokenString, "bro")

	if err == nil {
		t.Errorf("No error was returned when given a incorrect secret")
	} else {
		t.Logf("A error has successfully happened during parsing: %s", err.Error())
	}
}

// Should return an error when trying to parse a token with
// the incorred signing method
func TestShouldReturnErrorWhenWrongSigningMethod(t *testing.T) {
	originalClaims := map[string]interface{}{
		"_id":  "someid",
		"name": "test",
	}

	secret := "test"

	_, tokenString, _ := CreateTokenWithClaims(originalClaims, secret)

	_, err := ParseTokenAndGetClaims(tokenString, secret, jwt.SigningMethodES384)

	if err == nil {
		t.Errorf("No error was returned when given a incorrect secret")
	} else {
		t.Logf("A error has successfully happened during parsing: %s", err.Error())
	}
}
