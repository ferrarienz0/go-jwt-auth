package auth

import (
	"errors"

	jwt "github.com/dgrijalva/jwt-go"
)

func chooseDefaultSignInMethod(signInMethod []jwt.SigningMethod) jwt.SigningMethod {
	var selectedSigningMethod = jwt.SigningMethod(jwt.SigningMethodHS256)

	if signInMethod != nil {
		selectedSigningMethod = signInMethod[0]
	}

	return selectedSigningMethod
}

// CreateTokenWithClaims creates a JWT with the provided claims and based on the
// specified secret
func CreateTokenWithClaims(claims map[string]interface{}, secret string, signInMethod ...jwt.SigningMethod) (*jwt.Token, string, error) {
	customClaims := jwt.MapClaims(claims)

	selectedSigningMethod := chooseDefaultSignInMethod(signInMethod)

	token := jwt.NewWithClaims(selectedSigningMethod, customClaims)

	byteSecret := []byte(secret)

	tokenString, err := token.SignedString(byteSecret)

	return token, tokenString, err
}

// ParseTokenAndGetClaims Parses a token and returns it's claims if everything was ok
func ParseTokenAndGetClaims(tokenString string, secret string, signInMethod ...jwt.SigningMethod) (map[string]interface{}, error) {
	selectedSigningMethod := chooseDefaultSignInMethod(signInMethod)

	tokenCallback := func(token *jwt.Token) (interface{}, error) {
		isSigningMethodValid := validateTokenSignInMethod(*token, selectedSigningMethod)

		if !isSigningMethodValid {
			return nil, errors.New("signing method is not what the same as used in token")
		}

		return []byte(secret), nil
	}

	token, err := jwt.Parse(tokenString, tokenCallback)

	if err != nil {
		return nil, err
	}

	if !token.Valid {
		return nil, errors.New("token is invalid")
	}

	claims, ok := token.Claims.(jwt.MapClaims)

	if !ok {
		return nil, errors.New("there is no claims in the token")
	}

	return claims, nil
}

func validateTokenSignInMethod(token jwt.Token, signInMethod ...jwt.SigningMethod) bool {
	selectedSigningMethod := chooseDefaultSignInMethod(signInMethod)

	return token.Method.Alg() == selectedSigningMethod.Alg()
}
