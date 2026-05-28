package lunarcrypt

import (
	"fmt"

	"github.com/golang-jwt/jwt/v5"
)

func signingMethodForStrength(strength EncryptionStrength) (jwt.SigningMethod, error) {
	switch strength {
	case Sufficient:
		return jwt.SigningMethodHS256, nil
	case Good:
		return jwt.SigningMethodHS384, nil
	case Strong:
		return jwt.SigningMethodHS512, nil
	default:
		return nil, fmt.Errorf("strength %q is not supported", strength)
	}
}

func signClaims(claims jwt.MapClaims, secret []byte, strength EncryptionStrength) (string, error) {
	method, err := signingMethodForStrength(strength)
	if err != nil {
		return "", err
	}
	token := jwt.NewWithClaims(method, claims)
	return token.SignedString(secret)
}

func verifyClaims(tokenText string, secret []byte, strength EncryptionStrength) (jwt.MapClaims, error) {
	expectedMethod, err := signingMethodForStrength(strength)
	if err != nil {
		return nil, err
	}

	claims := jwt.MapClaims{}
	token, err := jwt.ParseWithClaims(tokenText, claims, func(token *jwt.Token) (any, error) {
		if token.Method.Alg() != expectedMethod.Alg() {
			return nil, fmt.Errorf("unexpected signing method %q", token.Method.Alg())
		}
		return secret, nil
	}, jwt.WithValidMethods([]string{expectedMethod.Alg()}))
	if err != nil {
		return nil, err
	}
	if !token.Valid {
		return nil, fmt.Errorf("token is invalid")
	}
	return claims, nil
}
