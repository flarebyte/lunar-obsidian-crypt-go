package lunarcrypt

import (
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

func translucentLizardSignID(prefix string, cypher TranslucentLizardCypher, payload IDPayload, now func() time.Time) Result[string] {
	errs := ValidateIDPayload(payload)
	if len(errs) > 0 {
		return Fail[string](CryptError{
			Step:   StepSignIDValidatePayload,
			Errors: errs,
		})
	}

	duration, err := cypher.Expiration.Duration()
	if err != nil {
		return Fail[string](CryptError{
			Step:    StepSignIDSign,
			Message: "The JWT token could not be signed",
		})
	}

	claims := jwt.MapClaims{
		"id":  payload.ID,
		"exp": now().Add(duration).Unix(),
	}
	if payload.Scope != nil {
		claims["scope"] = payload.Scope
	}

	token, err := signClaims(claims, cypher.Secret, cypher.Strength)
	if err != nil {
		return Fail[string](CryptError{
			Step:    StepSignIDSign,
			Message: "The JWT token could not be signed",
		})
	}
	return Succeed(composeFullToken(prefix, token))
}

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
