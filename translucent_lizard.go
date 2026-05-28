package lunarcrypt

import (
	"fmt"
	"math"
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

func translucentLizardVerifyID(prefix string, cypher TranslucentLizardCypher, fullToken string) Result[IDPayload] {
	token, extractErr := extractToken(prefix, fullToken)
	if extractErr != nil {
		return Fail[IDPayload](*extractErr)
	}

	claims, verifyErr := verifyClaims(token, cypher.Secret, cypher.Strength)
	if verifyErr != nil {
		if len(cypher.AltSecret) > 0 {
			altClaims, altErr := verifyClaims(token, cypher.AltSecret, cypher.Strength)
			if altErr == nil {
				return payloadFromVerifiedClaims(altClaims, cypher)
			}
			return Fail[IDPayload](CryptError{
				Step:         StepVerifyIDVerifyToken,
				Message:      "The JWT token could not be verified",
				FinalMessage: "Verification with previous secret failed as well",
			})
		}
		return Fail[IDPayload](CryptError{
			Step:    StepVerifyIDVerifyToken,
			Message: "The JWT token could not be verified",
		})
	}

	return payloadFromVerifiedClaims(claims, cypher)
}

func payloadFromVerifiedClaims(claims jwt.MapClaims, cypher TranslucentLizardCypher) Result[IDPayload] {
	protected, errs := protectedPayloadFromClaims(claims)
	if len(errs) > 0 {
		return Fail[IDPayload](CryptError{
			Step:   StepVerifyIDValidatePayload,
			Errors: errs,
		})
	}

	if scopeErr := checkScope(protected.Scope, cypher.ExpectedScope, cypher.ScopeValidator); scopeErr != nil {
		return Fail[IDPayload](*scopeErr)
	}

	return Succeed(IDPayload{
		ID:    protected.ID,
		Scope: protected.Scope,
	})
}

func protectedPayloadFromClaims(claims jwt.MapClaims) (ProtectedPayload, []ValidationError) {
	var payload ProtectedPayload
	var errs []ValidationError

	id, ok := claims["id"].(string)
	if ok {
		payload.ID = id
	}

	exp, ok := claimInt64(claims["exp"])
	if ok {
		payload.Exp = exp
	}

	if rawScope, ok := claims["scope"]; ok {
		scope, scopeErrs := scopeFromClaim(rawScope)
		if len(scopeErrs) > 0 {
			errs = append(errs, scopeErrs...)
		} else {
			payload.Scope = scope
		}
	}

	errs = append(errs, ValidateProtectedPayload(payload)...)
	return payload, errs
}

func claimInt64(value any) (int64, bool) {
	switch typed := value.(type) {
	case float64:
		if typed <= 0 || math.Trunc(typed) != typed {
			return 0, false
		}
		return int64(typed), true
	case int64:
		return typed, typed > 0
	case int:
		return int64(typed), typed > 0
	default:
		return 0, false
	}
}

func scopeFromClaim(value any) (map[string]ScopeValue, []ValidationError) {
	rawScope, ok := value.(map[string]any)
	if !ok {
		return nil, []ValidationError{{
			Message: "scope must be an object",
			Path:    "scope",
		}}
	}

	scope := make(map[string]ScopeValue, len(rawScope))
	var errs []ValidationError
	for key, rawValue := range rawScope {
		values, valueErrs := scopeValueFromClaim(key, rawValue)
		if len(valueErrs) > 0 {
			errs = append(errs, valueErrs...)
			continue
		}
		scope[key] = values
	}
	return scope, errs
}

func scopeValueFromClaim(key string, value any) (ScopeValue, []ValidationError) {
	switch typed := value.(type) {
	case string:
		return ScopeValue{typed}, nil
	case []any:
		values := make(ScopeValue, 0, len(typed))
		for index, rawItem := range typed {
			item, ok := rawItem.(string)
			if !ok {
				return nil, []ValidationError{{
					Message: "scope value must be a string",
					Path:    fmt.Sprintf("scope.%s[%d]", key, index),
				}}
			}
			values = append(values, item)
		}
		return values, nil
	case []string:
		return append(ScopeValue(nil), typed...), nil
	default:
		return nil, []ValidationError{{
			Message: "scope value must be a string or string list",
			Path:    "scope." + key,
		}}
	}
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
