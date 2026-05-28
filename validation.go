package lunarcrypt

import (
	"errors"
	"fmt"
	"strings"
	"time"
	"unicode/utf8"
)

const (
	maxTitleLength     = 50
	maxIDLength        = 400
	maxExpirationValue = 1000000
)

func (e Expiration) Duration() (time.Duration, error) {
	if e.Value <= 0 {
		return 0, fmt.Errorf("expiration value must be positive")
	}
	if e.Value > maxExpirationValue {
		return 0, fmt.Errorf("expiration value must be at most %d", maxExpirationValue)
	}

	value := time.Duration(e.Value)
	switch e.Unit {
	case Seconds:
		return value * time.Second, nil
	case Minutes:
		return value * time.Minute, nil
	case Hours:
		return value * time.Hour, nil
	case Days:
		return value * 24 * time.Hour, nil
	case Weeks:
		return value * 7 * 24 * time.Hour, nil
	default:
		return 0, fmt.Errorf("expiration unit %q is not supported", e.Unit)
	}
}

func ValidateStore(store Store) error {
	if err := validateTitle("store title", store.Title); err != nil {
		return err
	}
	if len(store.Cyphers) == 0 {
		return errors.New("store must include at least one cypher")
	}

	for prefix, cypher := range store.Cyphers {
		if err := validatePrefix(prefix); err != nil {
			return fmt.Errorf("cypher prefix %q: %w", prefix, err)
		}
		if err := validateTranslucentLizardCypher(prefix, cypher); err != nil {
			return err
		}
	}

	return nil
}

func ValidateIDPayload(payload IDPayload) []ValidationError {
	return validateIDPayloadFields(payload.ID, payload.Scope)
}

func ValidateProtectedPayload(payload ProtectedPayload) []ValidationError {
	errs := validateIDPayloadFields(payload.ID, payload.Scope)
	if payload.Exp <= 0 {
		errs = append(errs, ValidationError{
			Message: "exp must be a positive number",
			Path:    "exp",
		})
	}
	return errs
}

func validateTranslucentLizardCypher(prefix string, cypher TranslucentLizardCypher) error {
	if cypher.Kind != TranslucentLizard {
		return fmt.Errorf("cypher %q kind must be %q", prefix, TranslucentLizard)
	}
	if err := validateTitle(fmt.Sprintf("cypher %q title", prefix), cypher.Title); err != nil {
		return err
	}
	if len(cypher.Secret) == 0 {
		return fmt.Errorf("cypher %q secret is required", prefix)
	}
	if err := validateStrength(prefix, cypher.Strength); err != nil {
		return err
	}
	if _, err := cypher.Expiration.Duration(); err != nil {
		return fmt.Errorf("cypher %q expiration is invalid: %w", prefix, err)
	}
	if err := validateExpectedScope(prefix, cypher.ExpectedScope); err != nil {
		return err
	}
	return nil
}

func validateTitle(field string, value string) error {
	if value == "" {
		return fmt.Errorf("%s is required", field)
	}
	if strings.ContainsAny(value, "\r\n") {
		return fmt.Errorf("%s must be a single line", field)
	}
	if utf8.RuneCountInString(value) > maxTitleLength {
		return fmt.Errorf("%s must be at most %d characters", field, maxTitleLength)
	}
	return nil
}

func validatePrefix(prefix string) error {
	if prefix == "" {
		return errors.New("prefix is required")
	}
	if strings.ContainsAny(prefix, "\r\n") {
		return errors.New("prefix must be a single line")
	}
	return nil
}

func validateStrength(prefix string, strength EncryptionStrength) error {
	switch strength {
	case Sufficient, Good, Strong:
		return nil
	default:
		return fmt.Errorf("cypher %q strength %q is not supported", prefix, strength)
	}
}

func validateExpectedScope(prefix string, scope map[string]ScopeValue) error {
	for key, values := range scope {
		if key == "" {
			return fmt.Errorf("cypher %q expected scope key is required", prefix)
		}
		if strings.ContainsAny(key, "\r\n") {
			return fmt.Errorf("cypher %q expected scope key must be a single line", prefix)
		}
		if len(values) == 0 {
			return fmt.Errorf("cypher %q expected scope %q must include at least one value", prefix, key)
		}
		for index, value := range values {
			if value == "" {
				return fmt.Errorf("cypher %q expected scope %q value %d is required", prefix, key, index)
			}
		}
	}
	return nil
}

func validateIDPayloadFields(id string, scope map[string]ScopeValue) []ValidationError {
	var errs []ValidationError
	if id == "" {
		errs = append(errs, ValidationError{
			Message: "id is required",
			Path:    "id",
		})
	} else if utf8.RuneCountInString(id) > maxIDLength {
		errs = append(errs, ValidationError{
			Message: fmt.Sprintf("id must be at most %d characters", maxIDLength),
			Path:    "id",
		})
	}

	for key, values := range scope {
		if key == "" {
			errs = append(errs, ValidationError{
				Message: "scope key is required",
				Path:    "scope",
			})
			continue
		}
		if strings.ContainsAny(key, "\r\n") {
			errs = append(errs, ValidationError{
				Message: "scope key must be a single line",
				Path:    "scope." + key,
			})
		}
		if len(values) == 0 {
			errs = append(errs, ValidationError{
				Message: "scope value must include at least one string",
				Path:    "scope." + key,
			})
			continue
		}
		for index, value := range values {
			if value == "" {
				errs = append(errs, ValidationError{
					Message: "scope value is required",
					Path:    fmt.Sprintf("scope.%s[%d]", key, index),
				})
			}
		}
	}

	return errs
}
