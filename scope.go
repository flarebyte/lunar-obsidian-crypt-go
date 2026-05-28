package lunarcrypt

import (
	"fmt"
	"slices"
	"sort"
	"strings"
)

func checkScope(actual map[string]ScopeValue, expected map[string]ScopeValue, validator ScopeValidator) *CryptError {
	if len(expected) > 0 {
		if actual == nil {
			return &CryptError{
				Step:    StepVerifyIDVerifyScope,
				Message: "A scope was expected in the payload",
			}
		}

		missingKeys := mismatchedScopeKeys(actual, expected)
		if len(missingKeys) > 0 {
			return &CryptError{
				Step: StepVerifyIDVerifyScope,
				Message: fmt.Sprintf(
					"The following fields [%s] from the scope did not match the expectations",
					strings.Join(missingKeys, ","),
				),
			}
		}
	}

	if validator != nil {
		if actual == nil {
			return &CryptError{
				Step:    StepVerifyIDVerifyScope,
				Message: "The scope should be included in the JWT payload",
			}
		}
		if err := validator(actual); err != nil {
			return &CryptError{
				Step:    StepVerifyIDVerifyScope,
				Message: fmt.Sprintf("The custom validator failed with %s", err.Error()),
			}
		}
	}

	return nil
}

func mismatchedScopeKeys(actual map[string]ScopeValue, expected map[string]ScopeValue) []string {
	keys := make([]string, 0, len(expected))
	for key := range expected {
		keys = append(keys, key)
	}
	sort.Strings(keys)

	missingKeys := make([]string, 0)
	for _, key := range keys {
		if !slices.Equal(actual[key], expected[key]) {
			missingKeys = append(missingKeys, key)
		}
	}
	return missingKeys
}
