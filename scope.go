/*
Purpose: Verifies signed payload scopes against configured exact expectations and optional caller-provided validation logic.
Responsibilities:
- Require scopes when policy needs them, compare expected scope values deterministically, and invoke custom ScopeValidator hooks.
- Return verify-scope CryptError values with stable messages for failed scope checks.
Architecture notes:
- Scope comparison is exact and order-sensitive within each value list; this preserves caller intent instead of treating scopes as sets.
- Keys are sorted before reporting mismatches so diagnostics remain deterministic.
*/
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
