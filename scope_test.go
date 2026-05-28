package lunarcrypt

import (
	"errors"
	"testing"
)

func TestCheckScope(t *testing.T) {
	tests := []struct {
		name      string
		actual    map[string]ScopeValue
		expected  map[string]ScopeValue
		validator ScopeValidator
		wantStep  string
		wantMsg   string
	}{
		{
			name:     "nil actual and no expectations succeeds",
			actual:   nil,
			expected: nil,
		},
		{
			name:     "string scope match succeeds",
			actual:   map[string]ScopeValue{"account": {"account890"}},
			expected: map[string]ScopeValue{"account": {"account890"}},
		},
		{
			name:     "list scope match succeeds",
			actual:   map[string]ScopeValue{"roles": {"admin", "writer"}},
			expected: map[string]ScopeValue{"roles": {"admin", "writer"}},
		},
		{
			name:     "list scope order mismatch fails",
			actual:   map[string]ScopeValue{"roles": {"writer", "admin"}},
			expected: map[string]ScopeValue{"roles": {"admin", "writer"}},
			wantStep: StepVerifyIDVerifyScope,
			wantMsg:  "The following fields [roles] from the scope did not match the expectations",
		},
		{
			name:     "missing scope fails",
			actual:   nil,
			expected: map[string]ScopeValue{"account": {"account890"}},
			wantStep: StepVerifyIDVerifyScope,
			wantMsg:  "A scope was expected in the payload",
		},
		{
			name:     "mismatches are sorted",
			actual:   map[string]ScopeValue{"z": {"wrong"}, "a": {"wrong"}},
			expected: map[string]ScopeValue{"z": {"ok"}, "a": {"ok"}},
			wantStep: StepVerifyIDVerifyScope,
			wantMsg:  "The following fields [a,z] from the scope did not match the expectations",
		},
		{
			name:     "validator succeeds",
			actual:   map[string]ScopeValue{"account": {"account890"}},
			expected: nil,
			validator: func(scope map[string]ScopeValue) error {
				return nil
			},
		},
		{
			name:     "validator requires scope",
			actual:   nil,
			expected: nil,
			validator: func(scope map[string]ScopeValue) error {
				return nil
			},
			wantStep: StepVerifyIDVerifyScope,
			wantMsg:  "The scope should be included in the JWT payload",
		},
		{
			name:     "validator failure",
			actual:   map[string]ScopeValue{"account": {"account890"}},
			expected: nil,
			validator: func(scope map[string]ScopeValue) error {
				return errors.New("account is not allowed")
			},
			wantStep: StepVerifyIDVerifyScope,
			wantMsg:  "The custom validator failed with account is not allowed",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := checkScope(tt.actual, tt.expected, tt.validator)
			if tt.wantStep == "" {
				if got != nil {
					t.Fatalf("checkScope() = %#v, want nil", got)
				}
				return
			}
			if got == nil {
				t.Fatal("checkScope() = nil, want error")
			}
			if got.Step != tt.wantStep {
				t.Fatalf("step = %q, want %q", got.Step, tt.wantStep)
			}
			if got.Message != tt.wantMsg {
				t.Fatalf("message = %q, want %q", got.Message, tt.wantMsg)
			}
		})
	}
}
