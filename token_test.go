package lunarcrypt

import "testing"

func TestComposeFullToken(t *testing.T) {
	got := composeFullToken("tenant:product", "header.payload.signature")
	want := "tenant:product:header.payload.signature"
	if got != want {
		t.Fatalf("composeFullToken() = %q, want %q", got, want)
	}
}

func TestExtractTokenPrefix(t *testing.T) {
	tests := []struct {
		name            string
		fullToken       string
		allowedPrefixes []string
		wantPrefix      string
		wantToken       string
		wantMessage     string
	}{
		{
			name:            "simple prefix",
			fullToken:       "product:header.payload.signature",
			allowedPrefixes: []string{"product"},
			wantPrefix:      "product",
			wantToken:       "header.payload.signature",
		},
		{
			name:            "prefix containing colon",
			fullToken:       "tenant:product:header.payload.signature",
			allowedPrefixes: []string{"tenant:product"},
			wantPrefix:      "tenant:product",
			wantToken:       "header.payload.signature",
		},
		{
			name:            "no colon",
			fullToken:       "header.payload.signature",
			allowedPrefixes: []string{"product"},
			wantMessage:     "The full token must include a prefix and token separator",
		},
		{
			name:            "leading colon",
			fullToken:       ":header.payload.signature",
			allowedPrefixes: []string{"product"},
			wantMessage:     "The token prefix is required",
		},
		{
			name:            "trailing colon",
			fullToken:       "product:",
			allowedPrefixes: []string{"product"},
			wantMessage:     "The JWT token is required",
		},
		{
			name:            "unsupported prefix",
			fullToken:       "company:header.payload.signature",
			allowedPrefixes: []string{"product"},
			wantMessage:     "The token prefix is not supported",
		},
		{
			name:            "empty allowed prefixes",
			fullToken:       "product:header.payload.signature",
			allowedPrefixes: nil,
			wantMessage:     "The token prefix is not supported",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotPrefix, gotToken, gotErr := extractTokenPrefix(tt.fullToken, tt.allowedPrefixes)
			if tt.wantMessage == "" {
				if gotErr != nil {
					t.Fatalf("extractTokenPrefix() error = %#v, want nil", gotErr)
				}
				if gotPrefix != tt.wantPrefix {
					t.Fatalf("prefix = %q, want %q", gotPrefix, tt.wantPrefix)
				}
				if gotToken != tt.wantToken {
					t.Fatalf("token = %q, want %q", gotToken, tt.wantToken)
				}
				return
			}

			assertTokenExtractionError(t, gotErr, tt.wantMessage)
			if gotPrefix != "" || gotToken != "" {
				t.Fatalf("prefix/token = %q/%q, want empty values on failure", gotPrefix, gotToken)
			}
		})
	}
}

func TestExtractToken(t *testing.T) {
	tests := []struct {
		name           string
		expectedPrefix string
		fullToken      string
		wantToken      string
		wantMessage    string
	}{
		{
			name:           "matching prefix",
			expectedPrefix: "product",
			fullToken:      "product:header.payload.signature",
			wantToken:      "header.payload.signature",
		},
		{
			name:           "matching prefix with colon",
			expectedPrefix: "tenant:product",
			fullToken:      "tenant:product:header.payload.signature",
			wantToken:      "header.payload.signature",
		},
		{
			name:           "wrong prefix",
			expectedPrefix: "company",
			fullToken:      "product:header.payload.signature",
			wantMessage:    "The token prefix does not match the expected prefix",
		},
		{
			name:           "malformed full token",
			expectedPrefix: "product",
			fullToken:      "header.payload.signature",
			wantMessage:    "The full token must include a prefix and token separator",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotToken, gotErr := extractToken(tt.expectedPrefix, tt.fullToken)
			if tt.wantMessage == "" {
				if gotErr != nil {
					t.Fatalf("extractToken() error = %#v, want nil", gotErr)
				}
				if gotToken != tt.wantToken {
					t.Fatalf("token = %q, want %q", gotToken, tt.wantToken)
				}
				return
			}

			assertTokenExtractionError(t, gotErr, tt.wantMessage)
			if gotToken != "" {
				t.Fatalf("token = %q, want empty on failure", gotToken)
			}
		})
	}
}

func TestTokenExtractionErrorsDoNotIncludeFullToken(t *testing.T) {
	fullToken := "product:header.payload.signature"
	_, _, gotErr := extractTokenPrefix(fullToken, []string{"company"})
	assertTokenExtractionError(t, gotErr, "The token prefix is not supported")
	if gotErr.Message == fullToken {
		t.Fatal("error message includes full token")
	}
}

func TestUnsupportedPrefixError(t *testing.T) {
	got := unsupportedPrefixError("company")
	assertTokenExtractionError(t, got, `The token prefix "company" is not supported`)
}

func assertTokenExtractionError(t *testing.T, got *CryptError, wantMessage string) {
	t.Helper()
	if got == nil {
		t.Fatal("error = nil, want token extraction error")
	}
	if got.Step != StepVerifyIDExtractToken {
		t.Fatalf("step = %q, want %q", got.Step, StepVerifyIDExtractToken)
	}
	if got.Message != wantMessage {
		t.Fatalf("message = %q, want %q", got.Message, wantMessage)
	}
}
