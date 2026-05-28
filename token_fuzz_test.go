package lunarcrypt

import "testing"

func FuzzExtractTokenPrefix(f *testing.F) {
	f.Add("product:header.payload.signature")
	f.Add("tenant:product:header.payload.signature")
	f.Add("no-colon-token")
	f.Add(":missing-prefix")
	f.Add("missing-token:")

	allowed := []string{"product", "tenant:product"}
	f.Fuzz(func(t *testing.T, fullToken string) {
		prefix, token, err := extractTokenPrefix(fullToken, allowed)
		if err != nil {
			if err.Step != StepVerifyIDExtractToken {
				t.Fatalf("step = %q, want %q", err.Step, StepVerifyIDExtractToken)
			}
			if prefix != "" || token != "" {
				t.Fatalf("prefix/token = %q/%q, want empty values on failure", prefix, token)
			}
			return
		}
		if prefix == "" {
			t.Fatal("prefix is empty on success")
		}
		if token == "" {
			t.Fatal("token is empty on success")
		}
	})
}
