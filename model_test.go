package lunarcrypt

import (
	"encoding/json"
	"testing"
)

func TestPublicConstantValues(t *testing.T) {
	tests := map[string]string{
		"Seconds":           string(Seconds),
		"Minutes":           string(Minutes),
		"Hours":             string(Hours),
		"Days":              string(Days),
		"Weeks":             string(Weeks),
		"Sufficient":        string(Sufficient),
		"Good":              string(Good),
		"Strong":            string(Strong),
		"TranslucentLizard": string(TranslucentLizard),
		"Success":           string(Success),
		"Failure":           string(Failure),
	}

	want := map[string]string{
		"Seconds":           "seconds",
		"Minutes":           "minutes",
		"Hours":             "hours",
		"Days":              "days",
		"Weeks":             "weeks",
		"Sufficient":        "sufficient",
		"Good":              "good",
		"Strong":            "strong",
		"TranslucentLizard": "translucent-lizard",
		"Success":           "success",
		"Failure":           "failure",
	}

	for name, got := range tests {
		if got != want[name] {
			t.Fatalf("%s = %q, want %q", name, got, want[name])
		}
	}
}

func TestPayloadJSONFieldNames(t *testing.T) {
	payload := IDPayload{
		ID:    "product123",
		Scope: map[string]ScopeValue{"account": {"account890"}},
	}

	got, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal IDPayload: %v", err)
	}

	want := `{"id":"product123","scope":{"account":["account890"]}}`
	if string(got) != want {
		t.Fatalf("IDPayload JSON = %s, want %s", got, want)
	}
}

func TestResultJSONFieldNames(t *testing.T) {
	success := Succeed("signed-token")
	got, err := json.Marshal(success)
	if err != nil {
		t.Fatalf("marshal success result: %v", err)
	}
	want := `{"status":"success","value":"signed-token"}`
	if string(got) != want {
		t.Fatalf("success JSON = %s, want %s", got, want)
	}

	failure := Fail[string](CryptError{
		Step:    StepVerifyIDVerifyScope,
		Message: "scope mismatch",
	})
	got, err = json.Marshal(failure)
	if err != nil {
		t.Fatalf("marshal failure result: %v", err)
	}
	want = `{"status":"failure","error":{"step":"verify-id/verify-scope","message":"scope mismatch"}}`
	if string(got) != want {
		t.Fatalf("failure JSON = %s, want %s", got, want)
	}
}
