package lunarcrypt

import (
	"encoding/json"
	"strings"
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

func TestScopeValueUnmarshalJSON(t *testing.T) {
	tests := []struct {
		name string
		json string
		want ScopeValue
	}{
		{name: "scalar string", json: `{"id":"product123","scope":{"account":"account890"}}`, want: ScopeValue{"account890"}},
		{name: "string array", json: `{"id":"product123","scope":{"account":["account890","account891"]}}`, want: ScopeValue{"account890", "account891"}},
		{name: "empty array", json: `{"id":"product123","scope":{"account":[]}}`, want: ScopeValue{}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var payload IDPayload
			if err := json.Unmarshal([]byte(tt.json), &payload); err != nil {
				t.Fatalf("Unmarshal() error = %v", err)
			}
			got := payload.Scope["account"]
			if len(got) != len(tt.want) {
				t.Fatalf("scope len = %d, want %d", len(got), len(tt.want))
			}
			for index := range got {
				if got[index] != tt.want[index] {
					t.Fatalf("scope[%d] = %q, want %q", index, got[index], tt.want[index])
				}
			}
		})
	}
}

func TestScopeValueUnmarshalJSONRejectsInvalidValues(t *testing.T) {
	tests := []struct {
		name string
		json string
	}{
		{name: "number", json: `{"id":"product123","scope":{"account":123}}`},
		{name: "object", json: `{"id":"product123","scope":{"account":{"id":"account890"}}}`},
		{name: "null", json: `{"id":"product123","scope":{"account":null}}`},
		{name: "mixed array", json: `{"id":"product123","scope":{"account":["account890",123]}}`},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var payload IDPayload
			err := json.Unmarshal([]byte(tt.json), &payload)
			if err == nil {
				t.Fatal("Unmarshal() error = nil, want error")
			}
			if !strings.Contains(err.Error(), "scope value must be a string or string list") {
				t.Fatalf("Unmarshal() error = %q, want scope value error", err)
			}
		})
	}
}

func TestScopeValueMarshalJSONIsStable(t *testing.T) {
	payload := IDPayload{
		ID:    "product123",
		Scope: map[string]ScopeValue{"account": {"account890"}},
	}

	got, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("Marshal() error = %v", err)
	}
	want := `{"id":"product123","scope":{"account":["account890"]}}`
	if string(got) != want {
		t.Fatalf("Marshal() = %s, want %s", got, want)
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
