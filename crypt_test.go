package lunarcrypt

import (
	"strings"
	"testing"
	"time"
)

func TestSignIDRejectsUnsupportedPrefix(t *testing.T) {
	crypt := newTestCrypt(t, validStore([]byte("current-secret")))

	got := crypt.SignID("company", IDPayload{ID: "product123"})
	if got.Status != Failure {
		t.Fatalf("status = %q, want failure", got.Status)
	}
	if got.Error == nil {
		t.Fatal("error = nil, want error")
	}
	if got.Error.Step != StepSignIDStore {
		t.Fatalf("step = %q, want %q", got.Error.Step, StepSignIDStore)
	}
}

func TestSignIDRejectsInvalidPayload(t *testing.T) {
	crypt := newTestCrypt(t, validStore([]byte("current-secret")))

	got := crypt.SignID("product", IDPayload{})
	if got.Status != Failure {
		t.Fatalf("status = %q, want failure", got.Status)
	}
	if got.Error == nil {
		t.Fatal("error = nil, want error")
	}
	if got.Error.Step != StepSignIDValidatePayload {
		t.Fatalf("step = %q, want %q", got.Error.Step, StepSignIDValidatePayload)
	}
	if len(got.Error.Errors) != 1 || got.Error.Errors[0].Path != "id" {
		t.Fatalf("validation errors = %#v, want id error", got.Error.Errors)
	}
}

func TestSignIDDoesNotLeakSecretInFailures(t *testing.T) {
	secret := "current-secret"
	crypt := newTestCrypt(t, validStore([]byte(secret)))

	got := crypt.SignID("product", IDPayload{})
	if got.Error == nil {
		t.Fatal("error = nil, want error")
	}
	if strings.Contains(got.Error.Message, secret) {
		t.Fatalf("error message leaked secret: %q", got.Error.Message)
	}
	for _, err := range got.Error.Errors {
		if strings.Contains(err.Message, secret) {
			t.Fatalf("validation message leaked secret: %q", err.Message)
		}
	}
}

func TestSignIDUsesCurrentSecretNotAltSecret(t *testing.T) {
	store := validStore([]byte("current-secret"))
	cypher := store.Cyphers["product"]
	cypher.AltSecret = []byte("previous-secret")
	store.Cyphers["product"] = cypher
	crypt := newTestCrypt(t, store)

	got := crypt.SignID("product", IDPayload{ID: "product123"})
	if got.Status != Success {
		t.Fatalf("status = %q, error = %#v, want success", got.Status, got.Error)
	}

	token, err := extractToken("product", got.Value)
	if err != nil {
		t.Fatalf("extractToken() error = %#v", err)
	}
	if _, err := verifyClaims(token, []byte("current-secret"), Sufficient); err != nil {
		t.Fatalf("verify with current secret: %v", err)
	}
	if _, err := verifyClaims(token, []byte("previous-secret"), Sufficient); err == nil {
		t.Fatal("verify with previous secret succeeded, want signing to use current secret only")
	}
}

func newTestCrypt(t *testing.T, store Store) *Crypt {
	t.Helper()
	crypt, err := New(store)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	crypt.now = func() time.Time {
		return fixedNow()
	}
	return crypt
}
