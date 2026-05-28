package lunarcrypt

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
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

func TestVerifyIDSuccess(t *testing.T) {
	crypt := newTestCrypt(t, validStore([]byte("current-secret")))
	signResult := crypt.SignID("product", IDPayload{
		ID:    "product123",
		Scope: map[string]ScopeValue{"account": {"account890"}},
	})
	if signResult.Status != Success {
		t.Fatalf("sign status = %q, error = %#v, want success", signResult.Status, signResult.Error)
	}

	got := crypt.VerifyID(signResult.Value)
	if got.Status != Success {
		t.Fatalf("verify status = %q, error = %#v, want success", got.Status, got.Error)
	}
	if got.Value.ID != "product123" {
		t.Fatalf("id = %q, want product123", got.Value.ID)
	}
	if got.Value.Scope["account"][0] != "account890" {
		t.Fatalf("scope = %#v, want account890", got.Value.Scope)
	}
}

func TestVerifyIDByPrefixRejectsWrongPrefix(t *testing.T) {
	store := validStore([]byte("current-secret"))
	store.Cyphers["company"] = TranslucentLizardCypher{
		Kind:       TranslucentLizard,
		Title:      "Sign company IDs",
		Secret:     []byte("company-secret"),
		Strength:   Sufficient,
		Expiration: Expiration{Value: 2, Unit: Hours},
	}
	crypt := newTestCrypt(t, store)
	signResult := crypt.SignID("product", IDPayload{ID: "product123"})

	got := crypt.VerifyIDByPrefix("company", signResult.Value)
	assertFailureStep(t, got, StepVerifyIDExtractToken)
}

func TestVerifyIDRejectsUnknownPrefix(t *testing.T) {
	crypt := newTestCrypt(t, validStore([]byte("current-secret")))

	got := crypt.VerifyID("company:header.payload.signature")
	assertFailureStep(t, got, StepVerifyIDExtractToken)
}

func TestVerifyIDRejectsMalformedToken(t *testing.T) {
	crypt := newTestCrypt(t, validStore([]byte("current-secret")))

	got := crypt.VerifyID("product:not-a-jwt")
	assertFailureStep(t, got, StepVerifyIDDecodeToken)
}

func TestVerifyIDRejectsInvalidPayload(t *testing.T) {
	crypt := newTestCrypt(t, validStore([]byte("current-secret")))
	token, err := signClaims(jwt.MapClaims{"exp": fixedNow().Add(time.Hour).Unix()}, []byte("current-secret"), Sufficient)
	if err != nil {
		t.Fatalf("signClaims() error = %v", err)
	}

	got := crypt.VerifyID(composeFullToken("product", token))
	assertFailureStep(t, got, StepVerifyIDValidatePayload)
	if len(got.Error.Errors) == 0 || got.Error.Errors[0].Path != "id" {
		t.Fatalf("validation errors = %#v, want id error", got.Error.Errors)
	}
}

func TestVerifyIDRejectsExpiredToken(t *testing.T) {
	crypt := newTestCrypt(t, validStore([]byte("current-secret")))
	token, err := signClaims(jwt.MapClaims{
		"id":  "product123",
		"exp": time.Now().Add(-time.Hour).Unix(),
	}, []byte("current-secret"), Sufficient)
	if err != nil {
		t.Fatalf("signClaims() error = %v", err)
	}

	got := crypt.VerifyID(composeFullToken("product", token))
	assertFailureStep(t, got, StepVerifyIDVerifyToken)
}

func TestVerifyIDRejectsBadSignature(t *testing.T) {
	crypt := newTestCrypt(t, validStore([]byte("current-secret")))
	token, err := signClaims(jwt.MapClaims{
		"id":  "product123",
		"exp": fixedNow().Add(time.Hour).Unix(),
	}, []byte("other-secret"), Sufficient)
	if err != nil {
		t.Fatalf("signClaims() error = %v", err)
	}

	got := crypt.VerifyID(composeFullToken("product", token))
	assertFailureStep(t, got, StepVerifyIDVerifyToken)
}

func TestVerifyIDRejectsWrongAlgorithm(t *testing.T) {
	crypt := newTestCrypt(t, validStore([]byte("current-secret")))
	token, err := signClaims(jwt.MapClaims{
		"id":  "product123",
		"exp": fixedNow().Add(time.Hour).Unix(),
	}, []byte("current-secret"), Strong)
	if err != nil {
		t.Fatalf("signClaims() error = %v", err)
	}

	got := crypt.VerifyID(composeFullToken("product", token))
	assertFailureStep(t, got, StepVerifyIDVerifyToken)
}

func TestVerifyIDRejectsScopeMismatch(t *testing.T) {
	store := validStore([]byte("current-secret"))
	cypher := store.Cyphers["product"]
	cypher.ExpectedScope = map[string]ScopeValue{"account": {"account890"}}
	store.Cyphers["product"] = cypher
	crypt := newTestCrypt(t, store)
	signResult := crypt.SignID("product", IDPayload{
		ID:    "product123",
		Scope: map[string]ScopeValue{"account": {"other"}},
	})

	got := crypt.VerifyID(signResult.Value)
	assertFailureStep(t, got, StepVerifyIDVerifyScope)
}

func TestVerifyIDRejectsCustomScopeValidatorFailure(t *testing.T) {
	store := validStore([]byte("current-secret"))
	cypher := store.Cyphers["product"]
	cypher.ScopeValidator = func(scope map[string]ScopeValue) error {
		return errors.New("account is blocked")
	}
	store.Cyphers["product"] = cypher
	crypt := newTestCrypt(t, store)
	signResult := crypt.SignID("product", IDPayload{
		ID:    "product123",
		Scope: map[string]ScopeValue{"account": {"account890"}},
	})

	got := crypt.VerifyID(signResult.Value)
	assertFailureStep(t, got, StepVerifyIDVerifyScope)
}

func TestVerifyIDAltSecretSuccess(t *testing.T) {
	store := validStore([]byte("current-secret"))
	cypher := store.Cyphers["product"]
	cypher.AltSecret = []byte("previous-secret")
	store.Cyphers["product"] = cypher
	crypt := newTestCrypt(t, store)
	token, err := signClaims(jwt.MapClaims{
		"id":  "product123",
		"exp": fixedNow().Add(time.Hour).Unix(),
	}, []byte("previous-secret"), Sufficient)
	if err != nil {
		t.Fatalf("signClaims() error = %v", err)
	}

	got := crypt.VerifyID(composeFullToken("product", token))
	if got.Status != Success {
		t.Fatalf("status = %q, error = %#v, want success", got.Status, got.Error)
	}
	if got.Value.ID != "product123" {
		t.Fatalf("id = %q, want product123", got.Value.ID)
	}
}

func TestVerifyIDAltSecretFailure(t *testing.T) {
	store := validStore([]byte("current-secret"))
	cypher := store.Cyphers["product"]
	cypher.AltSecret = []byte("previous-secret")
	store.Cyphers["product"] = cypher
	crypt := newTestCrypt(t, store)
	token, err := signClaims(jwt.MapClaims{
		"id":  "product123",
		"exp": fixedNow().Add(time.Hour).Unix(),
	}, []byte("other-secret"), Sufficient)
	if err != nil {
		t.Fatalf("signClaims() error = %v", err)
	}

	got := crypt.VerifyID(composeFullToken("product", token))
	assertFailureStep(t, got, StepVerifyIDVerifyToken)
	if got.Error.FinalMessage != "Verification with previous secret failed as well" {
		t.Fatalf("finalMessage = %q, want previous secret failure", got.Error.FinalMessage)
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

func assertFailureStep[T any](t *testing.T, got Result[T], wantStep string) {
	t.Helper()
	if got.Status != Failure {
		t.Fatalf("status = %q, want failure", got.Status)
	}
	if got.Error == nil {
		t.Fatal("error = nil, want error")
	}
	if got.Error.Step != wantStep {
		t.Fatalf("step = %q, want %q", got.Error.Step, wantStep)
	}
}
