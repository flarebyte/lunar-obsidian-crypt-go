package lunarcrypt

import (
	"encoding/base64"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

func TestSecurityRejectsTamperedPayload(t *testing.T) {
	crypt := newTestCrypt(t, validStore([]byte("current-secret")))
	signResult := crypt.SignID("product", IDPayload{ID: "product123"})
	if signResult.Status != Success {
		t.Fatalf("sign status = %q, error = %#v, want success", signResult.Status, signResult.Error)
	}

	token, tokenErr := extractToken("product", signResult.Value)
	if tokenErr != nil {
		t.Fatalf("extractToken() error = %#v", tokenErr)
	}
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		t.Fatalf("JWT parts = %d, want 3", len(parts))
	}
	tamperedPayload := base64.RawURLEncoding.EncodeToString([]byte(`{"id":"product999","exp":4102452000}`))
	tampered := parts[0] + "." + tamperedPayload + "." + parts[2]

	got := crypt.VerifyID(composeFullToken("product", tampered))
	assertFailureStep(t, got, StepVerifyIDVerifyToken)
}

func TestSecurityRejectsTamperedSignature(t *testing.T) {
	crypt := newTestCrypt(t, validStore([]byte("current-secret")))
	signResult := crypt.SignID("product", IDPayload{ID: "product123"})
	if signResult.Status != Success {
		t.Fatalf("sign status = %q, error = %#v, want success", signResult.Status, signResult.Error)
	}

	token, tokenErr := extractToken("product", signResult.Value)
	if tokenErr != nil {
		t.Fatalf("extractToken() error = %#v", tokenErr)
	}
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		t.Fatalf("JWT parts = %d, want 3", len(parts))
	}
	tampered := parts[0] + "." + parts[1] + ".tampered-signature"

	got := crypt.VerifyID(composeFullToken("product", tampered))
	assertFailureStep(t, got, StepVerifyIDVerifyToken)
}

func TestSecurityRejectsMalformedCompactJWTs(t *testing.T) {
	crypt := newTestCrypt(t, validStore([]byte("current-secret")))
	tests := []string{
		"one-part",
		"two.parts",
		"too.many.parts.here",
		"not-base64.payload.signature",
	}

	for _, token := range tests {
		t.Run(token, func(t *testing.T) {
			got := crypt.VerifyID(composeFullToken("product", token))
			assertFailureStep(t, got, StepVerifyIDVerifyToken)
		})
	}
}

func TestSecurityRejectsUnrelatedSecret(t *testing.T) {
	crypt := newTestCrypt(t, validStore([]byte("current-secret")))
	token, err := signClaims(jwt.MapClaims{
		"id":  "product123",
		"exp": fixedNow().Add(time.Hour).Unix(),
	}, []byte("unrelated-secret"), Sufficient)
	if err != nil {
		t.Fatalf("signClaims() error = %v", err)
	}

	got := crypt.VerifyID(composeFullToken("product", token))
	assertFailureStep(t, got, StepVerifyIDVerifyToken)
}

func TestSecurityRejectsUnexpectedClaimShapes(t *testing.T) {
	crypt := newTestCrypt(t, validStore([]byte("current-secret")))
	token, err := signClaims(jwt.MapClaims{
		"id":    []string{"product123"},
		"exp":   fixedNow().Add(time.Hour).Unix(),
		"scope": "not-an-object",
	}, []byte("current-secret"), Sufficient)
	if err != nil {
		t.Fatalf("signClaims() error = %v", err)
	}

	got := crypt.VerifyID(composeFullToken("product", token))
	assertFailureStep(t, got, StepVerifyIDValidatePayload)
}
