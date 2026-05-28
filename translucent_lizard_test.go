package lunarcrypt

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"

	"github.com/golang-jwt/jwt/v5"
)

func TestSigningMethodForStrength(t *testing.T) {
	tests := []struct {
		name     string
		strength EncryptionStrength
		wantAlg  string
	}{
		{name: "sufficient", strength: Sufficient, wantAlg: "HS256"},
		{name: "good", strength: Good, wantAlg: "HS384"},
		{name: "strong", strength: Strong, wantAlg: "HS512"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			method, err := signingMethodForStrength(tt.strength)
			if err != nil {
				t.Fatalf("signingMethodForStrength() error = %v", err)
			}
			if method.Alg() != tt.wantAlg {
				t.Fatalf("alg = %q, want %q", method.Alg(), tt.wantAlg)
			}
		})
	}
}

func TestSigningMethodForStrengthRejectsUnknownStrength(t *testing.T) {
	if _, err := signingMethodForStrength(EncryptionStrength("weak")); err == nil {
		t.Fatal("signingMethodForStrength() error = nil, want error")
	}
}

func TestSignClaimsUsesExpectedAlgorithm(t *testing.T) {
	tests := []struct {
		name     string
		strength EncryptionStrength
		wantAlg  string
	}{
		{name: "hs256", strength: Sufficient, wantAlg: "HS256"},
		{name: "hs384", strength: Good, wantAlg: "HS384"},
		{name: "hs512", strength: Strong, wantAlg: "HS512"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tokenText, err := signClaims(jwt.MapClaims{"id": "product123"}, []byte("secret"), tt.strength)
			if err != nil {
				t.Fatalf("signClaims() error = %v", err)
			}
			if got := jwtHeaderAlg(t, tokenText); got != tt.wantAlg {
				t.Fatalf("JWT alg = %q, want %q", got, tt.wantAlg)
			}
		})
	}
}

func TestVerifyClaimsAcceptsMatchingHMACMethod(t *testing.T) {
	tokenText, err := signClaims(jwt.MapClaims{"id": "product123"}, []byte("secret"), Strong)
	if err != nil {
		t.Fatalf("signClaims() error = %v", err)
	}

	claims, err := verifyClaims(tokenText, []byte("secret"), Strong)
	if err != nil {
		t.Fatalf("verifyClaims() error = %v", err)
	}
	if claims["id"] != "product123" {
		t.Fatalf("id claim = %#v, want product123", claims["id"])
	}
}

func TestVerifyClaimsRejectsAlgorithmConfusion(t *testing.T) {
	tests := []struct {
		name           string
		tokenStrength  EncryptionStrength
		verifyStrength EncryptionStrength
	}{
		{name: "hs256 token as hs512", tokenStrength: Sufficient, verifyStrength: Strong},
		{name: "hs512 token as hs256", tokenStrength: Strong, verifyStrength: Sufficient},
		{name: "hs384 token as hs256", tokenStrength: Good, verifyStrength: Sufficient},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tokenText, err := signClaims(jwt.MapClaims{"id": "product123"}, []byte("secret"), tt.tokenStrength)
			if err != nil {
				t.Fatalf("signClaims() error = %v", err)
			}

			if _, err := verifyClaims(tokenText, []byte("secret"), tt.verifyStrength); err == nil {
				t.Fatal("verifyClaims() error = nil, want algorithm mismatch error")
			}
		})
	}
}

func TestVerifyClaimsRejectsNoneAlgorithm(t *testing.T) {
	token := jwt.NewWithClaims(jwt.SigningMethodNone, jwt.MapClaims{"id": "product123"})
	tokenText, err := token.SignedString(jwt.UnsafeAllowNoneSignatureType)
	if err != nil {
		t.Fatalf("sign none token: %v", err)
	}

	if _, err := verifyClaims(tokenText, []byte("secret"), Sufficient); err == nil {
		t.Fatal("verifyClaims() error = nil, want none algorithm rejection")
	}
}

func TestVerifyClaimsRejectsNonHMACAlgorithm(t *testing.T) {
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{"id": "product123"})
	signingString, err := token.SigningString()
	if err != nil {
		t.Fatalf("build RSA signing string: %v", err)
	}
	tokenText := signingString + ".signature"

	if _, err := verifyClaims(tokenText, []byte("secret"), Sufficient); err == nil {
		t.Fatal("verifyClaims() error = nil, want non-HMAC algorithm rejection")
	}
}

func jwtHeaderAlg(t *testing.T, tokenText string) string {
	t.Helper()
	parts := strings.Split(tokenText, ".")
	if len(parts) != 3 {
		t.Fatalf("JWT has %d parts, want 3", len(parts))
	}

	headerBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		t.Fatalf("decode JWT header: %v", err)
	}
	var header struct {
		Alg string `json:"alg"`
	}
	if err := json.Unmarshal(headerBytes, &header); err != nil {
		t.Fatalf("unmarshal JWT header: %v", err)
	}
	return header.Alg
}
