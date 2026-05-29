package lunarcrypt

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

func TestSigningMethodForStrength(t *testing.T) {
	for _, tt := range signingAlgorithmCases("sufficient", "good", "strong") {
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
	for _, tt := range signingAlgorithmCases("hs256", "hs384", "hs512") {
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

func TestTranslucentLizardSignIDCreatesPrefixedJWT(t *testing.T) {
	for _, tt := range signingAlgorithmCases("hs256", "hs384", "hs512") {
		t.Run(tt.name, func(t *testing.T) {
			cypher := validCypher([]byte("current-secret"))
			cypher.Strength = tt.strength
			got := translucentLizardSignID("product", cypher, IDPayload{
				ID:    "product123",
				Scope: map[string]ScopeValue{"account": {"account890"}},
			}, fixedNow)
			if got.Status != Success {
				t.Fatalf("status = %q, error = %#v, want success", got.Status, got.Error)
			}
			token, tokenErr := extractToken("product", got.Value)
			if tokenErr != nil {
				t.Fatalf("extractToken() error = %#v", tokenErr)
			}
			if alg := jwtHeaderAlg(t, token); alg != tt.wantAlg {
				t.Fatalf("JWT alg = %q, want %q", alg, tt.wantAlg)
			}

			claims, err := verifyClaims(token, []byte("current-secret"), tt.strength)
			if err != nil {
				t.Fatalf("verifyClaims() error = %v", err)
			}
			if claims["id"] != "product123" {
				t.Fatalf("id claim = %#v, want product123", claims["id"])
			}
			if gotExp := int64(claims["exp"].(float64)); gotExp != 4102452000 {
				t.Fatalf("exp claim = %d, want 4102452000", gotExp)
			}
			scope, ok := claims["scope"].(map[string]any)
			if !ok {
				t.Fatalf("scope claim = %#v, want map", claims["scope"])
			}
			account, ok := scope["account"].([]any)
			if !ok || len(account) != 1 || account[0] != "account890" {
				t.Fatalf("scope account = %#v, want account890", scope["account"])
			}
		})
	}
}

type signingAlgorithmCase struct {
	name     string
	strength EncryptionStrength
	wantAlg  string
}

func signingAlgorithmCases(sufficientName, goodName, strongName string) []signingAlgorithmCase {
	return []signingAlgorithmCase{
		{name: sufficientName, strength: Sufficient, wantAlg: "HS256"},
		{name: goodName, strength: Good, wantAlg: "HS384"},
		{name: strongName, strength: Strong, wantAlg: "HS512"},
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

func fixedNow() time.Time {
	return time.Unix(4102444800, 0).UTC()
}
