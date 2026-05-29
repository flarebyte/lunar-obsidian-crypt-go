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

func TestSignClaimsRejectsUnknownStrength(t *testing.T) {
	if _, err := signClaims(jwt.MapClaims{"id": "product123"}, []byte("secret"), EncryptionStrength("weak")); err == nil {
		t.Fatal("signClaims() error = nil, want unknown strength error")
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

func TestTranslucentLizardSignIDRejectsInvalidExpiration(t *testing.T) {
	cypher := validCypher([]byte("current-secret"))
	cypher.Expiration = Expiration{Value: 0, Unit: Hours}

	got := translucentLizardSignID("product", cypher, IDPayload{ID: "product123"}, fixedNow)
	assertFailureStep(t, got, StepSignIDSign)
}

func TestTranslucentLizardSignIDRejectsInvalidStrength(t *testing.T) {
	cypher := validCypher([]byte("current-secret"))
	cypher.Strength = EncryptionStrength("weak")

	got := translucentLizardSignID("product", cypher, IDPayload{ID: "product123"}, fixedNow)
	assertFailureStep(t, got, StepSignIDSign)
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

func TestVerifyClaimsRejectsUnknownStrength(t *testing.T) {
	if _, err := verifyClaims("header.payload.signature", []byte("secret"), EncryptionStrength("weak")); err == nil {
		t.Fatal("verifyClaims() error = nil, want unknown strength error")
	}
}

func TestVerifyClaimsRejectsUnsignedGarbage(t *testing.T) {
	if _, err := verifyClaims("header.payload.signature", []byte("secret"), Sufficient); err == nil {
		t.Fatal("verifyClaims() error = nil, want parse error")
	}
}

func TestIsDecodeTokenError(t *testing.T) {
	validHeader := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"HS256"}`))
	validPayload := base64.RawURLEncoding.EncodeToString([]byte(`{"id":"product123"}`))
	invalidJSON := base64.RawURLEncoding.EncodeToString([]byte("not-json"))

	tests := []struct {
		name string
		in   string
		want bool
	}{
		{name: "valid compact shape", in: validHeader + "." + validPayload + ".signature"},
		{name: "invalid header base64", in: "*.payload.signature", want: true},
		{name: "invalid payload base64", in: validHeader + ".not-base64.signature", want: true},
		{name: "invalid payload json", in: validHeader + "." + invalidJSON + ".signature", want: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isDecodeTokenError(tt.in); got != tt.want {
				t.Fatalf("isDecodeTokenError() = %t, want %t", got, tt.want)
			}
		})
	}
}

func TestClaimInt64(t *testing.T) {
	tests := []struct {
		name string
		in   any
		want int64
		ok   bool
	}{
		{name: "float", in: float64(42), want: 42, ok: true},
		{name: "float zero", in: float64(0)},
		{name: "float fractional", in: float64(1.5)},
		{name: "int64", in: int64(42), want: 42, ok: true},
		{name: "int64 negative", in: int64(-1), want: -1},
		{name: "int", in: int(42), want: 42, ok: true},
		{name: "int zero", in: int(0)},
		{name: "string", in: "42"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := claimInt64(tt.in)
			if got != tt.want || ok != tt.ok {
				t.Fatalf("claimInt64(%#v) = %d, %t; want %d, %t", tt.in, got, ok, tt.want, tt.ok)
			}
		})
	}
}

func TestScopeFromClaim(t *testing.T) {
	got, errs := scopeFromClaim(map[string]any{
		"account": "account890",
		"roles":   []any{"admin", "editor"},
		"groups":  []string{"staff"},
	})
	if len(errs) > 0 {
		t.Fatalf("scopeFromClaim() errors = %#v, want none", errs)
	}
	if got["account"][0] != "account890" || got["roles"][1] != "editor" || got["groups"][0] != "staff" {
		t.Fatalf("scopeFromClaim() = %#v", got)
	}
}

func TestScopeFromClaimRejectsInvalidShapes(t *testing.T) {
	tests := []struct {
		name     string
		in       any
		wantPath string
	}{
		{name: "not object", in: "scope", wantPath: "scope"},
		{name: "list item not string", in: map[string]any{"roles": []any{"admin", 1}}, wantPath: "scope.roles[1]"},
		{name: "unsupported value", in: map[string]any{"roles": []int{1}}, wantPath: "scope.roles"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, errs := scopeFromClaim(tt.in)
			if len(errs) != 1 || errs[0].Path != tt.wantPath {
				t.Fatalf("scopeFromClaim() errors = %#v, want path %q", errs, tt.wantPath)
			}
		})
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
