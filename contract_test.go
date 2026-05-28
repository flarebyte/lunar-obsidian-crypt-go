package lunarcrypt

import (
	"encoding/json"
	"os"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

type contractFixtures struct {
	FixedNowUnix        int64    `json:"fixedNowUnix"`
	CurrentSecret       string   `json:"currentSecret"`
	PreviousSecret      string   `json:"previousSecret"`
	OtherSecret         string   `json:"otherSecret"`
	ProductPrefix       string   `json:"productPrefix"`
	CompanyPrefix       string   `json:"companyPrefix"`
	TenantProductPrefix string   `json:"tenantProductPrefix"`
	ProductID           string   `json:"productID"`
	Account             string   `json:"account"`
	Roles               []string `json:"roles"`
}

func TestContractSignAlgorithms(t *testing.T) {
	fixture := loadContractFixtures(t)
	tests := []struct {
		name     string
		strength EncryptionStrength
		wantAlg  string
	}{
		{name: "sign-hs256", strength: Sufficient, wantAlg: "HS256"},
		{name: "sign-hs384", strength: Good, wantAlg: "HS384"},
		{name: "sign-hs512", strength: Strong, wantAlg: "HS512"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			crypt := newContractCrypt(t, fixture, tt.strength, nil, nil)
			got := crypt.SignID(fixture.ProductPrefix, IDPayload{ID: fixture.ProductID})
			if got.Status != Success {
				t.Fatalf("status = %q, error = %#v, want success", got.Status, got.Error)
			}
			prefix, token, tokenErr := extractTokenPrefix(got.Value, []string{fixture.ProductPrefix})
			if tokenErr != nil {
				t.Fatalf("extractTokenPrefix() error = %#v", tokenErr)
			}
			if prefix != fixture.ProductPrefix {
				t.Fatalf("prefix = %q, want %q", prefix, fixture.ProductPrefix)
			}
			if alg := jwtHeaderAlg(t, token); alg != tt.wantAlg {
				t.Fatalf("alg = %q, want %q", alg, tt.wantAlg)
			}
		})
	}
}

func TestContractVerifyPrefix(t *testing.T) {
	fixture := loadContractFixtures(t)
	fullToken := composeFullToken(fixture.TenantProductPrefix, "header.payload.signature")

	prefix, token, err := extractTokenPrefix(fullToken, []string{fixture.TenantProductPrefix})
	if err != nil {
		t.Fatalf("extractTokenPrefix() error = %#v", err)
	}
	if prefix != fixture.TenantProductPrefix {
		t.Fatalf("prefix = %q, want %q", prefix, fixture.TenantProductPrefix)
	}
	if token != "header.payload.signature" {
		t.Fatalf("token = %q, want header.payload.signature", token)
	}
}

func TestContractVerifyFailureSteps(t *testing.T) {
	fixture := loadContractFixtures(t)
	crypt := newContractCrypt(t, fixture, Sufficient, nil, nil)
	signResult := crypt.SignID(fixture.ProductPrefix, IDPayload{ID: fixture.ProductID})
	if signResult.Status != Success {
		t.Fatalf("sign status = %q, error = %#v, want success", signResult.Status, signResult.Error)
	}

	tests := []struct {
		name     string
		verify   func() Result[IDPayload]
		wantStep string
	}{
		{
			name: "verify-wrong-prefix",
			verify: func() Result[IDPayload] {
				return crypt.VerifyIDByPrefix(fixture.CompanyPrefix, signResult.Value)
			},
			wantStep: StepVerifyIDExtractToken,
		},
		{
			name: "verify-unknown-prefix",
			verify: func() Result[IDPayload] {
				return crypt.VerifyID(composeFullToken("unknown", "header.payload.signature"))
			},
			wantStep: StepVerifyIDExtractToken,
		},
		{
			name: "expired-token",
			verify: func() Result[IDPayload] {
				token := signContractClaims(t, fixture, jwt.MapClaims{
					"id":  fixture.ProductID,
					"exp": int64(1),
				}, fixture.CurrentSecret, Sufficient)
				return crypt.VerifyID(composeFullToken(fixture.ProductPrefix, token))
			},
			wantStep: StepVerifyIDVerifyToken,
		},
		{
			name: "invalid-payload",
			verify: func() Result[IDPayload] {
				token := signContractClaims(t, fixture, jwt.MapClaims{
					"exp": contractNow(fixture).Add(time.Hour).Unix(),
				}, fixture.CurrentSecret, Sufficient)
				return crypt.VerifyID(composeFullToken(fixture.ProductPrefix, token))
			},
			wantStep: StepVerifyIDValidatePayload,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.verify()
			assertFailureStep(t, got, tt.wantStep)
		})
	}
}

func TestContractScopeBehavior(t *testing.T) {
	fixture := loadContractFixtures(t)

	t.Run("scope-string-match", func(t *testing.T) {
		crypt := newContractCrypt(t, fixture, Sufficient, map[string]ScopeValue{
			"account": {fixture.Account},
		}, nil)
		got := crypt.SignID(fixture.ProductPrefix, IDPayload{
			ID:    fixture.ProductID,
			Scope: map[string]ScopeValue{"account": {fixture.Account}},
		})
		if got.Status != Success {
			t.Fatalf("sign status = %q, error = %#v, want success", got.Status, got.Error)
		}
		verified := crypt.VerifyID(got.Value)
		if verified.Status != Success {
			t.Fatalf("verify status = %q, error = %#v, want success", verified.Status, verified.Error)
		}
	})

	t.Run("scope-list-match", func(t *testing.T) {
		crypt := newContractCrypt(t, fixture, Sufficient, map[string]ScopeValue{
			"roles": ScopeValue(fixture.Roles),
		}, nil)
		got := crypt.SignID(fixture.ProductPrefix, IDPayload{
			ID:    fixture.ProductID,
			Scope: map[string]ScopeValue{"roles": ScopeValue(fixture.Roles)},
		})
		if got.Status != Success {
			t.Fatalf("sign status = %q, error = %#v, want success", got.Status, got.Error)
		}
		verified := crypt.VerifyID(got.Value)
		if verified.Status != Success {
			t.Fatalf("verify status = %q, error = %#v, want success", verified.Status, verified.Error)
		}
	})

	t.Run("scope-missing", func(t *testing.T) {
		crypt := newContractCrypt(t, fixture, Sufficient, map[string]ScopeValue{
			"account": {fixture.Account},
		}, nil)
		got := crypt.SignID(fixture.ProductPrefix, IDPayload{ID: fixture.ProductID})
		if got.Status != Success {
			t.Fatalf("sign status = %q, error = %#v, want success", got.Status, got.Error)
		}
		verified := crypt.VerifyID(got.Value)
		assertFailureStep(t, verified, StepVerifyIDVerifyScope)
	})

	t.Run("scope-validator-error", func(t *testing.T) {
		crypt := newContractCrypt(t, fixture, Sufficient, nil, func(scope map[string]ScopeValue) error {
			return errContractScopeRejected{}
		})
		got := crypt.SignID(fixture.ProductPrefix, IDPayload{
			ID:    fixture.ProductID,
			Scope: map[string]ScopeValue{"account": {fixture.Account}},
		})
		if got.Status != Success {
			t.Fatalf("sign status = %q, error = %#v, want success", got.Status, got.Error)
		}
		verified := crypt.VerifyID(got.Value)
		assertFailureStep(t, verified, StepVerifyIDVerifyScope)
	})
}

func TestContractAltSecretBehavior(t *testing.T) {
	fixture := loadContractFixtures(t)

	t.Run("alt-secret-success", func(t *testing.T) {
		crypt := newContractCryptWithAltSecret(t, fixture)
		token := signContractClaims(t, fixture, jwt.MapClaims{
			"id":  fixture.ProductID,
			"exp": contractNow(fixture).Add(time.Hour).Unix(),
		}, fixture.PreviousSecret, Sufficient)
		got := crypt.VerifyID(composeFullToken(fixture.ProductPrefix, token))
		if got.Status != Success {
			t.Fatalf("status = %q, error = %#v, want success", got.Status, got.Error)
		}
		if got.Value.ID != fixture.ProductID {
			t.Fatalf("id = %q, want %q", got.Value.ID, fixture.ProductID)
		}
	})

	t.Run("alt-secret-failure", func(t *testing.T) {
		crypt := newContractCryptWithAltSecret(t, fixture)
		token := signContractClaims(t, fixture, jwt.MapClaims{
			"id":  fixture.ProductID,
			"exp": contractNow(fixture).Add(time.Hour).Unix(),
		}, fixture.OtherSecret, Sufficient)
		got := crypt.VerifyID(composeFullToken(fixture.ProductPrefix, token))
		assertFailureStep(t, got, StepVerifyIDVerifyToken)
		if got.Error.FinalMessage != "Verification with previous secret failed as well" {
			t.Fatalf("finalMessage = %q, want previous secret failure", got.Error.FinalMessage)
		}
	})
}

func loadContractFixtures(t *testing.T) contractFixtures {
	t.Helper()
	content, err := os.ReadFile("testdata/contract-fixtures.json")
	if err != nil {
		t.Fatalf("read contract fixtures: %v", err)
	}
	var fixture contractFixtures
	if err := json.Unmarshal(content, &fixture); err != nil {
		t.Fatalf("unmarshal contract fixtures: %v", err)
	}
	return fixture
}

func newContractCrypt(t *testing.T, fixture contractFixtures, strength EncryptionStrength, expectedScope map[string]ScopeValue, validator ScopeValidator) *Crypt {
	t.Helper()
	store := Store{
		Title: "Contract signing store",
		Cyphers: map[string]TranslucentLizardCypher{
			fixture.ProductPrefix: {
				Kind:           TranslucentLizard,
				Title:          "Sign product IDs",
				Secret:         []byte(fixture.CurrentSecret),
				Strength:       strength,
				Expiration:     Expiration{Value: 2, Unit: Hours},
				ExpectedScope:  expectedScope,
				ScopeValidator: validator,
			},
			fixture.CompanyPrefix: {
				Kind:       TranslucentLizard,
				Title:      "Sign company IDs",
				Secret:     []byte("contract-company-secret-not-real"),
				Strength:   Sufficient,
				Expiration: Expiration{Value: 2, Unit: Hours},
			},
		},
	}
	crypt := newTestCrypt(t, store)
	crypt.now = func() time.Time {
		return contractNow(fixture)
	}
	return crypt
}

func newContractCryptWithAltSecret(t *testing.T, fixture contractFixtures) *Crypt {
	t.Helper()
	crypt := newContractCrypt(t, fixture, Sufficient, nil, nil)
	cypher := crypt.store.Cyphers[fixture.ProductPrefix]
	cypher.AltSecret = []byte(fixture.PreviousSecret)
	crypt.store.Cyphers[fixture.ProductPrefix] = cypher
	return crypt
}

func signContractClaims(t *testing.T, fixture contractFixtures, claims jwt.MapClaims, secret string, strength EncryptionStrength) string {
	t.Helper()
	token, err := signClaims(claims, []byte(secret), strength)
	if err != nil {
		t.Fatalf("sign contract claims: %v", err)
	}
	return token
}

func contractNow(fixture contractFixtures) time.Time {
	return time.Unix(fixture.FixedNowUnix, 0).UTC()
}

type errContractScopeRejected struct{}

func (errContractScopeRejected) Error() string {
	return "contract scope rejected"
}
