package lunarcrypt

import (
	"strings"
	"testing"
	"time"
)

func TestExpirationDuration(t *testing.T) {
	tests := []struct {
		name string
		in   Expiration
		want time.Duration
	}{
		{name: "seconds", in: Expiration{Value: 2, Unit: Seconds}, want: 2 * time.Second},
		{name: "minutes", in: Expiration{Value: 2, Unit: Minutes}, want: 2 * time.Minute},
		{name: "hours", in: Expiration{Value: 2, Unit: Hours}, want: 2 * time.Hour},
		{name: "days", in: Expiration{Value: 2, Unit: Days}, want: 48 * time.Hour},
		{name: "weeks", in: Expiration{Value: 2, Unit: Weeks}, want: 14 * 24 * time.Hour},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.in.Duration()
			if err != nil {
				t.Fatalf("Duration() error = %v", err)
			}
			if got != tt.want {
				t.Fatalf("Duration() = %s, want %s", got, tt.want)
			}
		})
	}
}

func TestExpirationDurationRejectsInvalidValues(t *testing.T) {
	tests := []struct {
		name string
		in   Expiration
	}{
		{name: "zero value", in: Expiration{Value: 0, Unit: Seconds}},
		{name: "negative value", in: Expiration{Value: -1, Unit: Seconds}},
		{name: "too large", in: Expiration{Value: 1000001, Unit: Seconds}},
		{name: "unknown unit", in: Expiration{Value: 1, Unit: TimeUnit("fortnights")}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := tt.in.Duration(); err == nil {
				t.Fatal("Duration() error = nil, want error")
			}
		})
	}
}

func TestNewRejectsInvalidStore(t *testing.T) {
	secret := "very-secret-value"
	tests := []struct {
		name      string
		mutate    func(Store) Store
		wantError string
	}{
		{
			name: "empty store title",
			mutate: func(store Store) Store {
				store.Title = ""
				return store
			},
			wantError: "store title is required",
		},
		{
			name: "overlong store title",
			mutate: func(store Store) Store {
				store.Title = strings.Repeat("a", 51)
				return store
			},
			wantError: "store title must be at most 50 characters",
		},
		{
			name: "multiline store title",
			mutate: func(store Store) Store {
				store.Title = "line one\nline two"
				return store
			},
			wantError: "store title must be a single line",
		},
		{
			name: "empty cypher map",
			mutate: func(store Store) Store {
				store.Cyphers = map[string]TranslucentLizardCypher{}
				return store
			},
			wantError: "store must include at least one cypher",
		},
		{
			name: "empty prefix",
			mutate: func(store Store) Store {
				cypher := store.Cyphers["product"]
				store.Cyphers = map[string]TranslucentLizardCypher{"": cypher}
				return store
			},
			wantError: "prefix is required",
		},
		{
			name: "invalid kind",
			mutate: func(store Store) Store {
				cypher := store.Cyphers["product"]
				cypher.Kind = CypherKind("other")
				store.Cyphers["product"] = cypher
				return store
			},
			wantError: `kind must be "translucent-lizard"`,
		},
		{
			name: "missing cypher title",
			mutate: func(store Store) Store {
				cypher := store.Cyphers["product"]
				cypher.Title = ""
				store.Cyphers["product"] = cypher
				return store
			},
			wantError: `cypher "product" title is required`,
		},
		{
			name: "missing secret",
			mutate: func(store Store) Store {
				cypher := store.Cyphers["product"]
				cypher.Secret = nil
				store.Cyphers["product"] = cypher
				return store
			},
			wantError: `cypher "product" secret is required`,
		},
		{
			name: "invalid strength",
			mutate: func(store Store) Store {
				cypher := store.Cyphers["product"]
				cypher.Strength = EncryptionStrength("weak")
				store.Cyphers["product"] = cypher
				return store
			},
			wantError: `strength "weak" is not supported`,
		},
		{
			name: "invalid expiration",
			mutate: func(store Store) Store {
				cypher := store.Cyphers["product"]
				cypher.Expiration = Expiration{Value: 0, Unit: Hours}
				store.Cyphers["product"] = cypher
				return store
			},
			wantError: "expiration is invalid",
		},
		{
			name: "invalid expected scope",
			mutate: func(store Store) Store {
				cypher := store.Cyphers["product"]
				cypher.ExpectedScope = map[string]ScopeValue{"account": {}}
				store.Cyphers["product"] = cypher
				return store
			},
			wantError: `expected scope "account" must include at least one value`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := New(tt.mutate(validStore([]byte(secret))))
			if err == nil {
				t.Fatal("New() error = nil, want error")
			}
			if !strings.Contains(err.Error(), tt.wantError) {
				t.Fatalf("New() error = %q, want to contain %q", err, tt.wantError)
			}
			if strings.Contains(err.Error(), secret) {
				t.Fatalf("New() error leaked secret: %q", err)
			}
		})
	}
}

func TestNewCopiesStore(t *testing.T) {
	secret := []byte("current-secret")
	store := validStore(secret)
	cypher := store.Cyphers["product"]
	cypher.AltSecret = []byte("previous-secret")
	cypher.ExpectedScope = map[string]ScopeValue{"account": {"account890"}}
	store.Cyphers["product"] = cypher

	crypt, err := New(store)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	store.Title = "mutated"
	product := store.Cyphers["product"]
	product.Secret[0] = 'X'
	product.AltSecret[0] = 'X'
	product.ExpectedScope["account"][0] = "mutated"
	store.Cyphers["product"] = product
	store.Cyphers["other"] = product

	got := crypt.store.Cyphers["product"]
	if crypt.store.Title != "Business ID signing store" {
		t.Fatalf("stored title = %q, want original", crypt.store.Title)
	}
	if string(got.Secret) != "current-secret" {
		t.Fatalf("stored secret was mutated: %q", got.Secret)
	}
	if string(got.AltSecret) != "previous-secret" {
		t.Fatalf("stored alt secret was mutated: %q", got.AltSecret)
	}
	if got.ExpectedScope["account"][0] != "account890" {
		t.Fatalf("stored expected scope was mutated: %q", got.ExpectedScope["account"][0])
	}
	if _, ok := crypt.store.Cyphers["other"]; ok {
		t.Fatal("stored cypher map was mutated after New")
	}
}

func validStore(secret []byte) Store {
	return Store{
		Title: "Business ID signing store",
		Cyphers: map[string]TranslucentLizardCypher{
			"product": {
				Kind:       TranslucentLizard,
				Title:      "Sign product IDs",
				Secret:     append([]byte(nil), secret...),
				Strength:   Sufficient,
				Expiration: Expiration{Value: 2, Unit: Hours},
			},
		},
	}
}
