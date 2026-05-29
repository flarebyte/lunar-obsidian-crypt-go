package lunarcrypt

import (
	"strings"
	"testing"
)

func TestBuilderBuildsPlainStore(t *testing.T) {
	store, err := NewBuilder().
		SetTitle("Business ID signing store").
		AddTranslucentLizard("product", TranslucentLizardCypher{
			Title:      "Sign product IDs",
			Secret:     []byte("current-secret"),
			Strength:   Sufficient,
			Expiration: Expiration{Value: 2, Unit: Hours},
		}).
		Build()
	if err != nil {
		t.Fatalf("Build() error = %v", err)
	}

	cypher := store.Cyphers["product"]
	if store.Title != "Business ID signing store" {
		t.Fatalf("store title = %q, want configured title", store.Title)
	}
	if cypher.Kind != TranslucentLizard {
		t.Fatalf("builder cypher kind = %q, want %q", cypher.Kind, TranslucentLizard)
	}
	if _, err := New(store); err != nil {
		t.Fatalf("New(builder store) error = %v", err)
	}
}

func TestBuilderRejectsDuplicatePrefixes(t *testing.T) {
	secret := "current-secret"
	builder := NewBuilder().
		SetTitle("Business ID signing store").
		AddTranslucentLizard("product", validCypher([]byte(secret))).
		AddTranslucentLizard("product", validCypher([]byte(secret)))
	builder.AddTranslucentLizard("company", validCypher([]byte(secret)))

	_, err := builder.Build()
	if err == nil {
		t.Fatal("Build() error = nil, want duplicate prefix error")
	}
	if !strings.Contains(err.Error(), `cypher prefix "product" is already configured`) {
		t.Fatalf("Build() error = %q, want duplicate prefix", err)
	}
	if strings.Contains(err.Error(), secret) {
		t.Fatalf("Build() error leaked secret: %q", err)
	}
}

func TestBuilderNilReceiverMethods(t *testing.T) {
	var builder *Builder
	if got := builder.SetTitle("Business ID signing store"); got != nil {
		t.Fatalf("SetTitle() = %#v, want nil", got)
	}
	if got := builder.AddTranslucentLizard("product", validCypher([]byte("current-secret"))); got != nil {
		t.Fatalf("AddTranslucentLizard() = %#v, want nil", got)
	}
	if _, err := builder.Build(); err == nil {
		t.Fatal("Build() error = nil, want nil builder error")
	}
}

func TestBuilderRejectsInvalidInputsThroughStoreValidation(t *testing.T) {
	secret := "current-secret"
	_, err := NewBuilder().
		SetTitle("Business ID signing store").
		AddTranslucentLizard("", validCypher([]byte(secret))).
		Build()
	if err == nil {
		t.Fatal("Build() error = nil, want invalid prefix error")
	}
	if !strings.Contains(err.Error(), "prefix is required") {
		t.Fatalf("Build() error = %q, want prefix validation error", err)
	}
	if strings.Contains(err.Error(), secret) {
		t.Fatalf("Build() error leaked secret: %q", err)
	}
}

func TestBuilderStoreIsIndependent(t *testing.T) {
	cypher := validCypher([]byte("current-secret"))
	builder := NewBuilder().
		SetTitle("Business ID signing store").
		AddTranslucentLizard("product", cypher)
	cypher.Secret[0] = 'X'

	store, err := builder.Build()
	if err != nil {
		t.Fatalf("Build() error = %v", err)
	}
	if string(store.Cyphers["product"].Secret) != "current-secret" {
		t.Fatalf("builder stored caller secret mutation: %q", store.Cyphers["product"].Secret)
	}

	store.Cyphers["product"].Secret[0] = 'Y'
	storeAgain, err := builder.Build()
	if err != nil {
		t.Fatalf("Build() second error = %v", err)
	}
	if string(storeAgain.Cyphers["product"].Secret) != "current-secret" {
		t.Fatalf("builder returned mutable internal secret: %q", storeAgain.Cyphers["product"].Secret)
	}
}

func TestBuilderAndPlainStoreAreEquivalent(t *testing.T) {
	plain := validStore([]byte("current-secret"))
	built, err := NewBuilder().
		SetTitle(plain.Title).
		AddTranslucentLizard("product", plain.Cyphers["product"]).
		Build()
	if err != nil {
		t.Fatalf("Build() error = %v", err)
	}

	if built.Title != plain.Title {
		t.Fatalf("built title = %q, want %q", built.Title, plain.Title)
	}
	if got, want := built.Cyphers["product"], plain.Cyphers["product"]; !sameCypher(got, want) {
		t.Fatalf("built cypher = %#v, want %#v", got, want)
	}
}

func validCypher(secret []byte) TranslucentLizardCypher {
	return TranslucentLizardCypher{
		Kind:       TranslucentLizard,
		Title:      "Sign product IDs",
		Secret:     append([]byte(nil), secret...),
		Strength:   Sufficient,
		Expiration: Expiration{Value: 2, Unit: Hours},
	}
}

func sameCypher(got TranslucentLizardCypher, want TranslucentLizardCypher) bool {
	return got.Kind == want.Kind &&
		got.Title == want.Title &&
		string(got.Secret) == string(want.Secret) &&
		string(got.AltSecret) == string(want.AltSecret) &&
		got.Strength == want.Strength &&
		got.Expiration == want.Expiration
}
