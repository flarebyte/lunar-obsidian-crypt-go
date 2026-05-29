package lunarcrypt_test

import (
	"errors"
	"log"

	lunarcrypt "github.com/flarebyte/lunar-obsidian-crypt-go"
)

func ExampleNew_plainStore() {
	store := exampleStore(map[string]lunarcrypt.TranslucentLizardCypher{
		"product": exampleProductCypher(),
		"company": {
			Kind:          lunarcrypt.TranslucentLizard,
			Title:         "Sign company IDs",
			Secret:        []byte("replace-with-another-long-random-secret"),
			AltSecret:     []byte("replace-with-previous-secret-during-rotation"),
			Strength:      lunarcrypt.Strong,
			Expiration:    lunarcrypt.Expiration{Value: 2, Unit: lunarcrypt.Weeks},
			ExpectedScope: map[string]lunarcrypt.ScopeValue{"account": {"account890"}},
		},
	})
	crypt, err := lunarcrypt.New(store)
	if err != nil {
		log.Fatal(err)
	}

	_ = crypt
}

func ExampleNewBuilder() {
	store, err := lunarcrypt.NewBuilder().
		SetTitle("Business ID signing store").
		AddTranslucentLizard("product", lunarcrypt.TranslucentLizardCypher{
			Title:      "Sign product IDs",
			Secret:     []byte("replace-with-a-long-random-secret"),
			Strength:   lunarcrypt.Sufficient,
			Expiration: lunarcrypt.Expiration{Value: 2, Unit: lunarcrypt.Hours},
		}).
		Build()
	if err != nil {
		log.Fatal(err)
	}

	crypt, err := lunarcrypt.New(store)
	if err != nil {
		log.Fatal(err)
	}

	_ = crypt
}

func ExampleCrypt_SignID() {
	crypt := exampleCrypt()
	payload := lunarcrypt.IDPayload{
		ID: "product123",
		Scope: map[string]lunarcrypt.ScopeValue{
			"account": {"account890"},
		},
	}

	signResult := crypt.SignID("product", payload)
	if signResult.Status == lunarcrypt.Failure {
		log.Printf("sign failed at %s: %s", signResult.Error.Step, signResult.Error.Message)
		return
	}

	fullToken := signResult.Value
	_ = fullToken
}

func ExampleCrypt_VerifyID() {
	crypt := exampleCrypt()
	signResult := crypt.SignID("product", lunarcrypt.IDPayload{
		ID:    "product123",
		Scope: map[string]lunarcrypt.ScopeValue{"account": {"account890"}},
	})
	if signResult.Status == lunarcrypt.Failure {
		log.Printf("sign failed at %s: %s", signResult.Error.Step, signResult.Error.Message)
		return
	}

	verifyResult := crypt.VerifyID(signResult.Value)
	if verifyResult.Status == lunarcrypt.Failure {
		log.Printf("verify failed at %s: %s", verifyResult.Error.Step, verifyResult.Error.Message)
		return
	}

	payload := verifyResult.Value
	_ = payload
}

func ExampleCrypt_VerifyIDByPrefix() {
	crypt := exampleCrypt()
	signResult := crypt.SignID("product", lunarcrypt.IDPayload{ID: "product123"})
	if signResult.Status == lunarcrypt.Failure {
		log.Printf("sign failed at %s: %s", signResult.Error.Step, signResult.Error.Message)
		return
	}

	verifyResult := crypt.VerifyIDByPrefix("product", signResult.Value)
	if verifyResult.Status == lunarcrypt.Failure {
		log.Printf("verify failed at %s", verifyResult.Error.Step)
		return
	}
}

func ExampleTranslucentLizardCypher_expectedScope() {
	cypher := exampleProductCypher()
	cypher.ExpectedScope = map[string]lunarcrypt.ScopeValue{"account": {"account890"}}
	crypt, err := lunarcrypt.New(exampleStore(map[string]lunarcrypt.TranslucentLizardCypher{"product": cypher}))
	if err != nil {
		log.Fatal(err)
	}

	_ = crypt
}

func ExampleTranslucentLizardCypher_scopeValidator() {
	cypher := exampleProductCypher()
	cypher.ScopeValidator = func(scope map[string]lunarcrypt.ScopeValue) error {
		if len(scope["account"]) == 0 {
			return errors.New("account is required")
		}
		return nil
	}
	crypt, err := lunarcrypt.New(exampleStore(map[string]lunarcrypt.TranslucentLizardCypher{"product": cypher}))
	if err != nil {
		log.Fatal(err)
	}

	_ = crypt
}

func ExampleTranslucentLizardCypher_secretRotation() {
	cypher := exampleProductCypher()
	cypher.Secret = []byte("current-secret")
	cypher.AltSecret = []byte("previous-secret")
	crypt, err := lunarcrypt.New(exampleStore(map[string]lunarcrypt.TranslucentLizardCypher{"product": cypher}))
	if err != nil {
		log.Fatal(err)
	}

	_ = crypt
}

func exampleCrypt() *lunarcrypt.Crypt {
	crypt, err := lunarcrypt.New(exampleStore(map[string]lunarcrypt.TranslucentLizardCypher{
		"product": exampleProductCypher(),
	}))
	if err != nil {
		log.Fatal(err)
	}
	return crypt
}

func exampleStore(cyphers map[string]lunarcrypt.TranslucentLizardCypher) lunarcrypt.Store {
	return lunarcrypt.Store{
		Title:   "Business ID signing store",
		Cyphers: cyphers,
	}
}

func exampleProductCypher() lunarcrypt.TranslucentLizardCypher {
	return lunarcrypt.TranslucentLizardCypher{
		Kind:       lunarcrypt.TranslucentLizard,
		Title:      "Sign product IDs",
		Secret:     []byte("replace-with-a-long-random-secret"),
		Strength:   lunarcrypt.Sufficient,
		Expiration: lunarcrypt.Expiration{Value: 2, Unit: lunarcrypt.Hours},
	}
}
