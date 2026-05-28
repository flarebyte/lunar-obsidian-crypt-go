# lunar-obsidian-crypt-go

Sign and verify application IDs as prefixed JWT tokens in Go.

![Lunar Obsidian Crypt Go hero](doc/lunar-obsidian-crypt-go-hero.png)

This project is a Go port of the TypeScript library
[`lunar-obsidian-crypt`](https://github.com/flarebyte/lunar-obsidian-crypt).
It is currently in the specification stage. The intended API is documented
below so consumers can review the library shape before the first implementation.

## What It Does

`lunar-obsidian-crypt-go` creates compact tokens for application resource IDs:

```text
prefix:jwt-token
```

The prefix selects the signing configuration. The JWT payload is signed with an
HMAC algorithm and can later be verified with the same configured prefix.

Use it when you need to:

- sign IDs such as product, company, tenant, account, or internal resource IDs
- attach optional scope to a token
- verify that a token was signed by a configured secret
- rotate secrets with a current and previous secret
- return structured success or failure values instead of panics or exceptions

## Security Boundary

This library signs data; it does not encrypt data.

JWT payloads are visible to anyone who holds the token. Do not put passwords,
API keys, secrets, or private user data in the payload. Store only identifiers
and scope values that are safe to reveal.

## Planned Installation

After the first release:

```bash
go get github.com/flarebyte/lunar-obsidian-crypt-go
```

The planned JWT implementation dependency is
[`github.com/golang-jwt/jwt/v5`](https://pkg.go.dev/github.com/golang-jwt/jwt/v5).

## Basic Usage

Create a store with one or more prefixes:

```go
package main

import (
	"log"

	lunarcrypt "github.com/flarebyte/lunar-obsidian-crypt-go"
)

func main() {
	crypt, err := lunarcrypt.New(lunarcrypt.Store{
		Title: "Business ID signing store",
		Cyphers: map[string]lunarcrypt.TranslucentLizardCypher{
			"product": {
				Kind:       lunarcrypt.TranslucentLizard,
				Title:      "Sign product IDs",
				Secret:     []byte("replace-with-a-long-random-secret"),
				Strength:   lunarcrypt.Sufficient,
				Expiration: lunarcrypt.Expiration{Value: 2, Unit: lunarcrypt.Hours},
			},
			"company": {
				Kind:          lunarcrypt.TranslucentLizard,
				Title:         "Sign company IDs",
				Secret:        []byte("replace-with-another-long-random-secret"),
				AltSecret:     []byte("replace-with-previous-secret-during-rotation"),
				Strength:      lunarcrypt.Strong,
				Expiration:    lunarcrypt.Expiration{Value: 2, Unit: lunarcrypt.Weeks},
				ExpectedScope: map[string]lunarcrypt.ScopeValue{"account": {"account890"}},
			},
		},
	})
	if err != nil {
		log.Fatal(err)
	}

	_ = crypt
}
```

The first Go release is planned to support both plain `Store` structs and an
ergonomic builder API. The same setup should also be possible with a builder:

```go
store, err := lunarcrypt.NewBuilder().
	SetTitle("Business ID signing store").
	AddTranslucentLizard("product", lunarcrypt.TranslucentLizardCypher{
		Kind:       lunarcrypt.TranslucentLizard,
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
```

## Sign An ID

```go
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
```

`fullToken` will use the prefixed token format:

```text
product:eyJ...
```

## Verify A Token

```go
verifyResult := crypt.VerifyID(fullToken)
if verifyResult.Status == lunarcrypt.Failure {
	log.Printf("verify failed at %s: %s", verifyResult.Error.Step, verifyResult.Error.Message)
	return
}

payload := verifyResult.Value
```

Successful verification returns the application payload without the JWT `exp`
claim.

## Verify A Specific Prefix

Use `VerifyIDByPrefix` when the caller already knows which prefix must be used:

```go
verifyResult := crypt.VerifyIDByPrefix("product", fullToken)
if verifyResult.Status == lunarcrypt.Failure {
	log.Printf("verify failed at %s", verifyResult.Error.Step)
	return
}
```

If the embedded token prefix does not match the requested prefix, verification
fails.

## Scope Checks

A cypher can require scope values:

```go
ExpectedScope: map[string]lunarcrypt.ScopeValue{
	"account": {"account890"},
}
```

During verification, every configured expected scope key must be present and
must match the decoded payload scope by value.

For custom policy, attach a validator:

```go
ScopeValidator: func(scope map[string]lunarcrypt.ScopeValue) error {
	if len(scope["account"]) == 0 {
		return fmt.Errorf("account is required")
	}
	return nil
}
```

## Secret Rotation

Set `AltSecret` during rotation:

```go
TranslucentLizardCypher{
	Secret:    []byte("current-secret"),
	AltSecret: []byte("previous-secret"),
}
```

Verification tries the current secret first. If that fails, it tries the
previous secret. Signing always uses the current secret.

## Strength Mapping

| Strength | JWT algorithm |
| --- | --- |
| `Sufficient` | `HS256` |
| `Good` | `HS384` |
| `Strong` | `HS512` |

## Result Shape

Expected signing and verification failures return `Result[T]` values:

```go
type Result[T any] struct {
	Status ResultStatus
	Value  T
	Error  *CryptError
}
```

Configuration errors are returned by `New(store)` as Go errors because they are
setup failures and should be fixed before runtime use.

## Error Steps

Callers can branch on stable error step IDs:

| Step | Meaning |
| --- | --- |
| `sign-id/store` | signing prefix or cypher is not configured |
| `sign-id/validate-payload` | payload is invalid before signing |
| `sign-id/sign` | JWT signing failed |
| `verify-id/extract-token` | full token prefix or token syntax is invalid |
| `verify-id/store` | verification prefix or cypher is not configured |
| `verify-id/decode-token` | token decoding failed |
| `verify-id/validate-payload` | decoded payload shape is invalid |
| `verify-id/verify-scope` | expected or custom scope check failed |
| `verify-id/verify-token` | signature, expiration, or JWT verification failed |

## Design Specification

The protocol and Go implementation notes are maintained in `doc/design-meta`
and generated with:

```bash
make doc-design
```

Read the generated specification at
[`doc/design/lunar-obsidian-crypt-spec.md`](doc/design/lunar-obsidian-crypt-spec.md).
