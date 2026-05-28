# Lunar Obsidian Crypt Protocol Specification

Language-neutral specification reverse engineered from the TypeScript implementation.

## 01 Overview

Protocol intent, terminology, and portability boundaries.

### 01 Intent

What this specification captures.

#### Intent

This specification captures the protocol behind `lunar-obsidian-crypt` independently of the current TypeScript implementation.

The core protocol signs application ID payloads into prefixed compact JWT tokens. A target implementation in TypeScript, Go, or another language should preserve the same token syntax, payload validation, algorithm mapping, scope verification, secret rotation behavior, and structured result shape.

#### Security Model

The current protocol is a signing protocol, not an encryption protocol. Payload claims are visible to any holder of the token.

Secrets must be opaque byte arrays supplied by the embedding application. Implementations should rely on a JOSE-compatible JWT library for HMAC signing and verification rather than custom cryptographic code.

#### Terminology

- Store: named collection of cypher configurations.
- Prefix: application-level token namespace placed before the JWT token.
- Full token: `prefix:jwt-token`.
- Cypher: versionable signing configuration selected by prefix.
- Translucent Lizard: current cypher kind based on signed visible JWT payloads.
- Scope: optional key-value context used to restrict token validity.
- Result: success or failure value returned as data.

### 02 Use Cases

Actors and goals supported by the protocol.

#### Use Cases

| actor | goal | notes | success_output | usecase |
| --- | --- | --- | --- | --- |
| application developer | Define a named key store with one or more signing prefixes | Prefix names are application-level identifiers and are not JWT claims | Store model with title and cypher map | configure-store |
| application service | Create a portable signed token for a resource identifier | Payload remains visible because the protocol signs but does not encrypt | prefix:jwt full token | sign-resource-id |
| application service | Recover and validate the ID payload from a full token | Prefix selects the cypher before signature verification | ID payload without exp | verify-prefixed-token |
| application service | Require selected scope fields or custom scope rules | Scope checks happen during verification | Failure when mandatory scope requirements are not met | restrict-token-scope |
| operations team | Accept tokens signed with the previous secret during migration | Current secret is tried first and alternate secret is a fallback | Verified payload when alternate secret succeeds | rotate-secret |
| application service | Return deterministic failure details for malformed expired or mismatched tokens | Callers should branch on result status rather than exceptions | Failure result with step and message | reject-invalid-token |

### 03 Language Portability

How the same protocol maps across implementation languages.

#### Language Portability

| concern | go_mapping_guidance | portable_spec | typescript_mapping |
| --- | --- | --- | --- |
| result handling | Struct with Status plus Value or Error fields | Return success or failure as data | Discriminated union with status |
| byte secrets | []byte | Secrets are opaque byte arrays | Uint8Array |
| time expiration | time.Duration derived from value and unit | Relative expiration is value plus unit | string passed to JOSE setExpirationTime |
| jwt library | golang-jwt or another JOSE-compatible library | Use JOSE-compatible HMAC JWT implementation | jose package |
| validation | Constructor validation or explicit validation functions | Validate store config and payload shape before use | zod and faora-kai |
| scope validator | function returning nil or error string | Allow local policy over decoded scope | function returning true or reason string |
| prefix parsing | LastIndexByte or equivalent | Split full token at the final colon | split reverse join |
| token visibility | JWS compact token | Payload is signed and visible not encrypted | JWS compact token |

## 02 Protocol Model

Canonical model, token syntax, and operation rules.

### 01 Domain Models

Portable data model extracted from TypeScript schemas.

#### Domain Models

| constraints | description | field | model | required | type |
| --- | --- | --- | --- | --- | --- |
| 1-50 single-line characters | Human-readable store title | title | Store | yes | string |
| prefix keys are stable string key names | Named signing configurations addressable by token prefix | cyphers | Store | yes | map<prefix Cypher> |
| translucent-lizard | Discriminator for the cypher protocol | kind | Cypher | yes | string literal |
| 1-50 single-line characters | Human-readable signing purpose | title | TranslucentLizard | yes | string |
| long random secret recommended | Shared secret used for HMAC signing and verification | secret | TranslucentLizard | yes | byte array |
| long random previous secret recommended | Previous secret accepted for rotation fallback | altSecret | TranslucentLizard | no | byte array |
| sufficient\|good\|strong | Security level mapped to a JWT HMAC algorithm | strength | TranslucentLizard | yes | enum |
| value and unit | Relative lifetime applied when signing | expiration | TranslucentLizard | yes | Expiration |
| string keys and string or string-list values | Subset of scope values required at verification time | expectedScope | TranslucentLizard | no | map<string ScopeValue> |
| scope -> true or reason string | Implementation-provided additional scope policy | scopeValidator | TranslucentLizard | no | function |
| 1..1000000 | Positive relative expiration quantity | value | Expiration | yes | integer |
| seconds\|minutes\|hours\|days\|weeks | Relative expiration unit | unit | Expiration | yes | enum |
| 1-400 characters | Application resource identifier | id | IdPayload | yes | string |
| string keys and string or string-list values | Optional authorization or tenant context | scope | IdPayload | no | map<string ScopeValue> |
| positive safe number | JWT expiration claim required after decoding | exp | ProtectedPayload | yes | number |
| success\|failure | Railway-style operation status | status | Result | yes | enum |
| matches operation success type | Returned when status is success | value | Success | yes | generic |
| matches failure schema | Returned when status is failure | error | Failure | yes | CryptError |

#### Portable API Types

```ts
export type TimeUnit = 'seconds' | 'minutes' | 'hours' | 'days' | 'weeks';

export type EncryptionStrength = 'sufficient' | 'good' | 'strong';

export type Expiration = {
  value: number;
  unit: TimeUnit;
};

export type ScopeValue = string | string[];

export type IdPayload = {
  id: string;
  scope?: Record<string, ScopeValue>;
};

export type ProtectedPayload = IdPayload & {
  exp: number;
};

export type TranslucentLizardCypher = {
  kind: 'translucent-lizard';
  title: string;
  secret: Uint8Array;
  altSecret?: Uint8Array;
  strength: EncryptionStrength;
  expiration: Expiration;
  expectedScope?: Record<string, ScopeValue>;
  scopeValidator?: (
    scope: Record<string, ScopeValue>
  ) => true | string;
};

export type Cypher = TranslucentLizardCypher;

export type StoreModel = {
  title: string;
  cyphers: Record<string, Cypher>;
};

export type ValidationError = {
  message: string;
  path: string;
};

export type CryptError =
  | {
      step: 'sign-id/validate-payload' | 'verify-id/validate-payload';
      errors: ValidationError[];
    }
  | {
      step:
        | 'sign-id/sign'
        | 'verify-id/extract-token'
        | 'verify-id/decode-token'
        | 'verify-id/verify-token'
        | 'verify-id/verify-scope'
        | 'verify-id/store'
        | 'sign-id/store';
      message: string;
      finalMessage?: string;
    };

export type Result<T, E> =
  | {status: 'success'; value: T}
  | {status: 'failure'; error: E};

export interface LunarObsidianCryptProtocol {
  signId(prefix: string, payload: IdPayload): Promise<Result<string, CryptError>>;
  verifyId(fullToken: string): Promise<Result<IdPayload, CryptError>>;
  verifyIdByPrefix(
    prefix: string,
    fullToken: string
  ): Promise<Result<IdPayload, CryptError>>;
}
```

### 02 Token And Algorithm Rules

Token syntax, signing algorithms, and normative behavior.

#### Algorithm Matrix

| implementation_note | jwt_algorithm | minimum_semantics | strength |
| --- | --- | --- | --- |
| Default fallback in the TypeScript implementation | HS256 | HMAC with SHA-256 | sufficient |
| Use a JOSE-compatible JWT library in each target language | HS384 | HMAC with SHA-384 | good |
| Use the same protected header alg value across implementations | HS512 | HMAC with SHA-512 | strong |

#### Protocol Rules

| area | normative_statement | rationale | rule |
| --- | --- | --- | --- |
| token syntax | A full token MUST be encoded as prefix:jwt-token. | The prefix is outside the JWT and selects the cypher configuration | full-token-format |
| token syntax | The verifier MUST treat the text after the final colon as the JWT token and the text before it as the prefix. | This permits prefixes that themselves contain colons | prefix-splitting |
| verification | verifyId MUST reject a token whose extracted prefix is empty or unsupported. | A token cannot be safely verified without a known cypher | prefix-selection |
| verification | verifyIdByPrefix MUST reject a full token whose embedded prefix differs from the requested prefix. | Callers cannot accidentally verify a token under a different namespace | explicit-prefix-verification |
| security | The protocol MUST be described as signing rather than encryption because JWT payload fields are visible. | Prevents callers from storing secrets in the payload | visible-payload |
| signing | Signing MUST validate the ID payload before creating a JWT. | Invalid payloads should fail before any cryptographic operation | payload-validation |
| signing | Signing MUST add a relative expiration claim to the JWT. | Verified tokens need a bounded lifetime | expiration-claim |
| verification | When expectedScope is configured every expected key MUST match the decoded scope value. | The configured scope is a mandatory subset rather than a full equality check | scope-subset |
| verification | When a custom scope validator is configured the decoded payload MUST include scope and the validator MUST return true. | Allows language implementations to attach local policy | scope-validator |
| verification | Verification MUST first try the current secret. | Normal traffic should use the active secret | verify-current-secret |
| verification | Verification MAY try altSecret only after current-secret verification fails. | Supports secret rotation without masking current-secret success | verify-alt-secret |
| success result | Successful verification MUST return the ID payload without exposing exp as an application field. | Expiration is a protocol claim rather than part of the domain payload | strip-exp |
| errors | Operations MUST return structured failure results instead of throwing for expected validation and verification failures. | Makes behavior portable across languages | error-result |

### 03 Message Examples

Representative store, request, response, and failure shapes.

#### Message Examples

```ts
export const storeExample = {
  title: 'Business ID signing store',
  cyphers: {
    product: {
      kind: 'translucent-lizard',
      title: 'Sign product IDs',
      secret: '<opaque bytes>',
      strength: 'sufficient',
      expiration: {value: 2, unit: 'hours'},
    },
    company: {
      kind: 'translucent-lizard',
      title: 'Sign company IDs',
      secret: '<opaque bytes>',
      altSecret: '<previous opaque bytes>',
      strength: 'strong',
      expiration: {value: 2, unit: 'weeks'},
      expectedScope: {account: 'account890'},
    },
  },
} as const;

export const signRequest = {
  prefix: 'product',
  payload: {
    id: 'product123',
    scope: {account: 'account890'},
  },
} as const;

export const signSuccess = {
  status: 'success',
  value: 'product:eyJhbGciOiJIUzI1NiJ9.eyJpZCI6InByb2R1Y3QxMjMiLCJleHAiOjE3MDAwMDAwMDB9.signature',
} as const;

export const verifyRequest = {
  fullToken: signSuccess.value,
} as const;

export const verifySuccess = {
  status: 'success',
  value: {
    id: 'product123',
    scope: {account: 'account890'},
  },
} as const;

export const scopeFailure = {
  status: 'failure',
  error: {
    step: 'verify-id/verify-scope',
    message: 'The following fields [account] from the scope did not match the expectations',
  },
} as const;
```

## 03 Workflows

End-to-end signing and verification behavior.

### 01 Operation Flow

Ordered protocol steps.

#### Operation Flow

| input | operation | output | portable_requirement | step |
| --- | --- | --- | --- | --- |
| builder calls or equivalent configuration | build-store | Store model | Language implementations may use builders structs or config files if they produce the same model | 1 |
| prefix and IdPayload | signId | Result<string CryptError> | Unsupported prefix fails with step sign-id/store | 2 |
| IdPayload | validate-sign-payload | valid payload or validation error | ID must be present and scope values must be string or string-list | 3 |
| valid payload cypher secret expiration strength | create-jwt | JWT token | Protected header alg is derived from strength | 4 |
| prefix and JWT token | compose-full-token | prefix:jwt-token | Prefix is prepended outside the JWT with a colon separator | 5 |
| full token | verifyId | Result<IdPayload CryptError> | Prefix is extracted then delegated to prefix-specific verification | 6 |
| expected prefix and full token | extract-token | JWT token or extraction error | Embedded prefix must match the expected prefix | 7 |
| JWT token and current or alternate secret | verify-signature | Verified JWT claims or verification error | Go verifies signature algorithm expiration and signature before accepting claims or scope | 8 |
| Verified JWT claims | decode-and-validate | ProtectedPayload or validation error | Decoded verified claims must include id and exp | 9 |
| ProtectedPayload and cypher scope policy | check-scope | scope accepted or verification error | Expected scope and custom validator are checked only after signature verification | 10 |
| ProtectedPayload | return-payload | IdPayload | The exp claim is removed from the application payload | 11 |

### 02 Operation Graph

Graph view of the sign and verify flow.

- <a id="graph-node-crypt-flow-build-store"></a> Build Store: Build or load the store model containing supported prefixes and cypher configurations.
  - <a id="graph-node-crypt-flow-sign"></a> Sign Payload: Validate an ID payload, create a JWT with the configured algorithm and expiration, and prepend the prefix.
    - <a id="graph-node-crypt-flow-extract-prefix"></a> Extract Prefix: Read the prefix from the full token and select the configured cypher.
      - <a id="graph-node-crypt-flow-verify-scope"></a> Verify Scope: Validate decoded payload shape and enforce configured expected scope and custom scope policy.
        - <a id="graph-node-crypt-flow-verify-signature"></a> Verify Signature: Verify the JWT with the current secret and optionally the previous secret.
          - <a id="graph-node-crypt-flow-return-result"></a> Return Result: Return a structured success payload without `exp` or a structured failure error.

### 03 Error Catalog

Stable error steps and expected failure shape.

#### Error Catalog

| error_shape | phase | step | trigger |
| --- | --- | --- | --- |
| message | signing | sign-id/store | Requested signing prefix is not configured |
| validation errors with message and path | signing | sign-id/validate-payload | Input payload fails IdPayload validation |
| message | signing | sign-id/sign | JWT library cannot sign the token |
| message | verification | verify-id/extract-token | Full token has no prefix unsupported prefix wrong prefix or missing token |
| message | verification | verify-id/store | Requested verification prefix is not configured |
| message | verification | verify-id/decode-token | JWT cannot be decoded or parsed far enough to inspect claims before validation |
| validation errors with message and path | verification | verify-id/validate-payload | Decoded JWT payload fails ProtectedPayload validation |
| message | verification | verify-id/verify-scope | Scope is missing mismatched or rejected by validator |
| message and optional finalMessage | verification | verify-id/verify-token | JWT is expired has a bad signature or cannot be verified |

## 04 Go Implementation

Concrete Go library guidance derived from the portable protocol.

### 01 API Shape

Suggested public Go surface and domain types.

#### Go API Sketch

```go
package lunarcrypt

import "time"

type TimeUnit string

const (
	Seconds TimeUnit = "seconds"
	Minutes TimeUnit = "minutes"
	Hours   TimeUnit = "hours"
	Days    TimeUnit = "days"
	Weeks   TimeUnit = "weeks"
)

type EncryptionStrength string

const (
	Sufficient EncryptionStrength = "sufficient"
	Good       EncryptionStrength = "good"
	Strong     EncryptionStrength = "strong"
)

type CypherKind string

const (
	TranslucentLizard CypherKind = "translucent-lizard"
)

type ResultStatus string

const (
	Success ResultStatus = "success"
	Failure ResultStatus = "failure"
)

type Expiration struct {
	Value int
	Unit  TimeUnit
}

func (e Expiration) Duration() (time.Duration, error) {
	// Implementations should reject unknown units and non-positive values.
	return 0, nil
}

type ScopeValue []string

type IDPayload struct {
	ID    string                `json:"id"`
	Scope map[string]ScopeValue `json:"scope,omitempty"`
}

type ProtectedPayload struct {
	ID    string                `json:"id"`
	Scope map[string]ScopeValue `json:"scope,omitempty"`
	Exp   int64                 `json:"exp"`
}

type ScopeValidator func(scope map[string]ScopeValue) error

type TranslucentLizardCypher struct {
	Kind           CypherKind
	Title          string
	Secret         []byte
	AltSecret      []byte
	Strength       EncryptionStrength
	Expiration     Expiration
	ExpectedScope  map[string]ScopeValue
	ScopeValidator ScopeValidator
}

type Store struct {
	Title   string
	Cyphers map[string]TranslucentLizardCypher
}

type Builder struct {
	store Store
}

func NewBuilder() *Builder {
	return nil
}

func (b *Builder) SetTitle(title string) *Builder {
	return b
}

func (b *Builder) AddTranslucentLizard(prefix string, cypher TranslucentLizardCypher) *Builder {
	return b
}

func (b *Builder) Build() (Store, error) {
	return Store{}, nil
}

type ValidationError struct {
	Message string `json:"message"`
	Path    string `json:"path"`
}

type CryptError struct {
	Step         string            `json:"step"`
	Message      string            `json:"message,omitempty"`
	FinalMessage string            `json:"finalMessage,omitempty"`
	Errors       []ValidationError `json:"errors,omitempty"`
}

type Result[T any] struct {
	Status ResultStatus `json:"status"`
	Value  T            `json:"value,omitempty"`
	Error  *CryptError  `json:"error,omitempty"`
}

type Crypt struct {
	store    Store
	prefixes []string
}

func New(store Store) (*Crypt, error) {
	return nil, nil
}

func (c *Crypt) SignID(prefix string, payload IDPayload) Result[string] {
	return Result[string]{}
}

func (c *Crypt) VerifyID(fullToken string) Result[IDPayload] {
	return Result[IDPayload]{}
}

func (c *Crypt) VerifyIDByPrefix(prefix string, fullToken string) Result[IDPayload] {
	return Result[IDPayload]{}
}
```

#### Go Implementation Decisions

| decision | go_guidance | rationale |
| --- | --- | --- |
| api-shape | Expose a small synchronous API with New Store SignID VerifyID and VerifyIDByPrefix | HMAC signing and verification are CPU-local operations and do not need context unless a future key provider is introduced |
| configuration-api | Include both plain Store structs and an ergonomic Builder API in the first Go release | Plain structs keep configuration transparent and testable while the builder gives users a safer guided setup path |
| result-shape | Return Result[T] values instead of Go errors for expected signing and verification failures | Preserves the TypeScript railway-style contract and keeps callers branching on status |
| constructor-validation | Return (*Crypt error) from New when store configuration is invalid | Configuration errors are programmer/setup failures and should be caught before runtime signing |
| payload-validation | Return failure Result values for invalid payloads passed to SignID or decoded from tokens | Payload failures are part of normal data handling and map to stable protocol steps |
| scope-value | Represent scope values as []string and normalize single string values into one-element slices during JSON decoding | Go cannot express string\|string[] directly and slice equality should be value-based |
| scope-comparison | Compare expected scope values by normalized string-slice contents rather than reference identity | The TypeScript implementation currently uses Object.is which makes array scope portability ambiguous |
| expiration | Convert Expiration to time.Duration and reject non-positive values or unknown units | Go callers should get deterministic validation before token creation |
| jwt-library | Use a maintained JWT or JOSE library and explicitly restrict accepted methods to HS256 HS384 and HS512 | Prevents algorithm confusion and preserves the strength mapping |
| token-parsing | Use strings.LastIndexByte(fullToken ':') to split prefix from JWT | Matches the final-colon rule and supports prefixes that contain colons |
| verification-order | Verify JWT algorithm signature and expiration before accepting claims validating payload shape or checking scope | This intentionally favors Go trust boundaries over the TypeScript decode-before-verify order |
| decode-token-errors | Use verify-id/decode-token only when a JWT cannot be decoded or parsed before claims validation | Separates malformed token structure from verified claims that fail payload validation |
| alt-secret | Try the current secret first and only try AltSecret after current verification fails | Preserves rotation behavior and makes finalMessage meaningful when both secrets fail |
| exp-stripping | Return IDPayload without Exp on successful verification | Keeps JWT protocol claims out of application payloads |
| error-ids | Keep step strings byte-for-byte stable across Go and TypeScript | Allows cross-language tests and caller logic to rely on deterministic failures |
| test-vectors | Add fixed-secret fixed-time contract tests before implementing release behavior | Prevents accidental divergence in token syntax algorithm mapping and error results |

#### Go Suggested Libraries

| library | package | reason | recommendation | when_to_reconsider |
| --- | --- | --- | --- | --- |
| golang-jwt | jwt/v5 | Focused JWT library with HS256 HS384 and HS512 support matching the protocol strength matrix | Use as the first JWT implementation dependency | Reconsider if the protocol expands beyond compact signed JWTs into broader JOSE features |
| standard-library | encoding/json strings time errors fmt | Keeps the runtime dependency surface small and makes deterministic protocol behavior easier to audit | Use for payload decoding prefix parsing expiration and validation errors | Reconsider only if custom parsing or validation becomes too large to maintain clearly |
| go-playground-validator | validator/v10 | The protocol needs stable privacy-first validation errors with exact paths rather than generic tag-driven validation | Do not use initially | Reconsider if model validation grows substantially and custom error mapping remains stable |
| lestrrat-go | jwx/v3 | Full JOSE coverage is more capability than the current HMAC compact JWT protocol needs | Do not use initially | Reconsider if future cypher kinds require JWK JWE detached signatures or richer JOSE interoperability |

### 02 Package Layout

Focused files and responsibilities for the Go implementation.

#### Go Package Layout

| path | public_surface | responsibility | test_focus |
| --- | --- | --- | --- |
| crypt.go | New SignID VerifyID VerifyIDByPrefix | Own the Crypt type and route SignID VerifyID and VerifyIDByPrefix calls | unsupported prefixes and cypher dispatch |
| model.go | domain structs constants and generic Result | Define Store Cypher Expiration IDPayload ProtectedPayload Result CryptError and ValidationError | JSON field names zero values and validation constraints |
| builder.go | NewBuilder SetTitle AddTranslucentLizard Build | Offer ergonomic construction helpers without hiding the validated Store model | prefix registration title constraints duplicate prefixes and equivalence with plain Store setup |
| translucent_lizard.go | internal sign and verify functions | Implement HMAC JWT signing and verification for the translucent-lizard cypher | algorithm mapping expiration alt secret fallback and exp stripping |
| token.go | extractTokenPrefix extractToken composeFullToken | Parse and compose prefixed JWT tokens | final-colon splitting wrong prefix empty prefix and missing token |
| scope.go | checkScope helper | Compare expected scope and run custom scope validators | string and string-list equality missing scope and custom validator errors |
| validation.go | ValidateStore ValidateIDPayload helpers | Validate store and payload inputs before cryptographic operations | stable validation paths and privacy-first messages |
| errors.go | Succeed Fail helpers or constructors | Centralize stable step identifiers and result constructors | exact step values status values and finalMessage behavior |
| *_test.go | none | Hold cross-language contract tests and Go unit tests | canonical token syntax algorithm mapping and failure catalog coverage |

### 03 Contract Tests

Cross-language behavior that should be pinned before release.

#### Go Contract Tests

| contract | expected | input |
| --- | --- | --- |
| sign-hs256 | token starts with product: and JWT header alg is HS256 | prefix product strength sufficient payload id product123 |
| sign-hs384 | token starts with product: and JWT header alg is HS384 | prefix product strength good payload id product123 |
| sign-hs512 | token starts with product: and JWT header alg is HS512 | prefix product strength strong payload id product123 |
| verify-prefix | extracted prefix is tenant:product and token is text after final colon | last-colon full token with prefix tenant:product |
| verify-wrong-prefix | failure step verify-id/extract-token | VerifyIDByPrefix company called with product:jwt |
| verify-unknown-prefix | failure step verify-id/extract-token or verify-id/store according to extraction phase | VerifyID called with unsupported prefix |
| scope-string-match | verification continues | expected account account890 actual account account890 |
| scope-list-match | verification continues using value equality | expected roles admin writer actual roles admin writer |
| scope-missing | failure step verify-id/verify-scope | expected account account890 actual no scope |
| scope-validator-error | failure step verify-id/verify-scope | validator returns an error string |
| alt-secret-success | success result with payload and no exp field | current secret fails previous secret succeeds |
| alt-secret-failure | failure step verify-id/verify-token with finalMessage | current secret fails previous secret fails |
| expired-token | failure step verify-id/verify-token | verified token has expired |
| invalid-payload | failure step verify-id/validate-payload | decoded payload has no id |

## 05 Open Questions

Questions to settle before treating this as a cross-language standard.

### 01 Specification Gaps

Implementation details that deserve explicit product decisions.

#### Open Questions

1. Should the protocol reserve a version field for future cypher kinds or token formats?
2. Should canonical JSON test vectors with fixed secrets and expiry times be generated from flyb metadata?

