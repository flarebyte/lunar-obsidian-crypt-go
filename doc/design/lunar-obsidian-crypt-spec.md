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
| JWT token | decode-and-validate | ProtectedPayload or validation error | Decoded payload must include id and exp | 8 |
| ProtectedPayload and cypher scope policy | check-scope | scope accepted or verification error | Expected scope and custom validator are checked before signature verification | 9 |
| JWT token and current or alternate secret | verify-signature | ProtectedPayload or verification error | Alternate secret is a fallback for rotation | 10 |
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
| message | verification | verify-id/decode-token | Reserved for token decoding failures |
| validation errors with message and path | verification | verify-id/validate-payload | Decoded JWT payload fails ProtectedPayload validation |
| message | verification | verify-id/verify-scope | Scope is missing mismatched or rejected by validator |
| message and optional finalMessage | verification | verify-id/verify-token | JWT is expired has a bad signature or cannot be verified |

## 04 Open Questions

Questions to settle before treating this as a cross-language standard.

### 01 Specification Gaps

Implementation details that deserve explicit product decisions.

#### Open Questions

1. Should the protocol reserve a version field for future cypher kinds or token formats?
2. Should array scope values be compared by value rather than by implementation object identity?
3. Should scope policy run before or after signature verification in all future implementations?
4. Should `verify-id/decode-token` become a required failure path for malformed JWTs?
5. Should the generated cross-language contract include canonical JSON test vectors with fixed secrets and expiry times?

