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
