package lunarcrypt

import (
	"bytes"
	"encoding/json"
	"fmt"
)

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

type ScopeValue []string

func (s *ScopeValue) UnmarshalJSON(data []byte) error {
	if bytes.Equal(data, []byte("null")) {
		return fmt.Errorf("scope value must be a string or string list")
	}

	var single string
	if err := json.Unmarshal(data, &single); err == nil {
		*s = ScopeValue{single}
		return nil
	}

	var values []string
	if err := json.Unmarshal(data, &values); err == nil {
		*s = append((*s)[:0], values...)
		return nil
	}

	return fmt.Errorf("scope value must be a string or string list")
}

func (s ScopeValue) MarshalJSON() ([]byte, error) {
	return json.Marshal([]string(s))
}

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
