package lunarcrypt

import (
	"encoding/json"
	"testing"
)

func FuzzScopeValueUnmarshalJSON(f *testing.F) {
	f.Add(`"account890"`)
	f.Add(`["admin","writer"]`)
	f.Add(`[]`)
	f.Add(`null`)
	f.Add(`123`)
	f.Add(`{"id":"account890"}`)
	f.Add(`["account890",123]`)

	f.Fuzz(func(t *testing.T, raw string) {
		var value ScopeValue
		err := json.Unmarshal([]byte(raw), &value)
		if err != nil {
			return
		}
		for index, item := range value {
			if item == "" {
				t.Fatalf("scope value %d is empty after successful unmarshal", index)
			}
		}
		if _, err := json.Marshal(value); err != nil {
			t.Fatalf("marshal ScopeValue after successful unmarshal: %v", err)
		}
	})
}
