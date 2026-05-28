package lunarcrypt

type Crypt struct {
	store    Store
	prefixes []string
}

func New(store Store) (*Crypt, error) {
	if err := ValidateStore(store); err != nil {
		return nil, err
	}

	copied := cloneStore(store)
	prefixes := make([]string, 0, len(copied.Cyphers))
	for prefix := range copied.Cyphers {
		prefixes = append(prefixes, prefix)
	}

	return &Crypt{
		store:    copied,
		prefixes: prefixes,
	}, nil
}

func cloneStore(store Store) Store {
	copied := Store{
		Title:   store.Title,
		Cyphers: make(map[string]TranslucentLizardCypher, len(store.Cyphers)),
	}
	for prefix, cypher := range store.Cyphers {
		copied.Cyphers[prefix] = cloneCypher(cypher)
	}
	return copied
}

func cloneCypher(cypher TranslucentLizardCypher) TranslucentLizardCypher {
	copied := cypher
	copied.Secret = cloneBytes(cypher.Secret)
	copied.AltSecret = cloneBytes(cypher.AltSecret)
	copied.ExpectedScope = cloneScope(cypher.ExpectedScope)
	return copied
}

func cloneBytes(value []byte) []byte {
	if value == nil {
		return nil
	}
	return append([]byte(nil), value...)
}

func cloneScope(scope map[string]ScopeValue) map[string]ScopeValue {
	if scope == nil {
		return nil
	}
	copied := make(map[string]ScopeValue, len(scope))
	for key, values := range scope {
		copied[key] = append(ScopeValue(nil), values...)
	}
	return copied
}
