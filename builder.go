package lunarcrypt

import "fmt"

type Builder struct {
	store Store
	seen  map[string]struct{}
	err   error
}

func NewBuilder() *Builder {
	return &Builder{
		store: Store{
			Cyphers: map[string]TranslucentLizardCypher{},
		},
		seen: map[string]struct{}{},
	}
}

func (b *Builder) SetTitle(title string) *Builder {
	if b == nil {
		return b
	}
	b.store.Title = title
	return b
}

func (b *Builder) AddTranslucentLizard(prefix string, cypher TranslucentLizardCypher) *Builder {
	if b == nil {
		return b
	}
	if b.err != nil {
		return b
	}
	if _, ok := b.seen[prefix]; ok {
		b.err = fmt.Errorf("cypher prefix %q is already configured", prefix)
		return b
	}

	if cypher.Kind == "" {
		cypher.Kind = TranslucentLizard
	}
	b.seen[prefix] = struct{}{}
	b.store.Cyphers[prefix] = cloneCypher(cypher)
	return b
}

func (b *Builder) Build() (Store, error) {
	if b == nil {
		return Store{}, fmt.Errorf("builder is nil")
	}
	if b.err != nil {
		return Store{}, b.err
	}

	store := cloneStore(b.store)
	if err := ValidateStore(store); err != nil {
		return Store{}, err
	}
	return store, nil
}
