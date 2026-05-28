package flyb

source: "lunar-obsidian-crypt"
name:   "lunar-obsidian-crypt-design-meta"
modules: ["core", "protocol", "portable-api"]

reports: [{
	title:       "Lunar Obsidian Crypt Protocol Specification"
	filepath:    "../design/lunar-obsidian-crypt-spec.md"
	description: "Language-neutral specification reverse engineered from the TypeScript implementation."
	sections: [{
		title:       "01 Overview"
		description: "Protocol intent, terminology, and portability boundaries."
		sections: [{
			title:       "01 Intent"
			description: "What this specification captures."
			notes: ["crypt.intent", "crypt.terminology", "crypt.security.model"]
		}, {
			title:       "02 Use Cases"
			description: "Actors and goals supported by the protocol."
			notes: ["crypt.usecases"]
		}, {
			title:       "03 Language Portability"
			description: "How the same protocol maps across implementation languages."
			notes: ["crypt.language.portability"]
		}]
	}, {
		title:       "02 Protocol Model"
		description: "Canonical model, token syntax, and operation rules."
		sections: [{
			title:       "01 Domain Models"
			description: "Portable data model extracted from TypeScript schemas."
			notes: ["crypt.domain.models", "crypt.ts.api"]
		}, {
			title:       "02 Token And Algorithm Rules"
			description: "Token syntax, signing algorithms, and normative behavior."
			notes: ["crypt.protocol.rules", "crypt.algorithm.matrix"]
		}, {
			title:       "03 Message Examples"
			description: "Representative store, request, response, and failure shapes."
			notes: ["crypt.ts.messages"]
		}]
	}, {
		title:       "03 Workflows"
		description: "End-to-end signing and verification behavior."
		sections: [{
			title:       "01 Operation Flow"
			description: "Ordered protocol steps."
			notes: ["crypt.operation.flow"]
		}, {
			title:       "02 Operation Graph"
			description: "Graph view of the sign and verify flow."
			arguments: [
				"graph-subject-label=operation",
				"graph-edge-label=then",
				"graph-start-node=crypt.flow.build.store",
				"graph-renderer=markdown-text",
			]
		}, {
			title:       "03 Error Catalog"
			description: "Stable error steps and expected failure shape."
			notes: ["crypt.error.catalog"]
		}]
	}, {
		title:       "04 Open Questions"
		description: "Questions to settle before treating this as a cross-language standard."
		sections: [{
			title:       "01 Specification Gaps"
			description: "Implementation details that deserve explicit product decisions."
			notes: ["crypt.open.questions"]
		}]
	}]
}]

notes: [
	{
		name:  "crypt.intent"
		title: "Intent"
		markdown: """
This specification captures the protocol behind `lunar-obsidian-crypt` independently of the current TypeScript implementation.

The core protocol signs application ID payloads into prefixed compact JWT tokens. A target implementation in TypeScript, Go, or another language should preserve the same token syntax, payload validation, algorithm mapping, scope verification, secret rotation behavior, and structured result shape.
"""
		labels: ["overview", "protocol"]
	},
	{
		name:  "crypt.terminology"
		title: "Terminology"
		markdown: """
- Store: named collection of cypher configurations.
- Prefix: application-level token namespace placed before the JWT token.
- Full token: `prefix:jwt-token`.
- Cypher: versionable signing configuration selected by prefix.
- Translucent Lizard: current cypher kind based on signed visible JWT payloads.
- Scope: optional key-value context used to restrict token validity.
- Result: success or failure value returned as data.
"""
		labels: ["overview", "vocabulary"]
	},
	{
		name:  "crypt.security.model"
		title: "Security Model"
		markdown: """
The current protocol is a signing protocol, not an encryption protocol. Payload claims are visible to any holder of the token.

Secrets must be opaque byte arrays supplied by the embedding application. Implementations should rely on a JOSE-compatible JWT library for HMAC signing and verification rather than custom cryptographic code.
"""
		labels: ["overview", "security"]
	},
	{
		name:      "crypt.usecases"
		title:     "Use Cases"
		filepath:  "examples/usecases.csv"
		arguments: ["format-csv=table"]
		labels:    ["csv", "usecase"]
	},
	{
		name:      "crypt.domain.models"
		title:     "Domain Models"
		filepath:  "examples/domain-models.csv"
		arguments: ["format-csv=table"]
		labels:    ["csv", "model"]
	},
	{
		name:      "crypt.protocol.rules"
		title:     "Protocol Rules"
		filepath:  "examples/protocol-rules.csv"
		arguments: ["format-csv=table"]
		labels:    ["csv", "protocol"]
	},
	{
		name:      "crypt.algorithm.matrix"
		title:     "Algorithm Matrix"
		filepath:  "examples/algorithm-matrix.csv"
		arguments: ["format-csv=table"]
		labels:    ["algorithm", "csv"]
	},
	{
		name:      "crypt.operation.flow"
		title:     "Operation Flow"
		filepath:  "examples/operation-flow.csv"
		arguments: ["format-csv=table"]
		labels:    ["csv", "flow"]
	},
	{
		name:      "crypt.error.catalog"
		title:     "Error Catalog"
		filepath:  "examples/error-catalog.csv"
		arguments: ["format-csv=table"]
		labels:    ["csv", "error"]
	},
	{
		name:      "crypt.language.portability"
		title:     "Language Portability"
		filepath:  "examples/language-portability.csv"
		arguments: ["format-csv=table"]
		labels:    ["csv", "portability"]
	},
	{
		name:     "crypt.ts.api"
		title:    "Portable API Types"
		filepath: "examples/api.ts"
		labels:   ["example", "typescript"]
	},
	{
		name:     "crypt.ts.messages"
		title:    "Message Examples"
		filepath: "examples/messages.ts"
		labels:   ["example", "typescript"]
	},
	{
		name:  "crypt.open.questions"
		title: "Open Questions"
		markdown: """
1. Should the protocol reserve a version field for future cypher kinds or token formats?
2. Should array scope values be compared by value rather than by implementation object identity?
3. Should scope policy run before or after signature verification in all future implementations?
4. Should `verify-id/decode-token` become a required failure path for malformed JWTs?
5. Should the generated cross-language contract include canonical JSON test vectors with fixed secrets and expiry times?
"""
		labels: ["open-question"]
	},
	{
		name:     "crypt.flow.build.store"
		title:    "Build Store"
		markdown: "Build or load the store model containing supported prefixes and cypher configurations."
		labels:   ["operation"]
	},
	{
		name:     "crypt.flow.sign"
		title:    "Sign Payload"
		markdown: "Validate an ID payload, create a JWT with the configured algorithm and expiration, and prepend the prefix."
		labels:   ["operation"]
	},
	{
		name:     "crypt.flow.extract.prefix"
		title:    "Extract Prefix"
		markdown: "Read the prefix from the full token and select the configured cypher."
		labels:   ["operation"]
	},
	{
		name:     "crypt.flow.verify.scope"
		title:    "Verify Scope"
		markdown: "Validate decoded payload shape and enforce configured expected scope and custom scope policy."
		labels:   ["operation"]
	},
	{
		name:     "crypt.flow.verify.signature"
		title:    "Verify Signature"
		markdown: "Verify the JWT with the current secret and optionally the previous secret."
		labels:   ["operation"]
	},
	{
		name:     "crypt.flow.return.result"
		title:    "Return Result"
		markdown: "Return a structured success payload without `exp` or a structured failure error."
		labels:   ["operation"]
	},
]

relationships: [
	{
		from:   "crypt.flow.build.store"
		to:     "crypt.flow.sign"
		label:  "then"
		labels: ["then"]
	},
	{
		from:   "crypt.flow.sign"
		to:     "crypt.flow.extract.prefix"
		label:  "then"
		labels: ["then"]
	},
	{
		from:   "crypt.flow.extract.prefix"
		to:     "crypt.flow.verify.scope"
		label:  "then"
		labels: ["then"]
	},
	{
		from:   "crypt.flow.verify.scope"
		to:     "crypt.flow.verify.signature"
		label:  "then"
		labels: ["then"]
	},
	{
		from:   "crypt.flow.verify.signature"
		to:     "crypt.flow.return.result"
		label:  "then"
		labels: ["then"]
	},
]

argumentRegistry: {
	version: "1"
	arguments: [
		{
			name:      "graph-subject-label"
			valueType: "string"
			scopes: ["h3-section"]
		},
		{
			name:      "graph-edge-label"
			valueType: "string"
			scopes: ["h3-section"]
		},
		{
			name:      "graph-start-node"
			valueType: "string"
			scopes: ["h3-section"]
		},
		{
			name:          "graph-renderer"
			valueType:     "enum"
			scopes: ["h3-section", "note"]
			allowedValues: ["markdown-text", "mermaid"]
			defaultValue:  "markdown-text"
		},
		{
			name:          "format-csv"
			valueType:     "enum"
			scopes: ["note"]
			allowedValues: ["raw", "table"]
			defaultValue:  "table"
		},
	]
}
