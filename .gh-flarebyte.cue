package ghflarebyte

project: {
	org:  "flarebyte"
	repo: "lunar-obsidian-crypt-go"
}

sync: {
	mode: "push"
}

repository: {
	description:   "Go library to sign and verify application IDs as prefixed JWT tokens"
	defaultBranch: "main"
	homepage:      "https://github.com/flarebyte/lunar-obsidian-crypt-go"
	visibility:    "public"
	template:      false
	topics: [
		"flarebyte",
		"go",
		"go-library",
		"jwt",
		"hmac",
		"security",
		"token",
	]
	labels: [
		{
			name:        "bug"
			color:       "d73a4a"
			description: "Something is not working"
		},
		{
			name:        "documentation"
			color:       "0075ca"
			description: "Improvements or additions to documentation"
		},
		{
			name:        "duplicate"
			color:       "cfd3d7"
			description: "This issue or pull request already exists"
		},
		{
			name:        "enhancement"
			color:       "a2eeef"
			description: "New feature or request"
		},
		{
			name:        "good first issue"
			color:       "7057ff"
			description: "Good for newcomers"
		},
		{
			name:        "help wanted"
			color:       "008672"
			description: "Extra attention is needed"
		},
		{
			name:        "invalid"
			color:       "e4e669"
			description: "This does not seem right"
		},
		{
			name:        "question"
			color:       "d876e3"
			description: "Further information is requested"
		},
		{
			name:        "wontfix"
			color:       "ffffff"
			description: "This will not be worked on"
		},
	]
	features: {
		issues:                       true
		wiki:                         false
		projects:                     false
		discussions:                  false
		autoMerge:                    true
		mergeCommit:                  false
		rebaseMerge:                  false
		squashMerge:                  true
		squashMergeCommitMessage:     "pr-title"
		deleteBranchOnMerge:          true
		allowForking:                 false
		allowUpdateBranch:            false
		advancedSecurity:             true
		secretScanning:               true
		secretScanningPushProtection: true
	}
}

build: {
	language: "go"
	mode:     "library"
	packages: [
		"./...",
	]
	runTests: true
}

go: {
	cacheDir:    "./.gocache"
	modCacheDir: "./.gomodcache"
	toolchain:   "local"
}

devOutput: {
	color:      "auto"
	style:      "summary"
	showPassed: true
}

coverage: {
	min:        80
	enforceMin: true
}

release: {
	versionSource:    "main.project.yaml"
	tagPrefix:        "v"
	notesMode:        "generate-notes"
	includeArtifacts: false
}
