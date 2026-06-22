module github.com/go-fde/fde

go 1.25.0

require (
	github.com/go-fde/apfs v0.0.0
	github.com/go-fde/clear v0.0.0-20260620062427-f7b9676e89b9
	github.com/go-fde/luks v0.0.0
	golang.org/x/crypto v0.50.0
)

require golang.org/x/sys v0.43.0 // indirect

// Monorepo-only: published-repo equivalents are pinned via `require`
// to tagged versions when the umbrella publish.sh runs. These three
// directives let `task ci` work in-tree with GOWORK=off.
replace github.com/go-fde/apfs => ../apfs

replace github.com/go-fde/luks => ../luks
