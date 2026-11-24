module abhed

go 1.22.0

// golang.org/x modules are fetched from their official GitHub mirrors so the build
// works where golang.org is unreachable. Dependencies are vendored (go build -mod=vendor).
replace (
	golang.org/x/mod => github.com/golang/mod v0.21.0
	golang.org/x/net => github.com/golang/net v0.30.0
	golang.org/x/sync => github.com/golang/sync v0.8.0
	golang.org/x/sys => github.com/golang/sys v0.26.0
	golang.org/x/tools => github.com/golang/tools v0.26.0
)

require github.com/miekg/dns v1.1.62

require (
	golang.org/x/mod v0.21.0 // indirect
	golang.org/x/net v0.30.0 // indirect
	golang.org/x/sync v0.8.0 // indirect
	golang.org/x/sys v0.26.0 // indirect
	golang.org/x/tools v0.22.0 // indirect
)
