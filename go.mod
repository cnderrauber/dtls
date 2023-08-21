module github.com/pion/dtls/v2

require (
	github.com/pion/logging v0.2.2
	github.com/pion/transport/v2 v2.2.1
	golang.org/x/crypto v0.11.0
	golang.org/x/net v0.13.0
)

go 1.13

replace github.com/pion/transport/v2 => github.com/cnderrauber/transport/v2 v2.0.0-20230821040120-99864414a8c1

// replace github.com/pion/transport/v2 => ../transport
