// Separate module, same as examples/verify-token, but this one imports the
// gateway's pkg/pasetoauth package — the "go get this repo" path a real
// consumer would take. The replace directive below only exists to point at
// the local checkout for this example; a real consumer would drop it and let
// go.mod resolve secure-auth-gateway from its actual published location.
module verify-token-pkg

go 1.26.3

require secure-auth-gateway v0.0.0

require (
	github.com/mitchellh/mapstructure v1.5.0 // indirect
	github.com/o1egl/paseto/v2 v2.1.1 // indirect
	golang.org/x/crypto v0.52.0 // indirect
	golang.org/x/sys v0.45.0 // indirect
	golang.org/x/xerrors v0.0.0-20240903120638-7835f813f4da // indirect
)

replace secure-auth-gateway => ../..
