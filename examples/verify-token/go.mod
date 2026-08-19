// Separate module on purpose: this example must build without access to the
// gateway's own packages, the same way a real third-party consumer would.
module verify-token

go 1.26.3

require github.com/o1egl/paseto/v2 v2.1.1

require (
	github.com/mitchellh/mapstructure v1.1.2 // indirect
	golang.org/x/crypto v0.52.0 // indirect
	golang.org/x/sys v0.45.0 // indirect
	golang.org/x/xerrors v0.0.0-20240903120638-7835f813f4da // indirect
)
