package brand

import (
	cryptoRand "crypto/rand"
	"fmt"
	"io"
)

// brand - balance-random - is a randomness indirection package.
//
// SECURITY (fixed): this package previously exposed a `needDeterministic`
// switch that swapped in a TIME-SEEDED math/rand reader (randbo). Any
// deterministic randomness path that can be reached by editing one constant
// is a footgun in a codebase that uses it for descriptor signing keys,
// client nonces, salts, IVs and auth cookies: an attacker who can guess the
// process start time (or force a restart) reproduces every "random" value.
// The deterministic path has been removed entirely — all randomness now
// comes from crypto/rand, unconditionally.

// Read fills b with cryptographically secure random bytes.
func Read(b []byte) (n int, err error) {
	return cryptoRand.Read(b)
}

// Reader returns a cryptographically secure io.Reader.
func Reader() io.Reader {
	return cryptoRand.Reader
}

// MustRead is a convenience wrapper that panics if the system CSPRNG fails.
// A broken CSPRNG must never degrade into a predictable fallback.
func MustRead(b []byte) {
	if _, err := cryptoRand.Read(b); err != nil {
		panic(fmt.Sprintf("crypto/rand failed: %v", err))
	}
}
