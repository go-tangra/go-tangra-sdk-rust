// main runs authclient.VerifyToken (auth sdk/v4.3.0) over the Rust SDK's
// token fixtures at the fixtures' instant and writes the verdicts.
package main

import (
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"time"

	"github.com/go-tangra/go-tangra-auth/sdk/v4/pkg/authclient"
)

const (
	iss = "https://auth.example.org"
	t0  = 1_789_560_000
)

type verdict struct {
	Name       string `json:"name"`
	OK         bool   `json:"ok"`
	UnknownKid bool   `json:"unknown_kid"`
	Error      string `json:"error,omitempty"`
}

func main() {
	dir := os.Args[1]
	raw, err := os.ReadFile(filepath.Join(dir, "tokens.json"))
	if err != nil {
		panic(err)
	}
	var toks []struct{ Name, Token string }
	if err := json.Unmarshal(raw, &toks); err != nil {
		panic(err)
	}
	seed := make([]byte, 32)
	for i := range seed {
		seed[i] = 7
	}
	pub := ed25519.NewKeyFromSeed(seed).Public().(ed25519.PublicKey)
	now := func() time.Time { return time.Unix(t0, 0) }
	lookup := func(kid string) (ed25519.PublicKey, bool) { return pub, kid == "k1" }
	var out []verdict
	for _, t := range toks {
		_, err := authclient.VerifyToken(t.Token, iss, 60*time.Second, 15*time.Minute, now, lookup)
		v := verdict{Name: t.Name, OK: err == nil}
		var uk *authclient.UnknownKeyError
		v.UnknownKid = errors.As(err, &uk)
		if err != nil {
			v.Error = err.Error()
		}
		out = append(out, v)
	}
	b, _ := json.MarshalIndent(out, "", "  ")
	if err := os.WriteFile(filepath.Join(dir, "expected.go.json"), append(b, '\n'), 0o644); err != nil {
		panic(err)
	}
}
