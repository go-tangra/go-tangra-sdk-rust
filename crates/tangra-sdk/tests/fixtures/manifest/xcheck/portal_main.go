// xcheck runs the gateway's real manifest validation over the Rust SDK's
// fixtures: Parse for json/*.json, FromProto for pb/*.pb, and the
// registry's content hash (sha256 of json.Marshal(m)) for accepted ones.
package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"google.golang.org/protobuf/proto"

	gatewayv1 "github.com/go-tangra/go-tangra-portal/sdk/v4/api/proto/gateway/v1"
	"github.com/go-tangra/go-tangra-portal/v4/internal/manifest"
)

type result struct {
	File  string `json:"file"`
	OK    bool   `json:"ok"`
	Error string `json:"error,omitempty"`
	Hash  string `json:"hash,omitempty"`
}

func main() {
	dir := os.Args[1]
	var files []string
	for _, pat := range []string{"json/*.json", "pb/*.pb"} {
		m, _ := filepath.Glob(filepath.Join(dir, pat))
		files = append(files, m...)
	}
	sort.Strings(files)
	var out []result
	for _, f := range files {
		raw, err := os.ReadFile(f)
		if err != nil {
			panic(err)
		}
		var m manifest.Manifest
		if strings.HasSuffix(f, ".pb") {
			var p gatewayv1.Manifest
			if err := proto.Unmarshal(raw, &p); err != nil {
				panic(err)
			}
			m, err = manifest.FromProto(&p)
		} else {
			m, err = manifest.Parse(raw)
		}
		rel, _ := filepath.Rel(dir, f)
		r := result{File: rel, OK: err == nil}
		if err != nil {
			r.Error = err.Error()
		} else {
			b, _ := json.Marshal(m)
			s := sha256.Sum256(b)
			r.Hash = hex.EncodeToString(s[:])
		}
		out = append(out, r)
	}
	b, _ := json.MarshalIndent(out, "", "  ")
	if err := os.WriteFile(filepath.Join(dir, "expected.go.json"), append(b, '\n'), 0o644); err != nil {
		panic(err)
	}
}
