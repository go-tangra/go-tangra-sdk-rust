// xcheck dumps the deployer's derived routes (JSON) and its wire manifest
// (binary gateway.v1.Manifest) for the Rust SDK cross-check.
package main

import (
	"encoding/json"
	"os"

	"google.golang.org/protobuf/proto"

	"github.com/go-tangra/go-tangra-deployer/v4/pkg/deployermanifest"
)

type route struct {
	Method        string `json:"method"`
	Path          string `json:"path"`
	Permission    string `json:"permission"`
	Public        bool   `json:"public"`
	MaxBodyBytes  uint64 `json:"max_body_bytes"`
	TimeoutSecs   int64  `json:"timeout_seconds"`
	ClientAddress bool   `json:"client_address"`
}

func main() {
	m, err := deployermanifest.Manifest()
	if err != nil {
		panic(err)
	}
	var out []route
	for _, r := range m.Routes {
		out = append(out, route{r.Method, r.Path, r.Permission, r.Public, r.MaxBodyBytes, int64(r.Timeout.Seconds()), r.ClientAddress})
	}
	b, _ := json.MarshalIndent(out, "", "  ")
	if err := os.WriteFile(os.Args[1], append(b, '\n'), 0o644); err != nil {
		panic(err)
	}
	pm, err := m.Proto()
	if err != nil {
		panic(err)
	}
	raw, _ := proto.MarshalOptions{Deterministic: true}.Marshal(pm)
	if err := os.WriteFile(os.Args[2], raw, 0o644); err != nil {
		panic(err)
	}
}
