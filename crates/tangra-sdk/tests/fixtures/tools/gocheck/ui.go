package main

import (
	"encoding/json"
	"fmt"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing/fstest"
)

// The deployer's /ui wiring (internal/httpapi/server.go, middleware.go,
// errors.go at origin/main), verbatim except for the package plumbing.
func writeError(w http.ResponseWriter, status int, reason string) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"reason": reason})
}

func secure(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Cache-Control", "no-store")
		next.ServeHTTP(w, r)
	})
}

func remoteHandler(dist fs.FS) http.Handler {
	fileServer := http.FileServerFS(dist)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p := strings.TrimPrefix(r.URL.Path, "/")
		if p == "" || strings.HasSuffix(p, "/") {
			writeError(w, http.StatusNotFound, "not_found")
			return
		}
		if _, err := fs.Stat(dist, p); err != nil {
			writeError(w, http.StatusNotFound, "not_found")
			return
		}
		if strings.HasPrefix(p, "assets/") {
			w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
		} else {
			w.Header().Set("Cache-Control", "no-cache")
		}
		fileServer.ServeHTTP(w, r)
	})
}

// uiMain replays fixtures/ui/requests.txt against the deployer stack over
// an embed-like FS (zero modification times) and writes ui/golden.txt.
func uiMain(root string) {
	dist := fstest.MapFS{}
	base := filepath.Join(root, "dist")
	must(filepath.WalkDir(base, func(p string, d fs.DirEntry, err error) error {
		must(err)
		if d.IsDir() {
			return nil
		}
		rel, _ := filepath.Rel(base, p)
		data, err := os.ReadFile(p)
		must(err)
		dist[filepath.ToSlash(rel)] = &fstest.MapFile{Data: data, Mode: 0o444}
		return nil
	}))
	mux := http.NewServeMux()
	mux.Handle("GET /ui/", http.StripPrefix("/ui", remoteHandler(dist)))
	mux.Handle("/", http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { writeError(w, http.StatusNotFound, "not_found") }))
	h := secure(mux)
	raw, err := os.ReadFile(filepath.Join(root, "requests.txt"))
	must(err)
	var sb strings.Builder
	for _, line := range strings.Split(strings.TrimSpace(string(raw)), "\n") {
		parts := strings.Split(line, "|")
		mp := strings.SplitN(parts[0], " ", 2)
		r := httptest.NewRequest(mp[0], mp[1], nil)
		for _, hv := range parts[1:] {
			k, v, _ := strings.Cut(hv, ": ")
			r.Header.Set(k, v)
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		res := w.Result()
		boundary := ""
		if ct := res.Header.Get("Content-Type"); strings.HasPrefix(ct, "multipart/byteranges; boundary=") {
			boundary = strings.TrimPrefix(ct, "multipart/byteranges; boundary=")
		}
		fmt.Fprintf(&sb, "== %s\nstatus %d\n", line, res.StatusCode)
		var keys []string
		for k := range res.Header {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			v := strings.Join(res.Header[k], ", ")
			if boundary != "" {
				v = strings.ReplaceAll(v, boundary, "BOUNDARY")
			}
			fmt.Fprintf(&sb, "%s: %s\n", strings.ToLower(k), v)
		}
		body := w.Body.String()
		if boundary != "" {
			body = strings.ReplaceAll(body, boundary, "BOUNDARY")
		}
		if mp[0] == "HEAD" {
			body = ""
		}
		fmt.Fprintf(&sb, "body %q\n", body)
	}
	must(os.WriteFile(filepath.Join(root, "golden.txt"), []byte(sb.String()), 0o644))
}
