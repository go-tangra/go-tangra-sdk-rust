// Command gocheck produces the golden files the Rust SDK cross-checks
// against: go-tangra v4.10.0 helpdocs (Load, bundle JSON, digest, problems)
// and catalogue (ParseDescriptor) over the committed fixtures.
//
//	gocheck helpdocs <fixtures/helpdocs>
//	gocheck catalogue <fixtures/catalogue>
package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing/fstest"

	"github.com/go-tangra/go-tangra/v4/catalogue"
	"github.com/go-tangra/go-tangra/v4/helpdocs"
)

func must(err error) {
	if err != nil {
		panic(err)
	}
}

func dirs(p string) []string {
	ents, err := os.ReadDir(p)
	must(err)
	var out []string
	for _, e := range ents {
		if e.IsDir() {
			out = append(out, e.Name())
		}
	}
	sort.Strings(out)
	return out
}

func moduleFor(name string) string {
	switch name {
	case "deployer":
		return "deployer"
	case "bad-module":
		return "Bad_Module"
	}
	return "fixture"
}

func helpdocsMain(root string) {
	for _, name := range dirs(filepath.Join(root, "valid")) {
		b, err := helpdocs.Load(os.DirFS(filepath.Join(root, "valid", name)), moduleFor(name))
		if err != nil {
			panic(fmt.Sprintf("valid/%s: %v", name, err))
		}
		raw, err := b.Marshal()
		must(err)
		must(os.WriteFile(filepath.Join(root, "valid", name+".bundle.json"), raw, 0o644))
		must(os.WriteFile(filepath.Join(root, "valid", name+".digest"), []byte(b.Digest+"\n"), 0o644))
		if helpdocs.Lint(os.DirFS(filepath.Join(root, "valid", name))) != nil {
			panic("lint disagrees with load: " + name)
		}
		fmt.Printf("valid/%s: %s (%d pages, %d assets)\n", name, b.Digest, len(b.Pages), len(b.Assets))
	}
	for _, name := range dirs(filepath.Join(root, "invalid")) {
		_, err := helpdocs.Load(os.DirFS(filepath.Join(root, "invalid", name)), moduleFor(name))
		if err == nil {
			panic("invalid/" + name + " loaded")
		}
		out := "load:\n" + err.Error() + "\n"
		if lerr := helpdocs.Lint(os.DirFS(filepath.Join(root, "invalid", name))); lerr != nil {
			out += "lint:\n" + lerr.Error() + "\n"
		} else {
			out += "lint:\nok\n"
		}
		must(os.WriteFile(filepath.Join(root, "invalid", name+".problems.txt"), []byte(out), 0o644))
		fmt.Printf("invalid/%s: %d lines\n", name, strings.Count(out, "\n"))
	}
	must(os.WriteFile(filepath.Join(root, "generated.golden"), []byte(generated()), 0o644))
	must(os.WriteFile(filepath.Join(root, "frontmatter.golden"), []byte(matrix(root)), 0o644))
}

// matrix loads every page of frontmatter-cases.txt as a one-page tree.
func matrix(root string) string {
	raw, err := os.ReadFile(filepath.Join(root, "frontmatter-cases.txt"))
	must(err)
	var sb strings.Builder
	for i, src := range strings.Split(string(raw), "\n%%%%\n") {
		fmt.Fprintf(&sb, "== %d\n", i)
		b, err := helpdocs.Load(fstest.MapFS{"index.md": {Data: []byte(src)}}, "fixture")
		if err != nil {
			sb.WriteString(err.Error() + "\n")
			continue
		}
		j, err := json.Marshal(b.Pages[0])
		must(err)
		sb.Write(j)
		sb.WriteString("\n")
	}
	return sb.String()
}

func page(title string) []byte {
	return []byte("---\ntitle: " + title + "\nkind: guide\n---\nbody\n")
}

func png(size int) []byte {
	b := make([]byte, size)
	copy(b, "\x89PNG\r\n\x1a\n")
	for i := 8; i < size; i++ {
		b[i] = byte(i % 251)
	}
	return b
}

// generated runs the cases whose trees are too large (or impossible) to
// commit; the Rust test builds the same trees in memory.
func generated() string {
	type tc struct {
		name string
		fs   fs.FS
	}
	big := func(n int) []byte { return bytes.Repeat([]byte("a"), n) }
	cases := []tc{{"empty", fstest.MapFS{}}, {"nil", nil}, {"missing-root", os.DirFS("/nonexistent/helpdocs")}}
	many := fstest.MapFS{"index.md": {Data: page("Home")}}
	for i := 0; i < 500; i++ {
		many[fmt.Sprintf("p%03d.md", i)] = &fstest.MapFile{Data: page(fmt.Sprintf("P%d", i))}
	}
	cases = append(cases, tc{"pages-501", many})
	cases = append(cases, tc{"page-too-big", fstest.MapFS{
		"index.md": {Data: page("Home")},
		"big.md":   {Data: append(page("Big"), big(helpdocs.MaxPageBytes)...)},
		"edge.md":  {Data: append(page("Edge"), big(helpdocs.MaxPageBytes-len(page("Edge")))...)},
	}})
	cases = append(cases, tc{"asset-too-big", fstest.MapFS{
		"index.md":  {Data: page("Home")},
		"big.png":   {Data: png(helpdocs.MaxAssetBytes + 1)},
		"edge.png":  {Data: png(helpdocs.MaxAssetBytes)},
		"other.svg": {Data: big(helpdocs.MaxAssetBytes + 1)},
	}})
	total := fstest.MapFS{"index.md": {Data: page("Home")}}
	for i := 0; i < 9; i++ {
		total[fmt.Sprintf("img/%d.png", i)] = &fstest.MapFile{Data: png(500 << 10)}
	}
	cases = append(cases, tc{"total-too-big", total})
	cases = append(cases, tc{"symlink", fstest.MapFS{
		"index.md": {Data: page("Home")},
		"link.md":  {Data: []byte("index.md"), Mode: fs.ModeSymlink},
	}})
	var sb strings.Builder
	for _, c := range cases {
		sb.WriteString("== " + c.name + "\n")
		b, err := helpdocs.Load(c.fs, "fixture")
		if err != nil {
			sb.WriteString(err.Error() + "\n")
			continue
		}
		raw, err := b.Marshal()
		must(err)
		fmt.Fprintf(&sb, "digest %q pages %d assets %d json %s\n", b.Digest, len(b.Pages), len(b.Assets), raw)
	}
	return sb.String()
}

func catalogueMain(root string) {
	ents, err := os.ReadDir(root)
	must(err)
	for _, e := range ents {
		if !strings.HasSuffix(e.Name(), ".yaml") {
			continue
		}
		raw, err := os.ReadFile(filepath.Join(root, e.Name()))
		must(err)
		var out string
		d, err := catalogue.ParseDescriptor(raw)
		if err != nil {
			out = "error: " + err.Error() + "\n"
		} else {
			j, err := json.Marshal(d)
			must(err)
			out = "ok\n" + string(j) + "\n"
		}
		name := strings.TrimSuffix(e.Name(), ".yaml")
		must(os.WriteFile(filepath.Join(root, name+".golden"), []byte(out), 0o644))
		fmt.Printf("%s: %s", name, strings.SplitN(out, "\n", 2)[0]+"\n")
	}
}

func main() {
	switch os.Args[1] {
	case "helpdocs":
		helpdocsMain(os.Args[2])
	case "catalogue":
		catalogueMain(os.Args[2])
	case "ui":
		uiMain(os.Args[2])
	default:
		panic("usage")
	}
}
