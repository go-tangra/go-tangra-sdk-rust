#!/usr/bin/env python3
"""Writes the helpdocs fixture trees (valid/ and invalid/) under argv[1]."""
import os
import shutil
import sys

root = sys.argv[1]

PNG = b"\x89PNG\r\n\x1a\n" + bytes(range(0, 48))
JPG = b"\xff\xd8\xff\xe0" + bytes(range(10, 60))
GIF = b"GIF89a" + bytes(range(1, 30))
WEBP = b"RIFF\x24\x00\x00\x00WEBPVP8 " + bytes(range(5, 40))


def fm(title="Page", kind="guide", extra="", body="Some text.\n"):
    return f"---\ntitle: {title}\nkind: {kind}\n{extra}---\n{body}"


def tree(kind, name, files):
    d = os.path.join(root, kind, name)
    if os.path.isdir(d):
        shutil.rmtree(d)
    for path, content in files.items():
        p = os.path.join(d, path)
        os.makedirs(os.path.dirname(p), exist_ok=True)
        if isinstance(content, str):
            content = content.encode("utf-8")
        with open(p, "wb") as f:
            f.write(content)


INDEX = fm("Home")

# ---------------------------------------------------------------- valid

tree("valid", "basic", {"index.md": INDEX})

tree("valid", "rich", {
    "index.md": "---\ntitle: Orders help\nsummary: Everything about orders.\nkind: guide\norder: -1\n"
                "tags: [orders, overview]\naudience: user\nlang: en\n---\n"
                "# Orders\n\nSee [setup](guides/setup.md), [guides](guides/index.md#top),\n"
                "[faq](faq.md?x=1), [portal](/orders/list), [site](https://example.org/a?b=c),\n"
                "[mail](mailto:ops@example.org), [anchor](#here) and ![logo](img/logo.png).\n\n"
                "[ref]: guides/setup.md\n\n<https://example.org/auto>\n\n"
                "<a href=\"faq.md\">faq</a> <img src=\"img/photo.jpg\" alt=\"\">\n\n"
                "Inline `[x](missing.md)` and:\n\n```\n[y](missing-too.md)\n![z](nope.png)\n```\n\n"
                "~~~md\n[w](gone.md)\n~~~\n\n"
                "[![badge](img/anim.gif)](guides/setup.md) and <img src='img/pic.webp'>\n",
    "faq.md": fm("FAQ", "faq", "order: 3\ntags:\n  - questions\n  - help\nrequires: orders:read\n",
                 "## Q\n\nA. Back to [home](index.md) or [start](./index.md).\n"),
    "guides/index.md": fm("Guides", "reference", "order: 2\n", "All guides: [setup](setup.md).\n"),
    "guides/setup.md": fm("Set up — ünïcode ✓", "example",
                          "summary: \"Quoted: summary with # hash\"\naudience: operator\norder: 10\n",
                          "Go [up](../index.md), see [the photo](../img/photo.jpg).\n"),
    "guides/deep/nested/index.md": fm("Nested", "guide", "", "Deep [guides](../../index.md).\n"),
    "img/logo.png": PNG,
    "img/photo.jpg": JPG,
    "img/anim.gif": GIF,
    "img/pic.webp": WEBP,
    "img/sub/x_y.z-1.jpeg": JPG,
})

tree("valid", "yaml-edge", {
    "index.md": "---\ntitle: 0x10\nkind: !!str guide\norder: 0x1F\n---\nHex title.\n",
    "a.md": "---\ntitle: 'single ''quoted'''\nkind: \"faq\"\norder: 1.9\n---\nfloat order\n",
    "b.md": "---\ntitle: true\nkind: guide\norder: -3\naudience: ~\nlang: ~\n---\nnull audience\n",
    "c.md": "---\ntitle: >\n  folded\n  title\nsummary: |\n  literal\n  summary\nkind: guide\norder: 1_000\n---\nfolded\n",
    "d.md": "---\ntitle: Tags   # a comment\nkind: guide\ntags: [a, ~, b]\norder: ~\nsummary: ~\n---\nnull tag dropped\n",
    "e.md": "---\ntitle: \"  padded  \"\nkind: reference\ntags: [1, 2x]\norder: +7\n---  \t\nclosing with spaces\n",
    "f.md": "---\n# comment only line\ntitle: 2024-01-02\nkind: guide\norder: 0o17\n---\n\ntimestamp title, octal order\n",
    "g.md": "---\ntitle: \"esc \\u00e9 \\t tab\"\nkind: guide\norder: 0b101\n---\nescapes\n",
    "h.md": "---\ntitle: &t anchored\nkind: guide\nsummary: *t\n---\nalias\n",
    "i.md": "---\n{title: flow map, kind: example, order: 4}\n---\nflow mapping\n",
    "j.md": "---\ntitle: 1e3\nkind: guide\norder: 2.5e1\n---\nexp\n",
    "k.md": "---\ntitle: Dupe\ntitle: Second\nkind: guide\n---\nduplicate key, last wins\n",
})

tree("valid", "escapes", {
    "index.md": "﻿---\r\ntitle: \"BOM & CRLF <page>\"\r\nkind: guide\r\n---\r\n"
                "Line one\r\nHTML: <b>bold</b> & <i>it</i> \"quotes\" 'single' \\ backslash\r\n",
    "ctrl.md": fm("Control", "guide", "", "tab\there, bell\x07, bs\x08, ff\x0c, vt\x0b, esc\x1b, del\x7f end\n"),
    "uni.md": fm("Ünïcødé 日本語 🎉", "guide", "tags: [x]\n",
                 "line sep para sep  nbsp  zwsp​ emoji 👍 \U0001F600\n"),
    "trail.md": fm("No trailing newline", "guide", "", "last line without newline"),
})

# ---------------------------------------------------------------- invalid

tree("invalid", "no-index", {"other.md": fm()})
tree("invalid", "unknown-key", {"index.md": fm(extra="author: me\nweight: 3\n")})
tree("invalid", "bad-kind", {"index.md": fm(kind="tutorial")})
tree("invalid", "missing-fields", {"index.md": "---\nsummary: no title\n---\nbody\n"})
tree("invalid", "long-title", {"index.md": fm(title="x" * 201)})
tree("invalid", "multiline-title", {"index.md": fm(title="\"a\\nb\"")})
tree("invalid", "long-summary", {"index.md": fm(extra="summary: " + "s" * 501 + "\n")})
tree("invalid", "tags", {"index.md": fm(extra="tags: [" + ", ".join(f"t{i}" for i in range(21)) + ", Bad_Tag, t1]\n")})
tree("invalid", "requires-audience-lang", {"index.md": fm(extra="requires: Orders\naudience: admin\nlang: fr\n")})
tree("invalid", "empty-body", {"index.md": "---\ntitle: T\nkind: guide\n---\n   \n\n"})
tree("invalid", "no-frontmatter", {"index.md": "# Title\n\nno front matter\n"})
tree("invalid", "unclosed", {"index.md": "---\ntitle: T\nkind: guide\n"})
tree("invalid", "not-mapping", {"index.md": "---\n- a\n- b\n---\nbody\n"})
tree("invalid", "yaml-syntax", {"index.md": "---\ntitle: [unclosed\nkind: guide\n---\nbody\n"})
tree("invalid", "wrong-types", {"index.md": "---\ntitle: [a, b]\nkind: {x: 1}\norder: abc\ntags: notalist\nsummary: [s]\n---\nbody\n"})
tree("invalid", "order-types", {"index.md": "---\ntitle: T\nkind: guide\norder: true\n---\nbody\n",
                                "a.md": "---\ntitle: T\nkind: guide\norder: 2024-01-01\n---\nbody\n",
                                "b.md": "---\ntitle: T\nkind: guide\norder: .nan\n---\nbody\n",
                                "c.md": "---\ntitle: T\nkind: guide\norder: '5'\n---\nbody\n",
                                "d.md": "---\ntitle: T\nkind: guide\ntags: [[a]]\n---\nbody\n"})
tree("invalid", "svg", {"index.md": INDEX, "img/x.svg": "<svg/>", "img/y.SVGZ": "z"})
tree("invalid", "unsupported", {"index.md": INDEX, "notes.txt": "hi", "README.MD": "x", ".hidden": "h"})
tree("invalid", "bad-asset-path", {"index.md": INDEX, "Img/logo.png": PNG, "img/_x.png": PNG, "img/a..b.png": PNG})
tree("invalid", "sniff-mismatch", {"index.md": INDEX, "a.png": JPG, "b.jpg": b"plain text", "c.gif": b"<html>x", "d.webp": b"RIFF"})
tree("invalid", "reserved-slug", {"index.md": INDEX, "assets.md": fm(), "assets/x.md": fm(), "assets/index.md": fm()})
tree("invalid", "bad-slug", {"index.md": INDEX, "Upper.md": fm(), "sp ace.md": fm(), "dir_x/a.md": fm(), "-x.md": fm()})
tree("invalid", "dup-slug", {"index.md": INDEX, "a.md": fm(), "a/index.md": fm()})
tree("invalid", "links", {
    "index.md": fm(body="[gone](missing.md)\n[out](../outside.md)\n[js](javascript:alert(1))\n"
                        "[js2](JAVA\tSCRIPT:x)\n[data](data:text/html,x)\n![abs](/img/a.png)\n"
                        "![remote](https://example.org/x.png)\n[pr](//evil.example/x)\n[bs](\\\\host\\x)\n"
                        "[empty]()\n[bad](%zz.md)\n![anchor](#x)\n![missing](nope.png)\n"
                        "[ftp](<ftp://x>)\n<ftp://auto.example/x>\n<a HREF=\"vbscript:x\">v</a>\n"
                        "[ref]: missing-ref.md\n[dir](guides)\n[asset-ok](img.png)\n![page-as-img](index.md)\n"),
    "img.png": PNG,
})
tree("invalid", "bad-utf8", {"index.md": b"---\ntitle: T\nkind: guide\n---\nbad \xff byte\n"})
tree("invalid", "frontmatter-start", {"index.md": "\n---\ntitle: T\nkind: guide\n---\nbody\n"})
tree("invalid", "scalar-frontmatter", {"index.md": "---\njust a string\n---\nbody\n"})
tree("invalid", "bad-module", {"index.md": INDEX})
tree("invalid", "open-trailing-space", {"index.md": "---   \ntitle: T\nkind: guide\n---\nbody\n"})
