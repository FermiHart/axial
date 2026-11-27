#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-SPL-1.0
"""Validate the static project's local references; never fetch remote resources.

srcset supports the project's local/HTTPS URL + optional width/density subset.
Complex comma-bearing URLs in srcset are deliberately not supported.
"""
from html.parser import HTMLParser
from pathlib import Path
import re
import sys
from urllib.parse import unquote, urlsplit

SITE = Path(__file__).resolve().parents[1] / "website"
DESCRIPTOR = re.compile(r"(?:[1-9][0-9]*w|(?:[0-9]+(?:\.[0-9]+)?|\.[0-9]+)x)")


class Resources(HTMLParser):
    def __init__(self, root, page):
        super().__init__(convert_charrefs=True)
        self.root = root
        self.page = page

    def reference(self, value, attr):
        url = urlsplit(value)
        if url.scheme == "https" and url.netloc:
            return
        if url.scheme == "mailto" and attr == "href":
            return
        if value.startswith("data:image/") and attr in ("src", "href"):
            return
        if url.scheme or url.netloc:
            raise ValueError(f"unsupported {attr} URL: {value!r}")
        if not url.path:
            return
        target = (self.page.parent / unquote(url.path)).resolve()
        if not target.is_relative_to(self.root) or not target.is_file():
            raise ValueError(f"missing or out-of-site {attr} resource: {value!r}")

    def handle_starttag(self, tag, attrs):
        for key, value in attrs:
            if not value:
                continue
            if key in ("src", "href"):
                self.reference(value, key)
            elif key == "srcset":
                for candidate in value.split(","):
                    parts = candidate.split()
                    if not parts or len(parts) > 2 or (
                        len(parts) == 2 and not DESCRIPTOR.fullmatch(parts[1])
                    ):
                        raise ValueError(f"unsupported srcset candidate: {candidate!r}")
                    self.reference(parts[0], key)


def main():
    root = SITE.resolve()
    pages = sorted(root.rglob("*.html"))
    if not pages:
        print("FAIL: no HTML pages", file=sys.stderr)
        return 1
    for page in pages:
        try:
            Resources(root, page).feed(page.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, ValueError) as exc:
            print(f"FAIL: {page.relative_to(root)}: {exc}", file=sys.stderr)
            return 1
    print(f"PASS: static resource references in {len(pages)} HTML page(s)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
