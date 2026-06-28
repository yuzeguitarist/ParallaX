#!/usr/bin/env python3
"""Fail if any ParallaX-DeepWiki page is missing from _Sidebar.md.

The sidebar is hand-curated (it carries grouping, short titles, and ordering
that cannot be inferred from filenames), but every content page must still be
reachable from it. This guard catches the common mistake of adding a new doc
and forgetting to list it in the sidebar.

Run directly (`python3 check_sidebar.py`) or via pytest. Exits non-zero and
prints the missing pages when the sidebar is out of date.
"""

import os
import re
import sys

SRC = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..",
                   "ParallaX-DeepWiki")
SIDEBAR = "_Sidebar.md"

# Link targets, both bare `](Name)` and angle `](<Name>)` forms.
TARGET_RE = re.compile(r"\]\((?:<([^>]+)>|([^()<>\s]+))\)")


def page_name(filename):
    """Map a source filename to its rendered wiki page name."""
    if filename == "README.md":
        return "Home"
    return filename[:-len(".md")]


def sidebar_targets(text):
    """All link targets in the sidebar, with any #anchor stripped."""
    out = set()
    for m in TARGET_RE.finditer(text):
        target = m.group(1) or m.group(2)
        out.add(target.partition("#")[0])
    return out


def find_missing(src=SRC):
    sidebar_path = os.path.join(src, SIDEBAR)
    with open(sidebar_path, encoding="utf-8") as f:
        targets = sidebar_targets(f.read())

    missing = []
    for name in sorted(n for n in os.listdir(src) if n.endswith(".md")):
        if name.startswith("_"):  # special pages (sidebar/footer) are not content
            continue
        page = page_name(name)
        if page not in targets:
            missing.append(page)
    return missing


def main():
    if not os.path.isfile(os.path.join(SRC, SIDEBAR)):
        sys.exit(f"ERROR: {SIDEBAR} not found under {SRC}")
    missing = find_missing()
    if missing:
        print("ERROR: these wiki pages are missing from "
              f"ParallaX-DeepWiki/{SIDEBAR}:", file=sys.stderr)
        for page in missing:
            print(f"  - {page}", file=sys.stderr)
        print("\nAdd each page to the appropriate section in "
              f"ParallaX-DeepWiki/{SIDEBAR}.", file=sys.stderr)
        sys.exit(1)
    print(f"ok: all wiki pages are listed in {SIDEBAR}")


if __name__ == "__main__":
    main()
