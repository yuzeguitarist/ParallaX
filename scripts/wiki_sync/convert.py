#!/usr/bin/env python3
"""Convert ParallaX-DeepWiki/*.md into GitHub-Wiki-compatible markdown.

Pure transformer: reads every ``*.md`` under ``--src`` and writes a transformed
copy under ``--out``. Source files are never modified. Standard library only.

Transform rules (the GitHub Wiki rendered web UI requires them):
  A. Strip the ``.md`` suffix from internal page links, for both the bare form
     ``[t](Name.md)`` and the angle form ``[t](<Name.md>)``. A link target is
     re-wrapped in angle brackets iff it contains a space, ``(``, ``)``, ``&``
     or ``+`` (otherwise emitted bare) so the output matches the existing wiki.
  B. The source ``README.md`` is written out as ``Home.md`` (the wiki landing
     page); link targets resolving to ``README`` are retargeted to ``Home``.
  C. Source-tree links (``../src/...``, ``../tests/...``, ``../Cargo.toml`` ...)
     are rewritten to absolute URLs: a directory target (trailing ``/``) points
     at ``tree/main``, a file target at ``blob/main``.

Fenced code blocks (``` or ~~~) are passed through byte-for-byte so markup such
as the mermaid diagram and the embedded bash heredoc in
``Documentation-Metadata-Search-Graph.md`` (which literally contains ``](`` and
``.md``) is never rewritten. Only the target inside ``](...)`` is ever changed;
link text is left untouched.
"""

import argparse
import os
import re
import sys

REPO = "https://github.com/yuzeguitarist/ParallaX"
BLOB = REPO + "/blob/main"
TREE = REPO + "/tree/main"

# A fence opens/closes on a line whose first non-space run is >=3 backticks or
# tildes. The closing fence must use the same char, be at least as long, and
# carry no info string.
FENCE_RE = re.compile(r"^(\s*)(`{3,}|~{3,})(.*)$")
# Angle-bracket link target: [t](<...>) — inner may contain spaces / parens / +.
ANGLE_RE = re.compile(r"\]\(<([^>]+?)>\)")
# Bare link target: [t](...) — no spaces/parens/angles; '&' is allowed because
# the source contains bare targets like ](Client-Runtime-&-SOCKS5-Proxy.md).
BARE_RE = re.compile(r"\]\(([^()<>\s]+)\)")

_ANGLE_FORCING = (" ", "(", ")", "&", "+")


def rule_c(path):
    """Rewrite a ``../`` source-tree path to an absolute blob/tree URL.

    Returns None for a path that escapes the repo root (``../../``), so the
    caller leaves it untouched rather than guessing.
    """
    rel = path[len("../"):].lstrip("/")
    if ".." in rel.split("/"):
        return None
    base = TREE if path.endswith("/") else BLOB
    return f"{base}/{rel}"


def transform_target(raw):
    """Map a captured link target to its replacement, or None to leave as-is."""
    path, sep, frag = raw.partition("#")
    frag = sep + frag  # "" or "#anchor"
    low = path.lower()

    if low.startswith(("http://", "https://", "mailto:")):
        return None
    if path == "":  # pure "#anchor"
        return None
    if path.startswith("../"):
        new = rule_c(path)
        return None if new is None else new + frag

    base = path[:-3] if low.endswith(".md") else path  # Rule A
    if base == "README":  # Rule B
        base = "Home"
    return base + frag


def _wrap(target):
    if any(c in target for c in _ANGLE_FORCING):
        return "](<" + target + ">)"
    return "](" + target + ")"


def _sub(match):
    new = transform_target(match.group(1))
    return match.group(0) if new is None else _wrap(new)


def transform_line(line):
    # Angle form first so its <...> targets aren't seen by the bare regex; both
    # substitutions are idempotent, so a re-match on the bare pass is harmless.
    return BARE_RE.sub(_sub, ANGLE_RE.sub(_sub, line))


def convert_text(text):
    out = []
    in_fence = False
    fence_char = ""
    fence_len = 0
    for line in text.split("\n"):
        m = FENCE_RE.match(line)
        if in_fence:
            out.append(line)  # never rewrite inside a fence
            if m and m.group(2)[0] == fence_char and len(m.group(2)) >= fence_len \
                    and m.group(3).strip() == "":
                in_fence = False
            continue
        if m:
            in_fence = True
            fence_char = m.group(2)[0]
            fence_len = len(m.group(2))
            out.append(line)
            continue
        out.append(transform_line(line))
    return "\n".join(out)


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--src", required=True, help="source dir (ParallaX-DeepWiki)")
    ap.add_argument("--out", required=True, help="output dir (wiki working tree)")
    args = ap.parse_args()

    names = sorted(n for n in os.listdir(args.src) if n.endswith(".md"))
    if not names:
        sys.exit(f"no .md files found under {args.src}")
    os.makedirs(args.out, exist_ok=True)

    for name in names:
        with open(os.path.join(args.src, name), encoding="utf-8") as f:
            text = f.read()
        out_name = "Home.md" if name == "README.md" else name
        with open(os.path.join(args.out, out_name), "w", encoding="utf-8",
                  newline="\n") as f:
            f.write(convert_text(text))

    print(f"converted {len(names)} files -> {args.out}")


if __name__ == "__main__":
    main()
