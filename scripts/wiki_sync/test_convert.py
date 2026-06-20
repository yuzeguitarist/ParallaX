#!/usr/bin/env python3
"""Pin the wiki conversion rules. Run with `pytest` or directly: `python3 test_convert.py`.

The end-to-end acceptance check is in sync.sh's local dry-run (convert.py output
diffed against a fresh clone of the live wiki). These cases lock the individual
rules so future edits to convert.py can't silently regress them.
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import convert  # noqa: E402

line = convert.transform_line
text = convert.convert_text


def test_strip_md_bare():
    assert line("[Core Architecture](Core-Architecture.md)") == \
        "[Core Architecture](Core-Architecture)"


def test_bare_ampersand_normalized_to_angle():
    # '&' in the target forces the angle-bracket form to match the live wiki.
    assert line("[Client Runtime & SOCKS5 Proxy](Client-Runtime-&-SOCKS5-Proxy.md)") == \
        "[Client Runtime & SOCKS5 Proxy](<Client-Runtime-&-SOCKS5-Proxy>)"


def test_angle_with_parens_plus_amp():
    src = "[PQ](<Post-Quantum-Cryptography-(ML-KEM-&-ML-DSA).md>)"
    assert line(src) == "[PQ](<Post-Quantum-Cryptography-(ML-KEM-&-ML-DSA)>)"
    src2 = "[Auth](<ClientHello-Authentication-(PSK-+-X25519).md>)"
    assert line(src2) == "[Auth](<ClientHello-Authentication-(PSK-+-X25519)>)"


def test_readme_to_home():
    assert line("[Index](README.md)") == "[Index](Home)"
    assert line("[x](README)") == "[x](Home)"


def test_rule_c_file_uses_blob():
    assert line("[../src/main.rs](../src/main.rs)") == \
        "[../src/main.rs](https://github.com/yuzeguitarist/ParallaX/blob/main/src/main.rs)"


def test_rule_c_dir_uses_tree():
    assert line("[../src/](../src/)") == \
        "[../src/](https://github.com/yuzeguitarist/ParallaX/tree/main/src/)"


def test_external_and_anchor_untouched():
    assert line("[x](https://example.com/a.md)") == "[x](https://example.com/a.md)"
    assert line("[x](#section)") == "[x](#section)"


def test_repo_escaping_left_alone():
    assert line("[x](../../secret.md)") == "[x](../../secret.md)"


def test_fenced_block_is_verbatim():
    src = "```bash\nsee [Foo](Foo.md) and ../src/main.rs\n```\n[Foo](Foo.md)"
    out = text(src)
    assert "see [Foo](Foo.md) and ../src/main.rs" in out  # inside fence: untouched
    assert out.endswith("[Foo](Foo)")                      # outside fence: rewritten


def test_tilde_fence_and_lang_info_string():
    src = "~~~\n[A](A.md)\n~~~"
    assert text(src) == src  # tilde fence with an inner link stays verbatim


if __name__ == "__main__":
    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    for fn in fns:
        fn()
    print(f"ok: {len(fns)} tests passed")
