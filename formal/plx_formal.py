#!/usr/bin/env python3
"""Exhaustive checker and TLA+ emitter for the ParallaX session state machines.

The transition tables in this file are the source of truth. ``check`` explores
every reachable state and proves the safety formulas (the transitions that must
never happen). ``emit`` writes the same tables as TLA+ so TLC can check them
with an independent engine. ``correspond`` checks that the Rust control flow
still matches the assumptions the tables were built from.

What is modeled, and what is not:

* TCP session: inbound auth, early pending admission, epoch-0 keys, PQ replay commit, identity,
  application data, UDP retain, failure, and reconnect. Crypto bytes are not
  modeled; a successful auth step stands in for a passing PSK/X25519 check.
* QUIC TLS handshake: the client ``ReadState`` order and the server
  ``ServerState`` order, including PSK resumption (no Certificate) and alerts.
* 0-RTT: one ticket identity. The client consumes it on offer. The server
  accepts it once, only after a good binder and only when the replay guard's
  lock is free. A second offer is a replay. Relay bytes wait for the handshake.
* Replay insert: the in-memory ``stage_insert`` order (stale, then nonce,
  then transcript, then capacity) for one slot. The journal MAC is not modeled.
* UDP probe: the timeout / loss / reply classification and the server's
  retain / hard-fail / stay decision. HMAC bytes are not modeled.
* Inbound decision function: auth, SNI, authorization. The surrounding pending
  replay-admission gate is modeled separately in the TCP session machine.
* QUIC key installation: the order ``write_handshake`` emits 0-RTT, Handshake,
  and 1-RTT keys. Key bytes are not modeled.
* QUIC close: one local CONNECTION_CLOSE, a silent peer or idle close, then drain.
* BBR mode: Startup, ProbeBW, and ProbeRTT. The window in bytes is not modeled.
* QUIC first byte: the fixed bit, header form, and long-packet type. Later
  header fields are not modeled.
* Record batches: reserve-before-dispatch, ordered publication, permanent poison
  after worker failure, and fresh-key rekey in a three-sequence nonce window.
* Framed commands: every partition of payload lengths 1..3, two successive
  frames, completion reset, and terminal rejection of malformed chunks.
* TCP MUX: two streams under capacity one/two, half-close in either direction,
  asynchronous cancellation, local failure isolation, and carrier teardown.
* PX1I caller: bounded arbitrary chunk metadata, authenticated decode, strict
  accumulation, identity verification, and establishment failure/deadline gates.

Run ``python3 formal/plx_formal.py check`` from the repository root.
"""

from __future__ import annotations

import argparse
import re
import subprocess
import sys
import tempfile
from collections import deque
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Mapping, Optional, Sequence, Union


ROOT = Path(__file__).resolve().parents[1]
FORMAL = Path(__file__).resolve().parent

# Every file ``correspond`` reads. The reorder test copies this list into a
# throwaway tree, so a new anchor has to be added here or that test cannot see it.
CORRESPOND_FILES = (
    "src/handshake/server.rs",
    "src/handshake/client.rs",
    "src/client/runtime.rs",
    "src/tls/quic/handshake.rs",
    "src/tls/quic/server.rs",
    "src/transport/udp/zero_rtt.rs",
    "src/crypto/session.rs",
    "src/crypto/pq.rs",
    "src/crypto/replay.rs",
    "src/transport/udp/probe.rs",
    "src/transport/udp/quic/conn.rs",
    "src/transport/udp/quic/congestion.rs",
    "src/transport/udp/quic/packet.rs",
    "src/protocol/command.rs",
    "src/protocol/data.rs",
)

Scalar = Union[bool, int, str]
State = dict[str, Scalar]
AST = Union["Not", "Bin", "Cmp", "FieldCmp", "InSet", "Flag"]


class FormalError(Exception):
    """A model, correspondence, or TLC failure. The message is the CI log."""


@dataclass(frozen=True)
class Not:
    inner: AST


@dataclass(frozen=True)
class Bin:
    op: str
    left: AST
    right: AST


@dataclass(frozen=True)
class Cmp:
    op: str
    field: str
    value: Scalar


@dataclass(frozen=True)
class FieldCmp:
    """Compare two state fields. TLA+ already allows ``a = b``; the checker does too."""

    op: str
    left: str
    right: str


@dataclass(frozen=True)
class InSet:
    field: str
    values: frozenset[Scalar]


@dataclass(frozen=True)
class Flag:
    field: str


@dataclass(frozen=True)
class Formula:
    text: str
    tree: AST

    def holds(self, state: Mapping[str, Scalar]) -> bool:
        # Walks the formula AST. This is not Python eval.
        return _holds(self.tree, state)


@dataclass(frozen=True)
class Action:
    name: str
    guard: str
    assign: dict[str, str]


@dataclass(frozen=True)
class Claim:
    name: str
    formula: str
    summary: str


@dataclass(frozen=True)
class Machine:
    name: str
    blurb: str
    fields: tuple[str, ...]
    defaults: dict[str, Scalar]
    initials: tuple[dict[str, Scalar], ...]
    actions: tuple[Action, ...]
    invariants: tuple[Claim, ...]
    witnesses: tuple[Claim, ...]
    terminal: str


@dataclass
class Report:
    name: str
    states: int
    terminals: int
    invariant_names: tuple[str, ...]
    witness_names: tuple[str, ...]


def tokenize(text: str) -> list[str]:
    i = 0
    n = len(text)
    out: list[str] = []
    while i < n:
        c = text[i]
        if c.isspace():
            i += 1
            continue
        if text.startswith("=>", i):
            out.append("=>")
            i += 2
            continue
        if text.startswith("\\/", i):
            out.append("\\/")
            i += 2
            continue
        if text.startswith("/\\", i):
            out.append("/\\")
            i += 2
            continue
        if text.startswith("\\in", i):
            out.append("\\in")
            i += 3
            continue
        if c in "~#=<>()+{},":
            out.append(c)
            i += 1
            continue
        if c == '"':
            j = text.find('"', i + 1)
            if j < 0:
                raise FormalError(f"unterminated string in formula: {text}")
            out.append(text[i : j + 1])
            i = j + 1
            continue
        if c.isdigit():
            j = i + 1
            while j < n and text[j].isdigit():
                j += 1
            out.append(text[i:j])
            i = j
            continue
        if c.isalpha() or c == "_":
            j = i + 1
            while j < n and (text[j].isalnum() or text[j] == "_"):
                j += 1
            out.append(text[i:j])
            i = j
            continue
        raise FormalError(f"cannot tokenize {text[i : i + 24]!r} in: {text}")
    return out


class _Parser:
    def __init__(self, tokens: Sequence[str], text: str) -> None:
        self.tokens = tokens
        self.text = text
        self.i = 0

    def peek(self) -> Optional[str]:
        if self.i >= len(self.tokens):
            return None
        return self.tokens[self.i]

    def pop(self) -> str:
        tok = self.peek()
        if tok is None:
            raise FormalError(f"unexpected end of formula: {self.text}")
        self.i += 1
        return tok

    def parse(self) -> AST:
        tree = self._impl()
        if self.peek() is not None:
            raise FormalError(
                f"leftover {self.peek()!r} in formula: {self.text}"
            )
        return tree

    def _impl(self) -> AST:
        left = self._or()
        if self.peek() == "=>":
            self.pop()
            return Bin("=>", left, self._impl())
        return left

    def _or(self) -> AST:
        left = self._and()
        while self.peek() == "\\/":
            self.pop()
            left = Bin("\\/", left, self._and())
        return left

    def _and(self) -> AST:
        left = self._not()
        while self.peek() == "/\\":
            self.pop()
            left = Bin("/\\", left, self._not())
        return left

    def _not(self) -> AST:
        if self.peek() == "~":
            self.pop()
            return Not(self._not())
        return self._atom()

    def _atom(self) -> AST:
        if self.peek() == "(":
            self.pop()
            inner = self._impl()
            if self.pop() != ")":
                raise FormalError(f"missing ')' in formula: {self.text}")
            return inner
        tok = self.pop()
        if tok in {"TRUE", "FALSE"}:
            raise FormalError(
                f"bare {tok} is not a state formula (use it in an assignment): {self.text}"
            )
        if self.peek() in {"=", "#", "<", "\\in"}:
            op = self.pop()
            if op == "\\in":
                return InSet(tok, frozenset(self._set()))
            nxt = self.peek()
            if nxt is not None and self._is_field(nxt):
                return FieldCmp(op, tok, self.pop())
            return Cmp(op, tok, self._scalar())
        return Flag(tok)

    def _is_field(self, tok: str) -> bool:
        if tok in {"TRUE", "FALSE"}:
            return False
        return tok[0].isalpha() or tok[0] == "_"

    def _set(self) -> list[Scalar]:
        if self.pop() != "{":
            raise FormalError(f"expected a set in formula: {self.text}")
        values = [self._scalar()]
        while self.peek() == ",":
            self.pop()
            values.append(self._scalar())
        if self.pop() != "}":
            raise FormalError(f"expected '}}' in formula: {self.text}")
        return values

    def _scalar(self) -> Scalar:
        tok = self.pop()
        if tok == "TRUE":
            return True
        if tok == "FALSE":
            return False
        if tok.startswith('"') and tok.endswith('"'):
            return tok[1:-1]
        if tok.isdigit():
            return int(tok)
        raise FormalError(f"expected a value, found {tok!r} in: {self.text}")


# Guards and invariants are immutable. The model checker used to parse the same
# text on every enabled-action test; the explored set depends only on the tree.
_FORMULAS: dict[str, Formula] = {}


def formula(text: str) -> Formula:
    cached = _FORMULAS.get(text)
    if cached is None:
        cached = Formula(text, _Parser(tokenize(text), text).parse())
        _FORMULAS[text] = cached
    return cached


def _holds(tree: AST, state: Mapping[str, Scalar]) -> bool:
    if isinstance(tree, Not):
        return not _holds(tree.inner, state)
    if isinstance(tree, Bin):
        left = _holds(tree.left, state)
        if tree.op == "/\\":
            return left and _holds(tree.right, state)
        if tree.op == "\\/":
            return left or _holds(tree.right, state)
        if tree.op == "=>":
            return (not left) or _holds(tree.right, state)
        raise FormalError(f"unknown operator {tree.op}")
    if isinstance(tree, Flag):
        value = state[tree.field]
        if not isinstance(value, bool):
            raise FormalError(f"{tree.field} is not a boolean flag")
        return value
    if isinstance(tree, Cmp):
        left = state[tree.field]
        if tree.op == "=":
            return left == tree.value
        if tree.op == "#":
            return left != tree.value
        if tree.op == "<":
            if not isinstance(left, int) or not isinstance(tree.value, int):
                raise FormalError(f"cannot compare {tree.field}")
            return left < tree.value
        raise FormalError(f"unknown comparison {tree.op}")
    if isinstance(tree, FieldCmp):
        left = state[tree.left]
        right = state[tree.right]
        if tree.op == "=":
            return left == right
        if tree.op == "#":
            return left != right
        if tree.op == "<":
            if not isinstance(left, int) or not isinstance(right, int):
                raise FormalError(f"cannot compare {tree.left} with {tree.right}")
            return left < right
        raise FormalError(f"unknown comparison {tree.op}")
    if isinstance(tree, InSet):
        return state[tree.field] in tree.values
    raise FormalError(f"cannot evaluate {tree!r}")


def act(name: str, guard: str, **assign: str) -> Action:
    return Action(name, guard, dict(assign))


def claim(name: str, summary: str, body: str) -> Claim:
    return Claim(name, body, summary)


def _key(machine: Machine, state: State) -> tuple[Scalar, ...]:
    return tuple(state[field] for field in machine.fields)


def _initials(machine: Machine) -> list[State]:
    if not machine.initials:
        return [dict(machine.defaults)]
    states = []
    for override in machine.initials:
        state = dict(machine.defaults)
        state.update(override)
        states.append(state)
    return states


def _field_index(index: dict[str, int], field: str) -> int:
    try:
        return index[field]
    except KeyError:
        raise FormalError(f"formula mentions unknown field {field}") from None


def _compile_pred(tree: AST, index: dict[str, int]):
    """Turn a formula tree into a predicate on a field-ordered state tuple.

    The cases match ``_holds``. ``/\\``, ``\\/``, and ``=>`` short-circuit the
    same way, so a guard that would not evaluate its right side still does not.
    """

    if isinstance(tree, Not):
        inner = _compile_pred(tree.inner, index)
        return lambda st, inner=inner: not inner(st)
    if isinstance(tree, Bin):
        left = _compile_pred(tree.left, index)
        right = _compile_pred(tree.right, index)
        if tree.op == "/\\":
            return lambda st, left=left, right=right: left(st) and right(st)
        if tree.op == "\\/":
            return lambda st, left=left, right=right: left(st) or right(st)
        if tree.op == "=>":
            return lambda st, left=left, right=right: (not left(st)) or right(st)
        raise FormalError(f"unknown operator {tree.op}")
    if isinstance(tree, Flag):
        i = _field_index(index, tree.field)
        field = tree.field

        def ev_flag(st, i=i, field=field):
            value = st[i]
            if not isinstance(value, bool):
                raise FormalError(f"{field} is not a boolean flag")
            return value

        return ev_flag
    if isinstance(tree, Cmp):
        i = _field_index(index, tree.field)
        field = tree.field
        op = tree.op
        value = tree.value
        if op == "=":
            return lambda st, i=i, value=value: st[i] == value
        if op == "#":
            return lambda st, i=i, value=value: st[i] != value
        if op == "<":

            def ev_lt(st, i=i, value=value, field=field):
                left = st[i]
                if not isinstance(left, int) or not isinstance(value, int):
                    raise FormalError(f"cannot compare {field}")
                return left < value

            return ev_lt
        raise FormalError(f"unknown comparison {op}")
    if isinstance(tree, FieldCmp):
        li = _field_index(index, tree.left)
        ri = _field_index(index, tree.right)
        op = tree.op
        if op == "=":
            return lambda st, li=li, ri=ri: st[li] == st[ri]
        if op == "#":
            return lambda st, li=li, ri=ri: st[li] != st[ri]
        if op == "<":

            def ev_field_lt(st, li=li, ri=ri, left=tree.left, right=tree.right):
                lv = st[li]
                rv = st[ri]
                if not isinstance(lv, int) or not isinstance(rv, int):
                    raise FormalError(f"cannot compare {left} with {right}")
                return lv < rv

            return ev_field_lt
        raise FormalError(f"unknown comparison {op}")
    if isinstance(tree, InSet):
        i = _field_index(index, tree.field)
        values = tree.values
        return lambda st, i=i, values=values: st[i] in values
    raise FormalError(f"cannot evaluate {tree!r}")


def _compile_rhs(expr: str, index: dict[str, int]):
    """Compile one assignment. Reads the pre-step tuple, not the updated one."""

    text = expr.strip()
    if text == "TRUE":
        return lambda _st: True
    if text == "FALSE":
        return lambda _st: False
    if text.startswith('"') and text.endswith('"') and len(text) >= 2:
        value = text[1:-1]
        return lambda _st, value=value: value
    if text.isdigit():
        value = int(text)
        return lambda _st, value=value: value
    if text in index:
        i = index[text]
        return lambda st, i=i: st[i]
    parts = text.split("+")
    if len(parts) == 2 and parts[1].strip().isdigit():
        field = parts[0].strip()
        i = _field_index(index, field)
        add = int(parts[1].strip())

        def ev_add(st, i=i, add=add, field=field):
            current = st[i]
            if not isinstance(current, int):
                raise FormalError(f"{field} is not an integer in an assignment")
            return current + add

        return ev_add
    raise FormalError(f"cannot evaluate assignment '{expr}'")


def _compile_guard(text: str, index: dict[str, int]):
    return _compile_pred(formula(text).tree, index)


def _trace(parents: dict[tuple[Scalar, ...], tuple], end: tuple[Scalar, ...]) -> list[str]:
    steps: list[str] = []
    cursor: Optional[tuple[Scalar, ...]] = end
    while cursor is not None:
        parent, name = parents[cursor]
        if name is not None:
            steps.append(name)
        cursor = parent
    steps.reverse()
    return steps


def _format_state(machine: Machine, state: State) -> str:
    parts = [f"{field}={state[field]!r}" for field in machine.fields]
    return ", ".join(parts)


def check_machine(machine: Machine) -> Report:
    names = [action.name for action in machine.actions]
    if len(names) != len(set(names)):
        raise FormalError(f"{machine.name} has duplicate action names")
    for field in machine.fields:
        if field not in machine.defaults:
            raise FormalError(f"{machine.name} default missing {field}")
    index = {field: i for i, field in enumerate(machine.fields)}
    compiled_actions = []
    for action in machine.actions:
        if not action.name.isidentifier():
            raise FormalError(f"bad action name {action.name}")
        guard = _compile_guard(action.guard, index)
        assigns = []
        for field, rhs in action.assign.items():
            if field not in machine.defaults:
                raise FormalError(f"{action.name} assigns unknown field {field}")
            assigns.append((index[field], _compile_rhs(rhs, index)))
        compiled_actions.append((action.name, guard, tuple(assigns)))
    compiled_inv = [
        (item, _compile_guard(item.formula, index)) for item in machine.invariants
    ]
    compiled_wit = [
        (item, _compile_guard(item.formula, index)) for item in machine.witnesses
    ]
    terminal = _compile_guard(machine.terminal, index)

    parents: dict[tuple[Scalar, ...], tuple] = {}
    states: dict[tuple[Scalar, ...], tuple[Scalar, ...]] = {}
    queue: deque[tuple[Scalar, ...]] = deque()
    for initial in _initials(machine):
        key = _key(machine, initial)
        if key not in states:
            states[key] = key
            parents[key] = (None, None)
            queue.append(key)

    def as_dict(key: tuple[Scalar, ...]) -> State:
        return {field: key[i] for i, field in enumerate(machine.fields)}

    terminals = 0
    while queue:
        state = queue.popleft()
        moved = False
        for name, guard, assigns in compiled_actions:
            if not guard(state):
                continue
            if assigns:
                updated = list(state)
                for pos, fn in assigns:
                    updated[pos] = fn(state)
                nxt = tuple(updated)
            else:
                nxt = state
            if nxt == state:
                raise FormalError(f"{machine.name}.{name} is a stuttering step")
            moved = True
            if nxt not in states:
                states[nxt] = nxt
                parents[nxt] = (state, name)
                queue.append(nxt)
        # Safety first. A stuck state that also breaks an invariant should name
        # the invariant; the dead-end check is for a stuck state that is
        # otherwise legal.
        for item, compiled in compiled_inv:
            if not compiled(state):
                steps = " -> ".join(_trace(parents, state)) or "(initial)"
                raise FormalError(
                    f"{machine.name} invariant {item.name} failed\n"
                    f"  {item.summary}\n"
                    f"  trace: {steps}\n"
                    f"  state: {_format_state(machine, as_dict(state))}"
                )
        if not moved:
            terminals += 1
            if not terminal(state):
                steps = " -> ".join(_trace(parents, state)) or "(initial)"
                raise FormalError(
                    f"{machine.name} reached a non-terminal dead end\n"
                    f"  trace: {steps}\n"
                    f"  state: {_format_state(machine, as_dict(state))}"
                )

    for item, compiled in compiled_wit:
        if not any(compiled(state) for state in states):
            raise FormalError(
                f"{machine.name} witness {item.name} was never reached\n"
                f"  {item.summary}"
            )
    return Report(
        machine.name,
        len(states),
        terminals,
        tuple(item.name for item in machine.invariants),
        tuple(item.name for item in machine.witnesses),
    )


def session_machine() -> Machine:
    """TCP camouflage session, from the first record through reconnect.

    Replay admission has two phases. After auth/SNI, ``reserve_pending`` can
    refuse an already committed, stale, duplicate-pending, or pending-full
    hello; a busy lock also refuses it. This early refusal splices without
    epoch-0 keys. Admission success reserves only an in-flight transcript,
    not a durable journal entry. A missing optional cache skips reservation.
    ``derive_keys_from_shared`` then rejects an all-zero X25519 secret without
    splicing. Epoch-0 keys exist only after admission and that check.
    The replay cache is committed only after a valid PQ rekey frame arrives;
    a race, newly stale timestamp, full journal/source quota, or missing cache
    closes before ``apply_server_pq_rekey``. ``hybrid_sandwich_rekey`` rejects an
    all-zero ephemeral the same way and does not advance the epoch. Identity
    verification requires the binding written by a successful rekey.
    Application data and UDP retain happen only after identity succeeds.
    Reconnect starts a fresh attempt at epoch 0.
    """

    fields = (
        "phase",
        "epoch",
        "binding",
        "keys",
        "usable",
        "admission",
        "replay",
        "attempt",
        "app",
        "udp",
        "how",
    )
    defaults: dict[str, Scalar] = {
        "phase": "idle",
        "epoch": 0,
        "binding": False,
        "keys": False,
        "usable": False,
        "admission": "none",
        "replay": "none",
        "attempt": 0,
        "app": False,
        "udp": "none",
        "how": "none",
    }
    live = 'phase \\in {"epoch0", "rekey_wait", "rekeyed", "verified", "app"}'
    drop = dict(usable="FALSE", app="FALSE", udp='"none"')
    return Machine(
        name="ParallaXSession",
        blurb=(
            "Handshake, early pending admission, late PQ replay commit, identity, app data, "
            "UDP retain, failure, and reconnect."
        ),
        fields=fields,
        defaults=defaults,
        initials=(),
        actions=(
            act("AuthFail", 'phase = "idle"', phase='"failed"', how='"splice"'),
            act("MissingSni", 'phase = "idle"', phase='"failed"', how='"splice"'),
            act("UnauthorizedSni", 'phase = "idle"', phase='"failed"', how='"splice"'),
            act("AuthOk", 'phase = "idle"', phase='"authed"'),
            act("AdmitPendingReplay", 'phase = "authed"',
                phase='"admitted"', admission='"reserved"'),
            act("AdmitWithoutReplayCache", 'phase = "authed"',
                phase='"admitted"', admission='"missing"'),
            *tuple(
                act(name, 'phase = "authed"', phase='"failed"',
                    admission=f'"{reason}"', how='"splice"')
                for name, reason in (
                    ("EarlyStaleSplice", "stale"),
                    ("EarlyCommittedNonceSplice", "committed_nonce"),
                    ("EarlyCommittedTranscriptSplice", "committed_transcript"),
                    ("EarlyDuplicatePendingSplice", "duplicate_pending"),
                    ("EarlyPendingFullSplice", "pending_full"),
                    ("EarlyBusyLockSplice", "busy"),
                )
            ),
            act(
                "DegenerateSharedSecret",
                'phase = "admitted"',
                phase='"failed"',
                how='"degen"',
            ),
            act(
                "InstallEpoch0",
                'phase = "admitted"',
                phase='"epoch0"',
                keys="TRUE",
                usable="TRUE",
            ),
            act(
                "SendRekey",
                'phase = "epoch0" /\\ usable /\\ ~binding',
                phase='"rekey_wait"',
                replay='"pending"',
            ),
            act(
                "ReplayReplayed",
                'phase = "rekey_wait" /\\ replay = "pending" /\\ admission = "reserved"',
                phase='"rejected"',
                replay='"replayed"',
                **drop,
            ),
            act(
                "ReplayStale",
                'phase = "rekey_wait" /\\ replay = "pending" /\\ admission = "reserved"',
                phase='"rejected"',
                replay='"stale"',
                **drop,
            ),
            act(
                "ReplayCacheFull",
                'phase = "rekey_wait" /\\ replay = "pending" /\\ admission = "reserved"',
                phase='"rejected"',
                replay='"full"',
                **drop,
            ),
            act(
                "ReplaySourceQuota",
                'phase = "rekey_wait" /\\ replay = "pending" /\\ admission = "reserved"',
                phase='"rejected"', replay='"source_quota"', **drop,
            ),
            act(
                "ReplayMissingCache",
                'phase = "rekey_wait" /\\ replay = "pending" /\\ admission = "missing"',
                phase='"rejected"', replay='"missing"', **drop,
            ),
            act(
                "RekeyMalformed",
                'phase = "rekey_wait"',
                phase='"failed"',
                **drop,
            ),
            act(
                "RekeyDegenerate",
                'phase = "rekey_wait" /\\ replay = "pending" /\\ admission = "reserved"',
                phase='"failed"',
                replay='"inserted"',
                how='"rekey_degen"',
                **drop,
            ),
            act(
                "VerifyBeforeBinding",
                'phase \\in {"epoch0", "rekey_wait"}',
                phase='"failed"',
                **drop,
            ),
            act(
                "RekeyOk",
                'phase = "rekey_wait" /\\ replay = "pending" /\\ admission = "reserved" /\\ usable',
                phase='"rekeyed"',
                replay='"inserted"',
                epoch="epoch + 1",
                binding="TRUE",
            ),
            act(
                "IdentityOk",
                'phase = "rekeyed" /\\ binding /\\ epoch = 1',
                phase='"verified"',
            ),
            act("IdentityFail", 'phase = "rekeyed"', phase='"failed"', **drop),
            act(
                "EnterApp",
                'phase = "verified" /\\ binding /\\ epoch = 1 /\\ usable',
                phase='"app"',
                app="TRUE",
            ),
            act(
                "ProbeRetain",
                'phase = "app" /\\ udp = "none"',
                udp='"retained"',
            ),
            act(
                "ProbeStayTcp",
                'phase = "app" /\\ udp = "none"',
                udp='"tcp_only"',
            ),
            act("Close", live, phase='"closed"', **drop),
            act("TransportError", live, phase='"failed"', **drop),
            act(
                "Reconnect",
                'phase \\in {"rejected", "closed", "failed"} /\\ attempt < 2',
                phase='"idle"',
                epoch="0",
                binding="FALSE",
                keys="FALSE",
                usable="FALSE",
                admission='"none"',
                replay='"none"',
                app="FALSE",
                udp='"none"',
                how='"none"',
                attempt="attempt + 1",
            ),
        ),
        invariants=(
            claim(
                "AppOnlyAfterIdentity",
                "application data only after identity, at epoch 1, with live keys",
                'app => (phase = "app" /\\ binding /\\ epoch = 1 /\\ usable /\\ keys)',
            ),
            claim(
                "VerifiedImpliesBinding",
                "verified and app phases have a binding, epoch 1, and live keys",
                'phase \\in {"verified", "app"} => (binding /\\ epoch = 1 /\\ keys /\\ usable)',
            ),
            claim(
                "RekeyedImpliesFreshCommit",
                "a rekeyed session has a fresh replay insert, a binding, and epoch 1",
                'phase = "rekeyed" => (replay = "inserted" /\\ binding /\\ epoch = 1 /\\ usable)',
            ),
            claim(
                "ReplayClosesBeforeRekey",
                "late replay/stale/full/source-quota/missing-cache refusal closes at epoch 0 without splicing",
                'replay \\in {"replayed", "stale", "full", "source_quota", "missing"} => (phase = "rejected" /\\ epoch = 0 /\\ keys /\\ ~binding /\\ ~app /\\ ~usable /\\ how # "splice")',
            ),
            claim(
                "PendingRefusalSplicesWithoutKeys",
                "early replay admission refusal splices before any session keys are installed",
                'admission \\in {"stale", "committed_nonce", "committed_transcript", "duplicate_pending", "pending_full", "busy"} => (phase = "failed" /\\ how = "splice" /\\ epoch = 0 /\\ ~keys /\\ ~usable /\\ ~binding /\\ ~app)',
            ),
            claim(
                "EpochZeroRequiresAdmission",
                "epoch-0 keys require an accepted pending gate, or the optional-cache-missing path",
                'keys => admission \\in {"reserved", "missing"}',
            ),
            claim(
                "AdmittedStillHasNoKeys",
                "pending admission alone does not install keys before the shared-secret check",
                'phase = "admitted" => (admission \\in {"reserved", "missing"} /\\ epoch = 0 /\\ ~keys /\\ ~usable /\\ ~binding)',
            ),
            claim(
                "IdleAndReconnectAreFresh",
                "idle, including after reconnect, holds no keys, binding, app data, or failure class",
                'phase = "idle" => (epoch = 0 /\\ ~binding /\\ ~keys /\\ ~usable /\\ ~app /\\ udp = "none" /\\ admission = "none" /\\ replay = "none" /\\ how = "none")',
            ),
            claim(
                "AuthedHasNoKeys",
                "authentication alone has not installed epoch-0 keys",
                'phase = "authed" => (epoch = 0 /\\ ~keys /\\ ~usable /\\ ~binding /\\ admission = "none" /\\ how = "none")',
            ),
            claim(
                "PostAuthDegenerateDoesNotSplice",
                "an all-zero shared secret after auth closes with no keys and is not a fallback splice",
                'how = "degen" => (phase = "failed" /\\ ~keys /\\ ~usable /\\ epoch = 0 /\\ ~binding /\\ ~app)',
            ),
            claim(
                "RekeyDegenerateStaysAtEpochZero",
                "an all-zero ephemeral in hybrid_sandwich_rekey fails after the replay insert, without splicing or advancing the epoch",
                'how = "rekey_degen" => (phase = "failed" /\\ epoch = 0 /\\ keys /\\ ~usable /\\ ~binding /\\ ~app /\\ replay = "inserted")',
            ),
            claim(
                "SpliceIsTheInboundReject",
                "a fallback splice is an inbound auth/SNI or early pending-admission refusal before keys exist",
                'how = "splice" => (phase = "failed" /\\ ~keys /\\ epoch = 0 /\\ ~binding)',
            ),
            claim(
                "TerminalDropsUsableKeys",
                "rejected, closed, and failed sessions cannot seal or send app data",
                'phase \\in {"rejected", "closed", "failed"} => (~usable /\\ ~app /\\ udp = "none")',
            ),
            claim(
                "UdpRetainOnlyAfterApp",
                "a retained QUIC leg exists only on a live, identity-verified app session",
                'udp = "retained" => (phase = "app" /\\ app /\\ usable)',
            ),
            claim(
                "UdpDeclineStaysOnApp",
                "a declined or failed UDP probe leaves the app session on TCP",
                'udp = "tcp_only" => (phase = "app" /\\ app /\\ usable)',
            ),
            claim(
                "UsableKeysImplyAuth",
                "usable keys exist only after auth, and never in the idle phase",
                "(usable => keys) /\\ (keys => (phase # \"idle\"))",
            ),
            claim(
                "EpochIsZeroOrOne",
                "a successful rekey steps the epoch by one and never past 1 here",
                "epoch \\in {0, 1}",
            ),
            claim(
                "RejectedOnlyAfterReplay",
                "the rejected phase is produced only by a replay-cache refusal",
                'phase = "rejected" => replay \\in {"replayed", "stale", "full", "source_quota", "missing"}',
            ),
            claim(
                "BindingMeansRekeyedEpoch",
                "an identity binding exists only at epoch 1 after a fresh replay insert",
                'binding => (epoch = 1 /\\ admission = "reserved" /\\ replay = "inserted" /\\ phase \\in {"rekeyed", "verified", "app", "closed", "failed"})',
            ),
            claim(
                "AttemptInBounds",
                "reconnect is bounded; attempt 2 is the last one",
                "attempt \\in {0, 1, 2}",
            ),
        ),
        witnesses=(
            claim(
                "HappyPathRetainsUdp",
                "an authenticated session can rekey, verify, and retain UDP",
                'app /\\ udp = "retained" /\\ binding /\\ epoch = 1',
            ),
            claim(
                "ProbeCanStayOnTcp",
                "a failed UDP probe keeps the verified session on TCP",
                'app /\\ udp = "tcp_only"',
            ),
            claim(
                "ReplayIsRejected",
                "a replay race after early admission is rejected with epoch still 0",
                'phase = "rejected" /\\ replay = "replayed" /\\ epoch = 0 /\\ ~usable',
            ),
            claim(
                "StaleIsRejected",
                "a reserved hello that expires before its data proof is rejected before rekey",
                'phase = "rejected" /\\ replay = "stale"',
            ),
            claim(
                "CacheFullIsRejected",
                "a full replay cache sheds the handshake before rekey",
                'phase = "rejected" /\\ replay = "full"',
            ),
            claim("PendingAdmissionCanInstallEpochZero", "an early fresh reservation may proceed to epoch-0 keys",
                  'admission = "reserved" /\\ phase = "epoch0" /\\ keys'),
            *tuple(
                claim(name, "early pending admission refusal splices with no epoch-0 keys",
                      f'admission = "{reason}" /\\ phase = "failed" /\\ how = "splice" /\\ ~keys')
                for name, reason in (
                    ("EarlyStaleUsesOrigin", "stale"),
                    ("EarlyCommittedNonceUsesOrigin", "committed_nonce"),
                    ("EarlyCommittedTranscriptUsesOrigin", "committed_transcript"),
                    ("DuplicatePendingUsesOrigin", "duplicate_pending"),
                    ("PendingCapacityUsesOrigin", "pending_full"),
                    ("BusyReplayLockUsesOrigin", "busy"),
                )
            ),
            claim("LateMissingCacheCloses", "missing optional cache fails closed at the later data-proof commit",
                  'admission = "missing" /\\ replay = "missing" /\\ phase = "rejected" /\\ keys /\\ how # "splice"'),
            claim("LateSourceQuotaCloses", "a per-source committed-journal quota refusal closes after the data proof",
                  'admission = "reserved" /\\ replay = "source_quota" /\\ phase = "rejected" /\\ keys /\\ how # "splice"'),
            claim(
                "AuthFailureInstallsNoKeys",
                "auth and SNI failures install no keys",
                'how = "splice" /\\ admission = "none" /\\ phase = "failed" /\\ ~keys',
            ),
            claim(
                "PostAuthDegenerateInstallsNoKeys",
                "a degenerate shared secret after auth installs no keys and does not splice",
                'how = "degen" /\\ phase = "failed" /\\ ~keys',
            ),
            claim(
                "RekeyDegenerateDropsTheSession",
                "a degenerate rekey ephemeral fails closed at epoch 0",
                'how = "rekey_degen" /\\ epoch = 0 /\\ ~usable /\\ keys',
            ),
            claim(
                "MalformedRekeyDoesNotAdvanceEpoch",
                "a malformed rekey fails without leaving epoch 0",
                'phase = "failed" /\\ keys /\\ epoch = 0 /\\ ~usable',
            ),
            claim(
                "IdentityFailureAfterRekey",
                "a bad identity proof fails the rekeyed session without app data",
                'phase = "failed" /\\ epoch = 1 /\\ binding /\\ ~usable /\\ ~app',
            ),
            claim(
                "ReconnectIsFresh",
                "a later attempt starts idle, with epoch 0 and no keys",
                'phase = "idle" /\\ attempt = 2 /\\ ~keys',
            ),
        ),
        terminal='phase \\in {"rejected", "closed", "failed"} /\\ attempt = 2',
    )


def quic_machine() -> Machine:
    """QUIC TLS handshake order for one client and one server.

    The two sides advance independently. That over-approximates the wire: a
    client can finish while the server is still waiting. The invariants are
    local to each side, which is what the ``match`` arms guarantee. A PSK
    resumption skips Certificate and CertificateVerify. Any other message
    before completion alerts and does not set ``complete``. A non-ticket message
    after completion alerts and leaves ``complete`` set. The server sets
    ``handshake_complete`` and only then issues the session ticket.
    """

    fields = (
        "client",
        "server",
        "psk",
        "saw_cert",
        "saw_cv",
        "saw_fin",
        "saw_ch",
        "saw_sfin",
        "complete",
        "server_complete",
        "client_alert",
        "server_alert",
        "post_alert",
        "server_post_alert",
        "server_ticket",
        "nst",
        "stek",
    )
    defaults: dict[str, Scalar] = {
        "client": "sh",
        "server": "expect_ch",
        "psk": False,
        "saw_cert": False,
        "saw_cv": False,
        "saw_fin": False,
        "saw_ch": False,
        "saw_sfin": False,
        "complete": False,
        "server_complete": False,
        "client_alert": False,
        "server_alert": False,
        "post_alert": False,
        "server_post_alert": False,
        "server_ticket": False,
        "nst": False,
        "stek": True,
    }
    return Machine(
        name="ParallaXQuic",
        blurb="QUIC TLS client ReadState and server ServerState.",
        fields=fields,
        defaults=defaults,
        initials=(
            {"psk": False, "stek": True},
            {"psk": True, "stek": True},
            {"psk": False, "stek": False},
            {"psk": True, "stek": False},
        ),
        actions=(
            act(
                "ClientServerHello",
                'client = "sh" /\\ ~client_alert',
                client='"ee"',
            ),
            act(
                "ClientEncryptedExtensionsFull",
                'client = "ee" /\\ ~client_alert /\\ ~psk',
                client='"cert"',
            ),
            act(
                "ClientEncryptedExtensionsPsk",
                'client = "ee" /\\ ~client_alert /\\ psk',
                client='"fin"',
            ),
            act(
                "ClientCertificate",
                'client = "cert" /\\ ~client_alert /\\ ~psk',
                client='"cv"',
                saw_cert="TRUE",
            ),
            act(
                "ClientCompressedCertificate",
                'client = "cert" /\\ ~client_alert /\\ ~psk',
                client='"cv"',
                saw_cert="TRUE",
            ),
            act(
                "ClientCertificateVerify",
                'client = "cv" /\\ ~client_alert /\\ ~psk',
                client='"fin"',
                saw_cv="TRUE",
            ),
            act(
                "ClientFinished",
                'client = "fin" /\\ ~client_alert',
                client='"done"',
                complete="TRUE",
                saw_fin="TRUE",
            ),
            act(
                "ClientNewSessionTicket",
                'complete /\\ client = "done" /\\ ~client_alert /\\ ~post_alert /\\ ~nst',
                nst="TRUE",
            ),
            act(
                "ClientUnexpected",
                "~client_alert /\\ ~complete",
                client_alert="TRUE",
                client='"alert"',
            ),
            act(
                "ClientUnexpectedAfterComplete",
                "complete /\\ ~client_alert /\\ ~post_alert",
                post_alert="TRUE",
            ),
            act(
                "ServerClientHello",
                'server = "expect_ch" /\\ ~server_alert',
                server='"expect_fin"',
                saw_ch="TRUE",
            ),
            act(
                "ServerFinished",
                'server = "expect_fin" /\\ ~server_alert',
                server='"done"',
                server_complete="TRUE",
                saw_sfin="TRUE",
            ),
            act(
                "ServerUnexpected",
                "~server_alert /\\ ~server_complete",
                server_alert="TRUE",
                server='"alert"',
            ),
            act(
                "ServerIssueTicket",
                "server_complete /\\ stek /\\ ~server_alert /\\ ~server_post_alert /\\ ~server_ticket",
                server_ticket="TRUE",
            ),
            act(
                "ServerUnexpectedAfterComplete",
                "server_complete /\\ (~stek \\/ server_ticket) /\\ ~server_alert /\\ ~server_post_alert",
                server_post_alert="TRUE",
            ),
        ),
        invariants=(
            claim(
                "CompleteOnlyAfterFinished",
                "the client is complete only in the done state, after Finished, with no alert",
                'complete => (client = "done" /\\ saw_fin /\\ ~client_alert)',
            ),
            claim(
                "ServerCompleteOnlyAfterBothMessages",
                "the server completes only after ClientHello and Finished",
                'server_complete => (server = "done" /\\ saw_ch /\\ saw_sfin /\\ ~server_alert)',
            ),
            claim(
                "ResumptionSkipsCertificate",
                "a PSK resumption that completes did not pass through Certificate",
                "complete /\\ psk => (~saw_cert /\\ ~saw_cv)",
            ),
            claim(
                "FullHandshakeSeesCertificate",
                "a full handshake that completes saw Certificate and CertificateVerify",
                "complete /\\ ~psk => (saw_cert /\\ saw_cv /\\ saw_fin)",
            ),
            claim(
                "AlertBeforeCompleteIsNotSuccess",
                "an unexpected message before completion alerts and does not complete",
                'client = "alert" => (client_alert /\\ ~complete /\\ ~post_alert)',
            ),
            claim(
                "AlertAfterCompleteDoesNotUndo",
                "an unexpected message after completion alerts and leaves the handshake complete",
                "post_alert => (complete /\\ client = \"done\" /\\ saw_fin /\\ ~client_alert)",
            ),
            claim(
                "ServerAlertIsNotComplete",
                "an unexpected server message before completion alerts and does not complete",
                'server = "alert" => (server_alert /\\ ~server_complete /\\ ~server_post_alert)',
            ),
            claim(
                "ServerAlertAfterCompleteDoesNotUndo",
                "an unexpected server message after completion does not clear handshake_complete",
                "server_post_alert => (server_complete /\\ server = \"done\" /\\ saw_sfin /\\ ~server_alert)",
            ),
            claim(
                "VerifyFollowsCertificate",
                "CertificateVerify is only recorded after a Certificate",
                "saw_cv => saw_cert",
            ),
            claim(
                "PskNeverEntersCertificate",
                "a resumption never sits in the Certificate states",
                'psk => (~saw_cert /\\ ~saw_cv /\\ client # "cert" /\\ client # "cv")',
            ),
            claim(
                "TicketOnlyAfterComplete",
                "a NewSessionTicket is stored only after the handshake completes",
                'nst => (complete /\\ client = "done")',
            ),
            claim(
                "ServerTicketOnlyAfterComplete",
                "the server issues a session ticket only after handshake_complete is set",
                "server_ticket => (server_complete /\\ server = \"done\" /\\ saw_sfin)",
            ),
            claim(
                "ServerNoStekIssuesNoTicket",
                "a server with no STEK calls issue_session_ticket and queues nothing",
                "~stek => ~server_ticket",
            ),
            claim(
                "PostAlertFollowsTheTicketCall",
                "a post-completion alert is after issue_session_ticket, which queues a ticket only when a STEK exists",
                "server_post_alert => (~stek \\/ server_ticket)",
            ),
        ),
        witnesses=(
            claim(
                "FullHandshakeCompletes",
                "a non-PSK handshake can complete and store a ticket",
                "complete /\\ ~psk /\\ saw_cert /\\ saw_cv /\\ nst",
            ),
            claim(
                "ResumptionCompletesWithoutCertificate",
                "a PSK resumption can complete without a certificate",
                "complete /\\ psk /\\ ~saw_cert /\\ saw_fin /\\ nst",
            ),
            claim(
                "ServerHandshakeCompletes",
                "the server can complete after ClientHello and Finished",
                "server_complete /\\ saw_ch /\\ saw_sfin",
            ),
            claim(
                "UnexpectedClientMessageAlerts",
                "an unexpected client message alerts before completion",
                'client = "alert" /\\ ~complete',
            ),
            claim(
                "UnexpectedClientMessageAfterComplete",
                "an unexpected client message after completion leaves the handshake complete",
                "post_alert /\\ complete /\\ nst",
            ),
            claim(
                "UnexpectedServerMessageAlerts",
                "an unexpected server message alerts before completion",
                'server = "alert" /\\ ~server_complete',
            ),
            claim(
                "ServerTicketFollowsComplete",
                "handshake_complete is set before the session ticket is issued",
                "server_ticket /\\ server_complete /\\ stek",
            ),
            claim(
                "NoStekAlertsWithoutATicket",
                "a no-STEK server still alerts after completion and has queued no ticket",
                "~stek /\\ server_post_alert /\\ ~server_ticket /\\ server_complete",
            ),
        ),
        terminal=(
            "(client_alert \\/ (complete /\\ post_alert))"
            " /\\ (server_alert \\/ (server_complete /\\ server_post_alert /\\ (~stek \\/ server_ticket)))"
        ),
    )


def zero_rtt_machine() -> Machine:
    """One 0-RTT ticket identity, including a replay of that same ticket.

    ``guard = busy`` is a contended or poisoned lock. ``guard = out`` is the
    cache already checked out when this attempt starts. Both fail closed: the
    ticket is not burned and early data is not accepted. After a fresh accept,
    ``Checkout`` is the background persist taking the cache, and a second offer
    in that window is ``CheckoutReject`` (fail closed, not a replay lookup).
    ``Persist`` returns the cache and makes the accept durable. CacheFull and an
    8-byte nonce prefix collision are decisions under a free lock: the ticket is not
    accepted and not burned, which is not the lock-busy path. The insert is
    ``insert_new_outcome_deferred``; the fsync is later. A restart before that
    fsync drops the in-memory accept so the same ticket can be accepted again.
    ``AcceptsAtMostOnce`` is per boot while the journal is not yet durable, not
    once-ever across that crash. A bad binder returns before the guard. Retain
    and the next ticket wait until the probe is verified AND the Safari
    SETTINGS check passes. ``dead`` is a handshake timeout.
    """

    fields = (
        "guard",
        "binder",
        "offered",
        "decided",
        "early",
        "burned",
        "durable",
        "journal",
        "restarted",
        "reject",
        "hs",
        "probe",
        "settings",
        "relay",
        "retained",
        "stored",
        "accepts",
        "replay_offered",
        "replay_decided",
        "replay_rejected",
        "dead",
    )
    defaults: dict[str, Scalar] = {
        "guard": "free",
        "binder": "ok",
        "offered": False,
        "decided": False,
        "early": False,
        "burned": False,
        "durable": False,
        "journal": "idle",
        "restarted": False,
        "reject": "none",
        "hs": False,
        "probe": "none",
        "settings": "none",
        "relay": False,
        "retained": False,
        "stored": False,
        "accepts": 0,
        "replay_offered": False,
        "replay_decided": False,
        "replay_rejected": False,
        "dead": False,
    }
    initials = tuple(
        {"guard": guard, "binder": binder}
        for guard in ("free", "busy", "out")
        for binder in ("ok", "bad")
    )
    return Machine(
        name="ParallaXZeroRtt",
        blurb="0-RTT ticket single-use, fail-closed guard, and reconnect replay.",
        fields=fields,
        defaults=defaults,
        initials=initials,
        actions=(
            act("Offer", "~offered /\\ ~dead", offered="TRUE"),
            act(
                "ProbeEarly",
                'offered /\\ probe = "none" /\\ ~hs /\\ ~dead',
                probe='"early"',
            ),
            act(
                "Accept",
                'offered /\\ ~decided /\\ binder = "ok" /\\ guard = "free" /\\ accepts = 0 /\\ ~burned /\\ ~dead',
                decided="TRUE",
                early="TRUE",
                burned="TRUE",
                durable="FALSE",
                accepts="accepts + 1",
            ),
            act(
                "CacheFull",
                'offered /\\ ~decided /\\ binder = "ok" /\\ guard = "free" /\\ accepts = 0 /\\ ~burned /\\ ~dead',
                decided="TRUE",
                early="FALSE",
                reject='"full"',
            ),
            act(
                "PrefixClash",
                'offered /\\ ~decided /\\ binder = "ok" /\\ guard = "free" /\\ accepts = 0 /\\ ~burned /\\ ~dead',
                decided="TRUE",
                early="FALSE",
                reject='"clash"',
            ),
            act(
                "Checkout",
                'burned /\\ accepts = 1 /\\ ~durable /\\ journal = "idle"',
                journal='"out"',
            ),
            act(
                "Persist",
                'burned /\\ accepts = 1 /\\ ~durable /\\ journal = "out"',
                durable="TRUE",
                journal='"back"',
            ),
            act(
                "Restart",
                "burned /\\ ~durable /\\ ~dead /\\ ~replay_offered",
                decided="FALSE",
                early="FALSE",
                burned="FALSE",
                accepts="0",
                journal='"idle"',
                restarted="TRUE",
            ),
            act(
                "FailClosed",
                'offered /\\ ~decided /\\ binder = "ok" /\\ guard # "free" /\\ accepts = 0 /\\ ~dead',
                decided="TRUE",
                early="FALSE",
            ),
            act(
                "BadBinder",
                'offered /\\ ~decided /\\ binder = "bad" /\\ ~dead',
                decided="TRUE",
                early="FALSE",
            ),
            act(
                "Handshake",
                'decided /\\ probe = "early" /\\ ~hs /\\ ~dead',
                hs="TRUE",
            ),
            act(
                "HsTimeout",
                "offered /\\ decided /\\ ~hs /\\ ~dead",
                dead="TRUE",
            ),
            act(
                "ProbeFailed",
                'hs /\\ probe = "early" /\\ ~dead',
                probe='"failed"',
            ),
            act(
                "ProbeVerified",
                'hs /\\ probe = "early" /\\ ~dead',
                probe='"verified"',
            ),
            act(
                "SettingsOk",
                'probe = "verified" /\\ settings = "none" /\\ ~dead',
                settings='"ok"',
            ),
            act(
                "SettingsFail",
                'probe = "verified" /\\ settings = "none" /\\ ~retained /\\ ~stored /\\ ~dead',
                probe='"settings_fail"',
                settings='"bad"',
            ),
            act(
                "Relay",
                'hs /\\ probe = "verified" /\\ settings = "ok" /\\ ~relay /\\ ~dead',
                relay="TRUE",
            ),
            act(
                "Retain",
                'probe = "verified" /\\ settings = "ok" /\\ ~retained /\\ ~dead',
                retained="TRUE",
            ),
            act(
                "StoreTicket",
                'probe = "verified" /\\ settings = "ok" /\\ ~stored /\\ ~dead',
                stored="TRUE",
            ),
            act(
                "ReplayOffer",
                'burned /\\ accepts = 1 /\\ ~replay_offered /\\ (journal = "out" \\/ hs \\/ dead)',
                replay_offered="TRUE",
            ),
            act(
                "ReplayReject",
                'replay_offered /\\ ~replay_decided /\\ journal # "out"',
                replay_decided="TRUE",
                replay_rejected="TRUE",
            ),
            act(
                "CheckoutReject",
                'replay_offered /\\ ~replay_decided /\\ journal = "out"',
                replay_decided="TRUE",
                replay_rejected="TRUE",
            ),
        ),
        invariants=(
            claim(
                "EarlyDataRequiresFreshAccept",
                "early data is accepted only once, after a good binder, with the guard free",
                'early => (offered /\\ decided /\\ burned /\\ accepts = 1 /\\ binder = "ok" /\\ guard = "free")',
            ),
            claim(
                "FailClosedDoesNotBurnOrAccept",
                "a busy or checked-out replay guard accepts nothing and does not burn the ticket",
                'guard # "free" => (~early /\\ ~burned /\\ accepts = 0)',
            ),
            claim(
                "BadBinderDoesNotBurnOrAccept",
                "a bad binder is rejected before the guard and does not burn the ticket",
                'binder = "bad" => (~early /\\ ~burned /\\ accepts = 0)',
            ),
            claim(
                "AcceptsAtMostOnce",
                "one boot accepts the ticket at most once; a crash before the deferred fsync is not this count",
                "accepts \\in {0, 1}",
            ),
            claim(
                "DurableAcceptStaysBurned",
                "once the journal fsync has landed, that accept is still burned and the cache is back",
                'durable => (burned /\\ early /\\ accepts = 1 /\\ journal = "back")',
            ),
            claim(
                "CheckoutIsUndurableAccept",
                "the cache is checked out only after a fresh accept and before the deferred fsync",
                'journal = "out" => (burned /\\ early /\\ accepts = 1 /\\ ~durable /\\ guard = "free")',
            ),
            claim(
                "CheckoutRejectsTheConcurrentOffer",
                "a second offer while the cache is checked out is rejected and does not accept again",
                'journal = "out" /\\ replay_decided => (replay_rejected /\\ accepts = 1 /\\ burned /\\ ~durable)',
            ),
            claim(
                "RestartUndoesUndurableAccept",
                "a restart before fsync clears the in-memory accept and the checkout",
                'restarted /\\ accepts = 0 => (~burned /\\ ~early /\\ ~durable /\\ journal = "idle")',
            ),
            claim(
                "FullOrClashDoesNotBurn",
                "CacheFull and an 8-byte nonce-prefix collision decide the ticket without burning it",
                'reject \\in {"full", "clash"} => (decided /\\ ~burned /\\ ~early /\\ accepts = 0 /\\ guard = "free" /\\ binder = "ok")',
            ),
            claim(
                "RelayWaitsForHandshake",
                "relay bytes are sent only after the handshake, a verified probe, and Safari SETTINGS",
                'relay => (hs /\\ ~dead /\\ probe = "verified" /\\ settings = "ok")',
            ),
            claim(
                "RetainOnlyVerified",
                "the QUIC leg is retained only after a verified probe, Safari SETTINGS, and the handshake",
                'retained => (probe = "verified" /\\ settings = "ok" /\\ hs /\\ ~dead)',
            ),
            claim(
                "StoreTicketOnlyVerified",
                "the next resumption ticket is stored only after a verified probe and Safari SETTINGS",
                'stored => (probe = "verified" /\\ settings = "ok" /\\ hs /\\ ~dead)',
            ),
            claim(
                "SettingsFailDoesNotStore",
                "a verified probe that fails the Safari SETTINGS check does not retain or store a ticket",
                'settings = "bad" => (~stored /\\ ~retained /\\ probe = "settings_fail")',
            ),
            claim(
                "VerifiedProbeImpliesHandshake",
                "a verified probe implies the handshake completed",
                'probe = "verified" => (hs /\\ ~dead)',
            ),
            claim(
                "ReplayDoesNotAcceptAgain",
                "a second offer of an accepted ticket is rejected and does not increment accepts",
                "replay_rejected => (replay_decided /\\ accepts = 1 /\\ burned)",
            ),
            claim(
                "DeadDropsTheAttempt",
                "a handshake timeout installs no relay, retain, or stored ticket",
                "dead => (~hs /\\ ~relay /\\ ~retained /\\ ~stored)",
            ),
            claim(
                "DecidedImpliesOffered",
                "the server decides a ticket only after the client has consumed it",
                "decided => offered",
            ),
            claim(
                "HandshakeFollowsEarlyProbe",
                "on this 0-RTT path the handshake follows an early probe",
                'hs => (probe = "early" \\/ probe = "verified" \\/ probe = "failed" \\/ probe = "settings_fail")',
            ),
        ),
        witnesses=(
            claim(
                "FreshTicketAccepted",
                "a good ticket with a free guard is accepted once",
                'early /\\ accepts = 1 /\\ guard = "free" /\\ binder = "ok"',
            ),
            claim(
                "BusyGuardFailsClosed",
                "a contended guard fails closed without burning the ticket",
                'decided /\\ ~early /\\ ~burned /\\ guard = "busy"',
            ),
            claim(
                "CheckedOutGuardFailsClosed",
                "a checked-out cache fails closed without burning the ticket",
                'decided /\\ ~early /\\ ~burned /\\ guard = "out"',
            ),
            claim(
                "ConcurrentOfferWhileCheckedOut",
                "a second offer during the deferred fsync is rejected without a second accept",
                'journal = "out" /\\ replay_rejected /\\ accepts = 1 /\\ ~durable /\\ early',
            ),
            claim(
                "BadBinderRejected",
                "a bad binder is rejected without burning the ticket",
                'decided /\\ ~early /\\ binder = "bad" /\\ ~burned',
            ),
            claim(
                "ReplayRejected",
                "reoffering an accepted ticket is rejected",
                "replay_rejected /\\ accepts = 1",
            ),
            claim(
                "RelayAfterFailClosed",
                "fail-closed 0-RTT can still relay after the 1-RTT handshake",
                'relay /\\ hs /\\ ~early /\\ guard = "busy"',
            ),
            claim(
                "VerifiedProbeRetains",
                "a verified probe that passes SETTINGS can retain QUIC and store the next ticket",
                'retained /\\ stored /\\ probe = "verified" /\\ settings = "ok"',
            ),
            claim(
                "SettingsFailDropsStore",
                "a verified probe that fails SETTINGS does not store or retain",
                'probe = "settings_fail" /\\ settings = "bad" /\\ ~stored /\\ ~retained',
            ),
            claim(
                "RestartAcceptsAgain",
                "a crash before fsync can accept the same ticket on the next boot",
                "restarted /\\ early /\\ accepts = 1 /\\ ~durable",
            ),
            claim(
                "CacheFullDoesNotBurn",
                "a full cache decides the ticket and does not burn it",
                'reject = "full" /\\ decided /\\ ~burned /\\ guard = "free"',
            ),
            claim(
                "PrefixClashDoesNotBurn",
                "an 8-byte nonce prefix collision decides the ticket and does not burn it",
                'reject = "clash" /\\ decided /\\ ~burned /\\ guard = "free"',
            ),
            claim(
                "TimeoutDropsAttempt",
                "a handshake timeout does not retain QUIC",
                "dead /\\ ~retained /\\ ~hs",
            ),
        ),
        terminal=(
            "(dead /\\ ~relay /\\ ~retained /\\ ~stored /\\ ~hs /\\ (~burned \\/ replay_decided))"
            " \\/ (~dead /\\ hs /\\ (accepts = 0 \\/ replay_decided) /\\ ("
            '(probe = "verified" /\\ settings = "ok" /\\ relay /\\ retained /\\ stored)'
            ' \\/ (probe = "failed" /\\ ~relay /\\ ~retained /\\ ~stored)'
            ' \\/ (probe = "settings_fail" /\\ settings = "bad" /\\ ~relay /\\ ~retained /\\ ~stored)))'
        ),
    )


def replay_machine() -> Machine:
    """In-memory ``stage_insert`` for a cache of capacity 0 or 1.

    Capacity 0 is replay protection off: the insert is reported and nothing is
    stored. Capacity 1 holds one handshake, ``a/ta``. ``prune_expired`` deletes
    expired entries and rebuilds the nonce and transcript sets, so expiry
    clears the slot. The candidate's timestamp class is armed before the
    decision, so a past-window or future-skewed timestamp cannot take the
    Replay action, and a transcript clash cannot be labeled CacheFull. The
    window edge and a future skew of +5 are still fresh. +6 seconds is stale.
    ``stored`` means this attempt wrote the slot. The journal MAC is not here.
    """

    fields = (
        "prot",
        "slot_n",
        "slot_t",
        "scene",
        "last",
        "cand_n",
        "stored",
        "kind",
        "pruned",
        "n",
    )
    defaults: dict[str, Scalar] = {
        "prot": "on",
        "slot_n": "none",
        "slot_t": "none",
        "scene": "none",
        "last": "none",
        "cand_n": "none",
        "stored": False,
        "kind": "none",
        "pruned": False,
        "n": 0,
    }
    return Machine(
        name="ParallaXReplay",
        blurb=(
            "ReplayInsertOutcome for protection-off and one slot: expiry clears "
            "the slot; stale and future skew cannot be replay; clash is not CacheFull."
        ),
        fields=fields,
        defaults=defaults,
        initials=({"prot": "off"}, {"prot": "on"}),
        actions=(
            act(
                "OffInsert",
                'prot = "off" /\\ n < 2',
                last='"inserted"',
                cand_n='"a"',
                stored="FALSE",
                kind='"off"',
                n="n + 1",
            ),
            act(
                "Insert",
                'prot = "on" /\\ n = 0 /\\ slot_n = "none" /\\ scene = "none"',
                slot_n='"a"',
                slot_t='"ta"',
                last='"inserted"',
                cand_n='"a"',
                stored="TRUE",
                kind='"insert"',
                n="1",
            ),
            act(
                "InsertEdge",
                'prot = "on" /\\ n = 0 /\\ slot_n = "none" /\\ scene = "none"',
                slot_n='"a"',
                slot_t='"ta"',
                last='"inserted"',
                cand_n='"a"',
                stored="TRUE",
                kind='"insert"',
                scene='"edge_done"',
                n="2",
            ),
            act(
                "InsertSkew",
                'prot = "on" /\\ n = 0 /\\ slot_n = "none" /\\ scene = "none"',
                slot_n='"a"',
                slot_t='"ta"',
                last='"inserted"',
                cand_n='"a"',
                stored="TRUE",
                kind='"insert"',
                scene='"skew_done"',
                n="2",
            ),
            act(
                "StalePastEmpty",
                'prot = "on" /\\ n = 0 /\\ slot_n = "none" /\\ scene = "none"',
                last='"stale"',
                cand_n='"a"',
                stored="FALSE",
                kind='"stale"',
                scene='"past"',
                n="2",
            ),
            act(
                "StaleFutureEmpty",
                'prot = "on" /\\ n = 0 /\\ slot_n = "none" /\\ scene = "none"',
                last='"stale"',
                cand_n='"a"',
                stored="FALSE",
                kind='"stale"',
                scene='"future"',
                n="2",
            ),
            act("ArmPast", 'n = 1 /\\ scene = "none" /\\ slot_n = "a"', scene='"past"'),
            act("ArmFuture", 'n = 1 /\\ scene = "none" /\\ slot_n = "a"', scene='"future"'),
            act("ArmEdge", 'n = 1 /\\ scene = "none" /\\ slot_n = "a"', scene='"edge"'),
            act("ArmSkew", 'n = 1 /\\ scene = "none" /\\ slot_n = "a"', scene='"skew"'),
            act("ArmNonce", 'n = 1 /\\ scene = "none" /\\ slot_n = "a"', scene='"nonce"'),
            act(
                "ArmTranscript",
                'n = 1 /\\ scene = "none" /\\ slot_n = "a"',
                scene='"transcript"',
            ),
            act(
                "ArmDistinct",
                'n = 1 /\\ scene = "none" /\\ slot_n = "a"',
                scene='"distinct"',
            ),
            act("ArmExpire", 'n = 1 /\\ scene = "none" /\\ slot_n = "a"', scene='"expire"'),
            act(
                "StalePast",
                'scene = "past" /\\ n = 1',
                last='"stale"',
                cand_n='"a"',
                stored="FALSE",
                kind='"stale"',
                n="2",
            ),
            act(
                "StaleFuture",
                'scene = "future" /\\ n = 1',
                last='"stale"',
                cand_n='"a"',
                stored="FALSE",
                kind='"stale"',
                n="2",
            ),
            act(
                "ReplayNonce",
                'scene = "nonce" /\\ n = 1',
                last='"replayed"',
                cand_n='"a"',
                stored="FALSE",
                kind='"replay"',
                n="2",
            ),
            act(
                "ReplayEdge",
                'scene = "edge" /\\ n = 1',
                last='"replayed"',
                cand_n='"a"',
                stored="FALSE",
                kind='"replay"',
                n="2",
            ),
            act(
                "ReplaySkew",
                'scene = "skew" /\\ n = 1',
                last='"replayed"',
                cand_n='"a"',
                stored="FALSE",
                kind='"replay"',
                n="2",
            ),
            act(
                "Clash",
                'scene = "transcript" /\\ n = 1',
                last='"replayed"',
                cand_n='"b"',
                stored="FALSE",
                kind='"replay"',
                n="2",
            ),
            act(
                "Full",
                'scene = "distinct" /\\ n = 1',
                last='"full"',
                cand_n='"b"',
                stored="FALSE",
                kind='"full"',
                n="2",
            ),
            act(
                "Expire",
                'scene = "expire" /\\ n = 1',
                slot_n='"none"',
                slot_t='"none"',
                last='"none"',
                cand_n='"none"',
                stored="FALSE",
                kind='"expire"',
                pruned="TRUE",
                scene='"expired"',
            ),
            act(
                "Reinsert",
                'scene = "expired" /\\ slot_n = "none" /\\ n = 1',
                slot_n='"b"',
                slot_t='"tb"',
                last='"inserted"',
                cand_n='"b"',
                stored="TRUE",
                kind='"insert"',
                scene='"done"',
                n="2",
            ),
        ),
        invariants=(
            claim(
                "OffStoresNothing",
                "protection off reports an insert and never occupies the slot",
                'prot = "off" => (slot_n = "none" /\\ slot_t = "none" /\\ ~stored /\\ ~pruned)',
            ),
            claim(
                "SlotIsPaired",
                "a stored handshake is one of the two abstract identities, or the slot is empty",
                '(slot_n = "none" /\\ slot_t = "none") \\/ (slot_n = "a" /\\ slot_t = "ta") \\/ (slot_n = "b" /\\ slot_t = "tb")',
            ),
            claim(
                "InsertRecordsTheCandidate",
                "an insert writes the candidate into the slot",
                'kind = "insert" => (last = "inserted" /\\ stored /\\ cand_n = slot_n /\\ slot_n # "none")',
            ),
            claim(
                "StaleIsNotAReplay",
                "a stale candidate is Stale, including when its nonce is already stored",
                'kind = "stale" => (last = "stale" /\\ ~stored)',
            ),
            claim(
                "StaleCannotTakeReplay",
                "a past-window or future-skewed timestamp is not classified as Replayed",
                'scene \\in {"past", "future"} => kind # "replay"',
            ),
            claim(
                "PastAndFutureAreStale",
                "once decided, a past-window or +6s timestamp is Stale",
                'scene \\in {"past", "future"} /\\ n = 2 => (kind = "stale" /\\ last = "stale")',
            ),
            claim(
                "EdgeAndSkewAreFresh",
                "the window edge and a future skew of +5 are fresh, so a stored nonce is Replayed",
                'scene \\in {"edge", "skew"} /\\ n = 2 => (kind = "replay" /\\ last = "replayed")',
            ),
            claim(
                "ReplayDoesNotRecord",
                "a replay reports Replayed, does not write, and only hits an occupied slot",
                'kind = "replay" => (last = "replayed" /\\ ~stored /\\ slot_n # "none")',
            ),
            claim(
                "ClashIsNotFull",
                "a transcript clash is Replayed, not CacheFull",
                'scene = "transcript" => kind # "full"',
            ),
            claim(
                "FullDoesNotEvict",
                "CacheFull leaves the occupant in place and does not store the distinct candidate",
                'kind = "full" => (last = "full" /\\ ~stored /\\ slot_n = "a" /\\ cand_n = "b")',
            ),
            claim(
                "ProtectionOffIsInsert",
                "with protection off the only decision is Inserted",
                'prot = "off" /\\ kind # "none" => (kind = "off" /\\ last = "inserted")',
            ),
            claim(
                "ExpireClearsTheSlot",
                "pruning an expired entry deletes it and rebuilds an empty slot",
                'kind = "expire" => (slot_n = "none" /\\ slot_t = "none" /\\ ~stored /\\ pruned)',
            ),
        ),
        witnesses=(
            claim(
                "ProtectionOffInserts",
                "protection off can insert without storing",
                'prot = "off" /\\ kind = "off" /\\ last = "inserted" /\\ slot_n = "none"',
            ),
            claim(
                "FreshInsert",
                "an empty cache can record handshake a",
                'kind = "insert" /\\ slot_n = "a" /\\ stored /\\ ~pruned',
            ),
            claim(
                "SameNonceReplay",
                "a second fresh use of a stored nonce is Replayed",
                'kind = "replay" /\\ scene = "nonce" /\\ cand_n = "a" /\\ slot_n = "a"',
            ),
            claim(
                "TranscriptClash",
                "a new nonce with a stored transcript is Replayed and the new nonce is not kept",
                'kind = "replay" /\\ scene = "transcript" /\\ cand_n = "b" /\\ slot_n = "a" /\\ ~stored',
            ),
            claim(
                "CacheFullKeepsPrior",
                "a full slot keeps the old handshake when a distinct one arrives",
                'kind = "full" /\\ scene = "distinct" /\\ cand_n = "b" /\\ slot_n = "a"',
            ),
            claim(
                "StaleBeatsSeenNonce",
                "a stale timestamp is Stale even though the nonce is already in the cache",
                'kind = "stale" /\\ scene = "past" /\\ slot_n = "a" /\\ ~stored',
            ),
            claim(
                "FutureSkewIsStale",
                "a timestamp more than 5 seconds ahead is Stale, not Replayed",
                'kind = "stale" /\\ scene = "future" /\\ slot_n = "a"',
            ),
            claim(
                "WindowEdgeInserts",
                "a timestamp exactly one window old is still fresh and can be inserted",
                'scene = "edge_done" /\\ kind = "insert" /\\ stored',
            ),
            claim(
                "SkewEdgeReplays",
                "a timestamp exactly 5 seconds ahead is fresh, so a stored nonce is Replayed",
                'scene = "skew" /\\ kind = "replay"',
            ),
            claim(
                "ReinsertAfterExpiry",
                "after the occupant is deleted, a later fresh handshake can take the slot",
                'pruned /\\ kind = "insert" /\\ slot_n = "b" /\\ scene = "done"',
            ),
        ),
        terminal="n = 2",
    )


def probe_machine() -> Machine:
    """Client probe classification and the server's PX1P retention gate.

    The client maps a Happy-Eyeballs timeout or a lost connection to
    Unreachable, and a setup failure, a short reply, a bad magic, a bad MAC,
    or a long body to Failed. Only the ``&&`` chain in ``classify_probe_reply``
    is Verified. The wire status is 0, 1, or 2; there is no error outcome.
    The server does not check its own probe result. It retains QUIC only for
    an AEAD-opened PX1P ack whose offer_id matches, whose status byte is
    Verified, and while it still holds the connection. A mismatched offer_id
    or a decode failure stays on TCP even if that connection is held. A PX1P
    read timeout or EOF aborts; it does not stay on TCP.
    """

    fields = ("obs", "have", "outcome", "status", "offer", "read", "decision")
    defaults: dict[str, Scalar] = {
        "obs": "timeout",
        "have": False,
        "outcome": "pending",
        "status": "none",
        "offer": "pending",
        "read": "pending",
        "decision": "pending",
    }
    observations = (
        "timeout",
        "lost",
        "setup",
        "short",
        "bad_magic",
        "bad_mac",
        "long",
        "ok",
    )
    initials = tuple(
        {"obs": obs, "have": have}
        for obs in observations
        for have in (False, True)
    )
    return Machine(
        name="ParallaXProbe",
        blurb=(
            "Client probe status (Verified, Unreachable, Failed) and the server "
            "PX1P gate: matching offer, held conn, or abort."
        ),
        fields=fields,
        defaults=defaults,
        initials=initials,
        actions=(
            act(
                "ToUnreachableTimeout",
                'obs = "timeout" /\\ outcome = "pending"',
                outcome='"unreachable"',
            ),
            act(
                "ToUnreachableLost",
                'obs = "lost" /\\ outcome = "pending"',
                outcome='"unreachable"',
            ),
            act(
                "ToFailSetup",
                'obs = "setup" /\\ outcome = "pending"',
                outcome='"failed"',
            ),
            act(
                "ToFailShort",
                'obs = "short" /\\ outcome = "pending"',
                outcome='"failed"',
            ),
            act(
                "ToFailMagic",
                'obs = "bad_magic" /\\ outcome = "pending"',
                outcome='"failed"',
            ),
            act(
                "ToFailMac",
                'obs = "bad_mac" /\\ outcome = "pending"',
                outcome='"failed"',
            ),
            act(
                "ToFailLong",
                'obs = "long" /\\ outcome = "pending"',
                outcome='"failed"',
            ),
            act(
                "ToVerified",
                'obs = "ok" /\\ outcome = "pending"',
                outcome='"verified"',
            ),
            act(
                "StatUnreachable",
                'outcome = "unreachable" /\\ status = "none"',
                status='"unreachable"',
            ),
            act(
                "StatFailed",
                'outcome = "failed" /\\ status = "none"',
                status='"failed"',
            ),
            act(
                "StatVerified",
                'outcome = "verified" /\\ status = "none"',
                status='"verified"',
            ),
            act(
                "Px1pTimeout",
                'decision = "pending" /\\ read = "pending"',
                read='"timeout"',
                decision='"abort"',
            ),
            act(
                "Px1pEof",
                'decision = "pending" /\\ read = "pending"',
                read='"eof"',
                decision='"abort"',
            ),
            act(
                "DecodeFail",
                'decision = "pending" /\\ read = "pending"',
                read='"decode"',
                decision='"stay"',
            ),
            act(
                "RejectAck",
                'status \\in {"verified", "unreachable", "failed"} /\\ decision = "pending" /\\ read = "pending"',
                offer='"mismatch"',
                read='"ok"',
                decision='"stay"',
            ),
            act(
                "Retain",
                'status = "verified" /\\ have /\\ decision = "pending" /\\ read = "pending"',
                offer='"match"',
                read='"ok"',
                decision='"retain"',
            ),
            act(
                "HardFail",
                'status = "verified" /\\ ~have /\\ decision = "pending" /\\ read = "pending"',
                offer='"match"',
                read='"ok"',
                decision='"hard_fail"',
            ),
            act(
                "StayUnreachable",
                'status = "unreachable" /\\ decision = "pending" /\\ read = "pending"',
                offer='"match"',
                read='"ok"',
                decision='"stay"',
            ),
            act(
                "StayFailed",
                'status = "failed" /\\ decision = "pending" /\\ read = "pending"',
                offer='"match"',
                read='"ok"',
                decision='"stay"',
            ),
        ),
        invariants=(
            claim(
                "VerifiedOnlyIfAuthentic",
                "the client classifier reports Verified only for a reply that passed the magic, length, and MAC chain",
                'outcome = "verified" => obs = "ok"',
            ),
            claim(
                "BadMacIsFailed",
                "a reply with a bad exporter MAC is Failed, not Verified and not Unreachable",
                'obs = "bad_mac" /\\ outcome # "pending" => outcome = "failed"',
            ),
            claim(
                "TimeoutIsUnreachable",
                "a Happy-Eyeballs timeout is Unreachable",
                'obs = "timeout" /\\ outcome # "pending" => outcome = "unreachable"',
            ),
            claim(
                "LostConnectionIsUnreachable",
                "a lost connection is Unreachable, not a failed authentication",
                'obs = "lost" /\\ outcome # "pending" => outcome = "unreachable"',
            ),
            claim(
                "ShortReplyIsFailed",
                "a short or truncated reply is Failed",
                'obs = "short" /\\ outcome # "pending" => outcome = "failed"',
            ),
            claim(
                "LongBodyIsFailed",
                "a body that fails the length conjunct is Failed",
                'obs = "long" /\\ outcome # "pending" => outcome = "failed"',
            ),
            claim(
                "SetupIsFailed",
                "a bind or setup failure is Failed, the status the client returns for that path",
                'obs = "setup" /\\ outcome # "pending" => outcome = "failed"',
            ),
            claim(
                "RetainOnlyMatchingAck",
                "QUIC is retained only for an AEAD-opened PX1P ack with a matching offer_id, status Verified, and the conn still held",
                'decision = "retain" => (status = "verified" /\\ offer = "match" /\\ have /\\ read = "ok")',
            ),
            claim(
                "VerifiedWithoutConnHardFails",
                "a matching Verified ack with no probed connection is a hard failure, not a silent TCP fallback",
                'decision = "hard_fail" => (status = "verified" /\\ offer = "match" /\\ read = "ok" /\\ ~have)',
            ),
            claim(
                "MismatchStaysOnTcp",
                "any decoded PX1P status whose offer_id does not match stays on TCP even if the conn is held",
                'offer = "mismatch" => (decision = "stay" /\\ read = "ok")',
            ),
            claim(
                "VerifiedStayIsARejectedAck",
                "staying on TCP after a Verified status is a mismatched offer_id or a decode failure",
                'decision = "stay" /\\ status = "verified" => (offer = "mismatch" \\/ read = "decode")',
            ),
            claim(
                "Px1pTimeoutAborts",
                "a PX1P read timeout aborts and does not stay on TCP",
                'read = "timeout" => decision = "abort"',
            ),
            claim(
                "Px1pEofAborts",
                "a PX1P read EOF aborts and does not stay on TCP",
                'read = "eof" => decision = "abort"',
            ),
        ),
        witnesses=(
            claim(
                "VerifiedRetains",
                "a matching Verified PX1P ack with the connection still held retains QUIC",
                'decision = "retain" /\\ status = "verified" /\\ offer = "match" /\\ have',
            ),
            claim(
                "VerifiedWithoutConnFailsHard",
                "a matching Verified ack whose connection is gone hard-fails",
                'decision = "hard_fail" /\\ status = "verified" /\\ ~have',
            ),
            claim(
                "MismatchDoesNotRetain",
                "a Verified ack with the wrong offer_id stays on TCP while the conn is held",
                'decision = "stay" /\\ status = "verified" /\\ offer = "mismatch" /\\ have',
            ),
            claim(
                "BadMacStaysOnTcp",
                "a bad MAC stays on TCP",
                'decision = "stay" /\\ obs = "bad_mac" /\\ outcome = "failed"',
            ),
            claim(
                "TimeoutStaysOnTcp",
                "a client probe timeout reported as Unreachable stays on TCP",
                'decision = "stay" /\\ obs = "timeout" /\\ outcome = "unreachable"',
            ),
            claim(
                "Px1pReadTimeoutAborts",
                "the server's PX1P read timeout aborts instead of staying on TCP",
                'decision = "abort" /\\ read = "timeout"',
            ),
            claim(
                "LostStaysOnTcp",
                "a lost connection stays on TCP and is Unreachable",
                'decision = "stay" /\\ obs = "lost"',
            ),
            claim(
                "SetupFailsClosed",
                "a setup failure is Failed and does not look verified",
                'decision = "stay" /\\ obs = "setup" /\\ outcome = "failed"',
            ),
            claim(
                "LongBodyFails",
                "a long probe body is Failed",
                'outcome = "failed" /\\ obs = "long"',
            ),
        ),
        terminal='decision # "pending"',
    )


def inbound_machine() -> Machine:
    """Server inbound decision after the first client record.

    The gates are ordered: a record that does not parse or does not carry
    timestamp and nonce is an auth failure; missing SNI is reported only after
    that material authenticated; an unauthorized name is reported only when a
    name is present. ``Replay`` is not a result of this decision. The constant-
    time DH ballast is not a state: this machine is the branch that is taken,
    not how long it takes.
    """

    fields = ("record_ok", "material", "has_sni", "sni_ok", "gate")
    defaults: dict[str, Scalar] = {
        "record_ok": False,
        "material": False,
        "has_sni": False,
        "sni_ok": False,
        "gate": "start",
    }
    initials = tuple(
        {
            "record_ok": record_ok,
            "material": material,
            "has_sni": has_sni,
            "sni_ok": sni_ok,
        }
        for record_ok in (False, True)
        for material in (False, True)
        for has_sni in (False, True)
        for sni_ok in (False, True)
    )
    return Machine(
        name="ParallaXInbound",
        blurb="Inbound auth, then SNI presence, then SNI authorization.",
        fields=fields,
        defaults=defaults,
        initials=initials,
        actions=(
            act(
                "FailClosed",
                'gate = "start" /\\ ~record_ok',
                gate='"auth_fail"',
            ),
            act(
                "FailMaterial",
                'gate = "start" /\\ record_ok /\\ ~material',
                gate='"auth_fail"',
            ),
            act(
                "FailMissingSni",
                'gate = "start" /\\ record_ok /\\ material /\\ ~has_sni',
                gate='"missing"',
            ),
            act(
                "FailUnauthorized",
                'gate = "start" /\\ record_ok /\\ material /\\ has_sni /\\ ~sni_ok',
                gate='"unauth"',
            ),
            act(
                "Accept",
                'gate = "start" /\\ record_ok /\\ material /\\ has_sni /\\ sni_ok',
                gate='"ok"',
            ),
        ),
        invariants=(
            claim(
                "MissingSniOnlyAfterAuth",
                "missing SNI is reported only after the record authenticated and carried its material",
                'gate = "missing" => (record_ok /\\ material /\\ ~has_sni)',
            ),
            claim(
                "UnauthorizedOnlyAfterSni",
                "an unauthorized name is reported only when auth succeeded and a name was present",
                'gate = "unauth" => (record_ok /\\ material /\\ has_sni /\\ ~sni_ok)',
            ),
            claim(
                "AuthenticatedClearsEveryGate",
                "the authenticated branch has a good record, material, and an authorized SNI",
                'gate = "ok" => (record_ok /\\ material /\\ has_sni /\\ sni_ok)',
            ),
            claim(
                "AuthFailIsNotASniDecision",
                "an auth failure is a bad record or missing material, not a SNI decision",
                'gate = "auth_fail" => (~record_ok \\/ ~material)',
            ),
        ),
        witnesses=(
            claim(
                "AuthenticatedHello",
                "a well-formed authorized hello is accepted",
                'gate = "ok" /\\ record_ok /\\ material /\\ sni_ok',
            ),
            claim(
                "MissingSniAfterAuth",
                "authenticated material with no SNI takes the missing-SNI branch",
                'gate = "missing" /\\ record_ok /\\ material',
            ),
            claim(
                "UnauthorizedSni",
                "a present but unauthorized name is rejected after auth",
                'gate = "unauth" /\\ has_sni /\\ ~sni_ok',
            ),
            claim(
                "UnparsedIsAuthFail",
                "a record that does not parse is an auth failure",
                'gate = "auth_fail" /\\ ~record_ok',
            ),
            claim(
                "MissingMaterialIsAuthFail",
                "authenticated framing without timestamp and nonce is still an auth failure",
                'gate = "auth_fail" /\\ record_ok /\\ ~material',
            ),
        ),
        terminal='gate # "start"',
    )


def keys_machine() -> Machine:
    """Order of QUIC key installation in ``write_handshake``.

    The client emits ClientHello, then 0-RTT keys only when a ticket was
    offered, then Handshake keys, then 1-RTT keys together with Finished.
    Accepting early data is a transition guarded by an offered ticket, not an
    input flag. The server emits 0-RTT open keys only after that accept, and
    it does that before ServerHello; Handshake keys come before 1-RTT keys.
    A server with a STEK emits the NewSessionTicket only after 1-RTT keys.
    A server with no STEK reaches 1-RTT and emits no ticket. The two sides
    advance independently, as in the read-state machine. Key bytes are not
    modeled.
    """

    fields = (
        "offer",
        "accept",
        "c",
        "s",
        "c_zrtt",
        "s_zrtt",
        "c_hs",
        "s_hs",
        "c_1rtt",
        "s_1rtt",
        "stek",
    )
    defaults: dict[str, Scalar] = {
        "offer": False,
        "accept": False,
        "c": "start",
        "s": "start",
        "c_zrtt": False,
        "s_zrtt": False,
        "c_hs": False,
        "s_hs": False,
        "c_1rtt": False,
        "s_1rtt": False,
        "stek": True,
    }
    return Machine(
        name="ParallaXKeys",
        blurb="Client and server write_handshake key-install order, including optional 0-RTT.",
        fields=fields,
        defaults=defaults,
        initials=(
            {},
            {"offer": True},
            {"stek": False},
            {"offer": True, "stek": False},
        ),
        actions=(
            act(
                "AcceptEarly",
                's = "start" /\\ offer /\\ ~accept /\\ c # "start"',
                accept="TRUE",
            ),
            act("EmitCh", 'c = "start"', c='"ch"'),
            act(
                "EmitCZrtt",
                'c = "ch" /\\ offer /\\ ~c_zrtt',
                c='"zrtt"',
                c_zrtt="TRUE",
            ),
            act(
                "EmitCHsNoZrtt",
                'c = "ch" /\\ ~offer',
                c='"hs"',
                c_hs="TRUE",
            ),
            act(
                "EmitCHsAfterZrtt",
                'c = "zrtt"',
                c='"hs"',
                c_hs="TRUE",
            ),
            act(
                "EmitCApp",
                'c = "hs"',
                c='"app"',
                c_1rtt="TRUE",
            ),
            act(
                "EmitSZrtt",
                's = "start" /\\ accept /\\ ~s_zrtt',
                s='"zrtt"',
                s_zrtt="TRUE",
            ),
            act(
                "EmitSShNoZrtt",
                's = "start" /\\ ~accept',
                s='"sh"',
            ),
            act(
                "EmitSShAfterZrtt",
                's = "zrtt"',
                s='"sh"',
            ),
            act(
                "EmitSHs",
                's = "sh"',
                s='"hs"',
                s_hs="TRUE",
            ),
            act(
                "EmitSApp",
                's = "hs"',
                s='"app"',
                s_1rtt="TRUE",
            ),
            act("EmitNst", 's = "app" /\\ stek', s='"nst"'),
        ),
        invariants=(
            claim(
                "ClientZeroRttOnlyIfOffered",
                "client 0-RTT keys exist only after an offered ticket, and the zrtt phase has installed them",
                '(c_zrtt => offer) /\\ (c = "zrtt" => c_zrtt)',
            ),
            claim(
                "ServerZeroRttOnlyIfAccepted",
                "server 0-RTT keys exist only after early data was accepted, and that phase has installed them",
                '(s_zrtt => accept) /\\ (s = "zrtt" => s_zrtt)',
            ),
            claim(
                "AcceptImpliesOffer",
                "the server does not accept early data the client did not offer",
                "accept => offer",
            ),
            claim(
                "ClientHandshakeKeysBeforeOneRtt",
                "client 1-RTT keys are installed only after Handshake keys, and only in the app phase",
                'c_1rtt => (c_hs /\\ c = "app")',
            ),
            claim(
                "ServerHandshakeKeysBeforeOneRtt",
                "server 1-RTT keys are installed only after Handshake keys",
                "s_1rtt => s_hs",
            ),
            claim(
                "OfferedZeroRttBeforeHandshakeKeys",
                "an offered ticket installs client 0-RTT keys before Handshake keys",
                '(c = "hs" \\/ c = "app") /\\ offer => c_zrtt',
            ),
            claim(
                "AcceptedZeroRttBeforeServerHello",
                "accepted early data installs server 0-RTT keys before ServerHello is emitted",
                '(s = "sh" \\/ s = "hs" \\/ s = "app" \\/ s = "nst") /\\ accept => s_zrtt',
            ),
            claim(
                "FullHandshakeSkipsZeroRtt",
                "a handshake that offered no ticket installs no 0-RTT keys on either side",
                "~offer => (~c_zrtt /\\ ~s_zrtt)",
            ),
            claim(
                "TicketOnlyAfterServerOneRtt",
                "the NewSessionTicket phase is after server 1-RTT keys",
                's = "nst" => (s_1rtt /\\ s_hs)',
            ),
            claim(
                "NoStekEmitsNoTicket",
                "a server with no STEK reaches 1-RTT and emits no NewSessionTicket",
                '~stek => s # "nst"',
            ),
            claim(
                "NoKeysBeforeClientHello",
                "the client installs nothing in the initial phase",
                'c = "start" => (~c_zrtt /\\ ~c_hs /\\ ~c_1rtt)',
            ),
        ),
        witnesses=(
            claim(
                "FullHandshakeInstallsOneRtt",
                "a full handshake reaches 1-RTT on both sides without 0-RTT keys",
                '~offer /\\ ~c_zrtt /\\ ~s_zrtt /\\ c = "app" /\\ s = "nst"',
            ),
            claim(
                "ResumptionInstallsZeroRtt",
                "an offered and accepted ticket installs 0-RTT keys before both sides reach 1-RTT",
                'offer /\\ accept /\\ c_zrtt /\\ s_zrtt /\\ c = "app" /\\ s = "nst"',
            ),
            claim(
                "RejectedEarlyDataStillReachesOneRtt",
                "a ticket the server did not accept still lets both sides install 1-RTT keys",
                'offer /\\ ~accept /\\ c_zrtt /\\ ~s_zrtt /\\ c_1rtt /\\ s_1rtt',
            ),
            claim(
                "NoStekReachesOneRtt",
                "a server with no STEK reaches 1-RTT without a NewSessionTicket",
                '~stek /\\ s = "app" /\\ s_1rtt /\\ c = "app" /\\ c_1rtt',
            ),
        ),
        terminal='c = "app" /\\ c_1rtt /\\ s_1rtt /\\ ((stek /\\ s = "nst") \\/ (~stek /\\ s = "app"))',
    )


def close_machine() -> Machine:
    """QUIC closing and draining, without timers or packet bytes.

    A local close may send one CONNECTION_CLOSE, including when the drain
    timer has already fired and the close packet was not yet written.
    A peer close and an idle timeout send none; the peer-close arm does not
    call ``close``. After close, the only transmit is that close packet:
    application data, STREAM, ACK, and probes are not sent.
    """

    fields = ("phase", "reason", "sent", "app", "after")
    defaults: dict[str, Scalar] = {
        "phase": "open",
        "reason": "none",
        "sent": False,
        "app": False,
        "after": "none",
    }
    return Machine(
        name="ParallaXClose",
        blurb="QUIC local, peer, and idle close: at most one close packet, then drain.",
        fields=fields,
        defaults=defaults,
        initials=(),
        actions=(
            act("SendApp", 'phase = "open" /\\ ~app', app="TRUE", after='"appdata"'),
            act("SendAck", 'phase = "open" /\\ after = "none"', after='"ack"'),
            act("SendStream", 'phase = "open" /\\ after = "none"', after='"stream"'),
            act("SendProbe", 'phase = "open" /\\ after = "none"', after='"probe"'),
            act(
                "LocalClose",
                'phase = "open"',
                phase='"closing"',
                reason='"local"',
                after='"none"',
            ),
            act(
                "PeerClose",
                'phase = "open"',
                phase='"closing"',
                reason='"peer"',
                after='"none"',
            ),
            act(
                "IdleClose",
                'phase = "open"',
                phase='"closing"',
                reason='"idle"',
                after='"none"',
            ),
            act(
                "SendClose",
                '(phase = "closing" \\/ phase = "drained") /\\ reason = "local" /\\ ~sent',
                sent="TRUE",
                after='"close"',
            ),
            act(
                "DrainAfterClose",
                'phase = "closing" /\\ reason = "local" /\\ sent',
                phase='"drained"',
            ),
            act(
                "DrainBeforeClose",
                'phase = "closing" /\\ reason = "local" /\\ ~sent',
                phase='"drained"',
            ),
            act(
                "DrainPeer",
                'phase = "closing" /\\ reason = "peer"',
                phase='"drained"',
            ),
            act(
                "DrainIdle",
                'phase = "closing" /\\ reason = "idle"',
                phase='"drained"',
            ),
        ),
        invariants=(
            claim(
                "OpenHasNoClose",
                "an open connection has no close reason and has not sent a close packet",
                'phase = "open" => (reason = "none" /\\ ~sent /\\ after # "close")',
            ),
            claim(
                "ClosePacketOnlyForLocal",
                "the single close packet is sent only for a local close",
                'sent => (reason = "local" /\\ after = "close")',
            ),
            claim(
                "PeerCloseIsSilent",
                "a peer CONNECTION_CLOSE does not send one back",
                'reason = "peer" => (~sent /\\ after = "none")',
            ),
            claim(
                "IdleCloseIsSilent",
                "an idle timeout does not send a CONNECTION_CLOSE",
                'reason = "idle" => (~sent /\\ after = "none")',
            ),
            claim(
                "TransmitAfterCloseIsTheClosePacket",
                "after close the only transmit is the local close packet; app, stream, ACK, and probe sends stay in the open phase",
                '(phase \\in {"closing", "drained"} => after \\in {"none", "close"}) /\\ (after \\in {"appdata", "ack", "stream", "probe"} => phase = "open")',
            ),
            claim(
                "DrainedHasAReason",
                "a drained connection was closed locally, by the peer, or by idle timeout",
                'phase = "drained" => reason \\in {"local", "peer", "idle"}',
            ),
        ),
        witnesses=(
            claim(
                "LocalSendsOneClose",
                "a local close can send application data first, then one close packet, then drain",
                'phase = "drained" /\\ reason = "local" /\\ sent /\\ app',
            ),
            claim(
                "PeerDrainsSilent",
                "a peer close drains without a close packet even if data was sent before",
                'phase = "drained" /\\ reason = "peer" /\\ ~sent /\\ app',
            ),
            claim(
                "IdleDrainsSilent",
                "an idle timeout drains without a close packet",
                'phase = "drained" /\\ reason = "idle" /\\ ~sent',
            ),
            claim(
                "DrainBeforeClosePacket",
                "the drain timer can win before the local close packet is written",
                'phase = "drained" /\\ reason = "local" /\\ ~sent',
            ),
            claim(
                "DrainedCanStillSendClose",
                "a drained local close that has not sent yet can still send the close packet",
                'phase = "drained" /\\ reason = "local" /\\ sent /\\ after = "close"',
            ),
        ),
        terminal='phase = "drained"',
    )


def bbr_machine() -> Machine:
    """BBRv1 mode graph. Bytes, rates, and clocks are events, not values.

    Three non-growth rounds leave Startup for ProbeBW at gain-cycle phase 2
    (cruise). A round whose sample is zero does not count: ``full_bw`` starts
    at 0, so ``btlbw >= full_bw * 1.25`` is true and the quiet count resets.
    ProbeBW advances the 8-phase cycle. ProbeRTT is not entered on the ack
    that fills the pipe; that ack seeds ``last_probe_rtt``. ProbeRTT returns
    to ProbeBW at phase 2, not to Startup. Loss sets a flag and does not
    change mode. There is no terminal state: the mode runs until the
    connection closes, which is a different machine. A state with no move is
    a stuck controller and fails the check.
    """

    fields = ("mode", "filled", "quiet", "phase", "loss", "undid", "probe_due")
    defaults: dict[str, Scalar] = {
        "mode": "startup",
        "filled": False,
        "quiet": 0,
        "phase": 0,
        "loss": False,
        "undid": False,
        "probe_due": False,
    }
    return Machine(
        name="ParallaXBbr",
        blurb="BBR Startup, ProbeBW, and ProbeRTT. Loss does not change the mode.",
        fields=fields,
        defaults=defaults,
        initials=(),
        actions=(
            act(
                "NoGrow",
                'mode = "startup" /\\ ~filled /\\ quiet < 2',
                quiet="quiet + 1",
                undid="FALSE",
            ),
            act(
                "SampleZero",
                'mode = "startup" /\\ ~filled /\\ (quiet # 0 \\/ ~undid)',
                quiet="0",
                undid="TRUE",
            ),
            act(
                "Grow",
                'mode = "startup" /\\ ~filled /\\ quiet # 0',
                quiet="0",
                undid="FALSE",
            ),
            act(
                "Fill",
                'mode = "startup" /\\ ~filled /\\ quiet = 2',
                mode='"probe_bw"',
                filled="TRUE",
                quiet="3",
                phase="2",
                undid="FALSE",
                probe_due="FALSE",
            ),
            act(
                "Advance",
                'mode = "probe_bw" /\\ phase < 7',
                phase="phase + 1",
            ),
            act(
                "AdvanceWrap",
                'mode = "probe_bw" /\\ phase = 7',
                phase="0",
            ),
            act(
                "ArmProbeRtt",
                'mode = "probe_bw" /\\ filled /\\ ~probe_due',
                probe_due="TRUE",
            ),
            act(
                "EnterProbeRtt",
                'mode = "probe_bw" /\\ filled /\\ probe_due',
                mode='"probe_rtt"',
            ),
            act(
                "ExitProbeRtt",
                'mode = "probe_rtt" /\\ filled',
                mode='"probe_bw"',
                phase="2",
                probe_due="FALSE",
            ),
            act("Loss", "~loss", loss="TRUE"),
        ),
        invariants=(
            claim(
                "StartupIsUnfilled",
                "Startup means the pipe is not full, the quiet count is below 3, and the gain phase is unused",
                'mode = "startup" => (~filled /\\ quiet < 3 /\\ phase = 0)',
            ),
            claim(
                "ProbeBwMeansFull",
                "ProbeBW is only entered once the pipe has filled, on the third quiet round",
                'mode = "probe_bw" => (filled /\\ quiet = 3)',
            ),
            claim(
                "ProbeRttMeansFull",
                "ProbeRTT is only entered from a full pipe, and not on the ack that filled it",
                'mode = "probe_rtt" => (filled /\\ quiet = 3 /\\ probe_due)',
            ),
            claim(
                "ZeroSampleDoesNotCount",
                "a zero bandwidth sample resets the quiet count and does not fill the pipe",
                "undid => (quiet = 0 /\\ mode = \"startup\" /\\ ~filled)",
            ),
            claim(
                "PhaseInCycle",
                "the ProbeBW gain index stays inside the 8-phase cycle",
                "phase \\in {0, 1, 2, 3, 4, 5, 6, 7}",
            ),
            claim(
                "QuietInBounds",
                "the Startup quiet count stays in 0..3",
                "quiet \\in {0, 1, 2, 3}",
            ),
        ),
        witnesses=(
            claim(
                "ReachesProbeBw",
                "three quiet rounds reach ProbeBW at the cruise phase",
                'mode = "probe_bw" /\\ filled /\\ phase = 2 /\\ quiet = 3',
            ),
            claim(
                "LossStaysInProbeBw",
                "a loss after the pipe fills leaves the mode in ProbeBW",
                'mode = "probe_bw" /\\ filled /\\ loss',
            ),
            claim(
                "EntersProbeRtt",
                "a full pipe can enter ProbeRTT after the fill ack's probe clock was seeded",
                'mode = "probe_rtt" /\\ filled /\\ probe_due',
            ),
            claim(
                "ZeroSampleResetsQuiet",
                "a zero sample leaves Startup with the quiet count cleared",
                'undid /\\ quiet = 0 /\\ mode = "startup" /\\ ~filled',
            ),
            claim(
                "GainCycleWraps",
                "the ProbeBW gain index wraps through 0",
                'mode = "probe_bw" /\\ phase = 0 /\\ filled',
            ),
            claim(
                "AboutToFill",
                "Startup can sit one quiet round before the pipe fills",
                'mode = "startup" /\\ quiet = 2 /\\ ~filled',
            ),
        ),
        # No control state is terminal. A dead end means the mode graph got stuck.
        terminal='mode = "startup" /\\ mode = "probe_bw"',
    )


# First-byte class to packet space. Actions come from this table; the
# invariants below are written out, so a row that disagrees with them fails.
# ``check_packet_bytes`` runs every first-byte value through the masks parsed
# from the Rust source and requires the same class-to-space result.
PACKET_SPACE = {
    "empty": "none",
    "bad_fixed": "none",
    "short": "1rtt",
    "initial": "initial",
    "zerortt": "0rtt",
    "handshake": "handshake",
    "retry": "none",
}


def packet_machine() -> Machine:
    """QUIC ``first_packet_space`` over header classes, not over every datagram.

    Empty input and a clear fixed bit are not a space. A short header is
    1-RTT. The long-header type bits select Initial, 0-RTT, or Handshake.
    Retry is not a space. The 256 concrete first bytes are checked against
    this table by ``check_packet_bytes``.
    """

    fields = ("form", "space")
    defaults: dict[str, Scalar] = {"form": "empty", "space": "pending"}
    actions = tuple(
        act(
            "Map" + form.title().replace("_", ""),
            f'form = "{form}" /\\ space = "pending"',
            space=f'"{space}"',
        )
        for form, space in PACKET_SPACE.items()
    )
    return Machine(
        name="ParallaXPacket",
        blurb="First-byte header class to QUIC packet space. Retry and a clear fixed bit are not spaces.",
        fields=fields,
        defaults=defaults,
        initials=tuple({"form": form} for form in PACKET_SPACE),
        actions=actions,
        invariants=(
            claim(
                "ShortHeaderIsOneRtt",
                "a short header is the 1-RTT space and nothing else is",
                '(form = "short" /\\ space # "pending" => space = "1rtt") /\\ (space = "1rtt" => form = "short")',
            ),
            claim(
                "LongTypesMatchTheirSpace",
                "Initial, 0-RTT, and Handshake map to those spaces",
                '(form = "initial" /\\ space # "pending" => space = "initial") /\\ (form = "zerortt" /\\ space # "pending" => space = "0rtt") /\\ (form = "handshake" /\\ space # "pending" => space = "handshake")',
            ),
            claim(
                "RetryIsNotASpace",
                "Retry is not decrypted as a packet-number space",
                'form = "retry" /\\ space # "pending" => space = "none"',
            ),
            claim(
                "ClearFixedBitIsNotASpace",
                "a clear fixed bit is not a packet space",
                'form = "bad_fixed" /\\ space # "pending" => space = "none"',
            ),
            claim(
                "EmptyIsNotASpace",
                "an empty datagram is not a packet space",
                'form = "empty" /\\ space # "pending" => space = "none"',
            ),
            claim(
                "ZeroRttIsItsOwnSpace",
                "0-RTT is classified on its own, not as 1-RTT and not as Initial",
                'space = "0rtt" => form = "zerortt"',
            ),
            claim(
                "NoneOnlyForRejects",
                "the no-space result is only empty, a clear fixed bit, or Retry",
                'space = "none" => form \\in {"empty", "bad_fixed", "retry"}',
            ),
        ),
        witnesses=(
            claim(
                "SeesOneRtt",
                "a short header is classified as 1-RTT",
                'form = "short" /\\ space = "1rtt"',
            ),
            claim(
                "SeesInitial",
                "an Initial long header is classified as Initial",
                'form = "initial" /\\ space = "initial"',
            ),
            claim(
                "SeesZeroRtt",
                "a 0-RTT long header is classified as 0-RTT",
                'form = "zerortt" /\\ space = "0rtt"',
            ),
            claim(
                "SeesHandshake",
                "a Handshake long header is classified as Handshake",
                'form = "handshake" /\\ space = "handshake"',
            ),
            claim(
                "RejectsRetry",
                "Retry is rejected",
                'form = "retry" /\\ space = "none"',
            ),
            claim(
                "RejectsClearFixedBit",
                "a clear fixed bit is rejected",
                'form = "bad_fixed" /\\ space = "none"',
            ),
        ),
        terminal='space # "pending"',
    )


def records_machine() -> Machine:
    """Parallel outbound batches in a three-sequence window and two key epochs.

    The small counter is an abstraction of the checked u64 counter, whose
    arithmetic and real AES retirement bound are proved separately by Kani.
    Rekey assumes a fresh key/nonce namespace; key derivation is not proved here.
    reserved0/reserved1 are independent ghost ledgers of consumed prefix lengths:
    reservation events increment them, and rekey never erases either history.
    No worker result is published until every result has succeeded.
    """
    actions = []
    for count in (1, 2):
        for epoch in (0, 1):
            ledger = f"reserved{epoch}"
            actions.append(act(
                f"Reserve{count}Epoch{epoch}",
                f'phase = "ready" /\\ ~poisoned /\\ next < {4 - count} /\\ epoch = {epoch}',
                phase='"reserved"', base="next + 0", prior_end=f"{ledger} + 0",
                next=f"next + {count}", high=f"next + {count}",
                remaining=str(count), published="FALSE",
                **{ledger: f"{ledger} + {count}"},
            ))
    actions.extend((
        act("CollectFirstSuccess", 'phase = "reserved" /\\ remaining = 2', remaining="1"),
        act("CollectLastSuccess", 'phase = "reserved" /\\ remaining = 1', remaining="0"),
        act("PublishWholeBatch", 'phase = "reserved" /\\ remaining = 0',
            phase='"ready"', published="TRUE"),
        act("WorkerFailure", 'phase = "reserved" /\\ remaining # 0',
            phase='"failed"', poisoned="TRUE", failed="TRUE", remaining="0", published="FALSE"),
        act("FreshKeyRekey", 'phase \\in {"ready", "failed"} /\\ epoch = 0',
            phase='"ready"', epoch="1", next="0", high="0", base="0",
            prior_end="0", remaining="0", published="FALSE"),
        act("CloseRecords", 'phase # "closed" /\\ phase # "reserved"',
            phase='"closed"', published="FALSE"),
    ))
    return Machine(
        name="ParallaXRecords",
        blurb="Bounded batch nonce reservation, publication, failure poison, and fresh-key rekey.",
        fields=("phase", "epoch", "next", "high", "base", "prior_end", "remaining", "poisoned", "failed", "published", "reserved0", "reserved1"),
        defaults={"phase": "ready", "epoch": 0, "next": 0, "high": 0,
                  "base": 0, "prior_end": 0, "remaining": 0, "poisoned": False,
                  "failed": False, "published": False, "reserved0": 0, "reserved1": 0},
        initials=(),
        actions=tuple(actions),
        invariants=(
            claim("ReservedRangesNeverOverlap", "new reservations begin after every earlier reservation in this key epoch",
                  'phase = "reserved" => (base = prior_end /\\ base < next /\\ next = high)'),
            claim("ReservationIsNeverRolledBack", "the next sequence matches an independent per-key reservation history",
                  "next = high /\\ (epoch = 0 => next = reserved0) /\\ (epoch = 1 => next = reserved1)"),
            claim("FailedBatchPoisonsPermanently", "worker failure remains poisoned even across a rekey",
                  "failed => poisoned"),
            claim("PoisonedCannotDispatch", "a poisoned codec cannot reserve or publish a later batch",
                  'poisoned => (phase # "reserved" /\\ ~published)'),
            claim("PublishOnlyWholeSuccess", "only a complete successful batch publishes ciphertext",
                  'published => (phase = "ready" /\\ remaining = 0 /\\ ~poisoned /\\ ~failed)'),
            claim("RecordWindowIsBounded", "the abstract counter has three sequences and two independent key epochs",
                  "next \\in {0, 1, 2, 3} /\\ epoch \\in {0, 1} /\\ reserved0 \\in {0, 1, 2, 3} /\\ reserved1 \\in {0, 1, 2, 3}"),
        ),
        witnesses=(
            claim("BatchCanPublish", "successful batches publish after reservation", "published"),
            claim("CounterCanRetire", "the abstract nonce window can be exhausted", 'next = 3 /\\ phase = "ready"'),
            claim("RekeyKeepsPoison", "rekey cannot revive a failed codec", 'epoch = 1 /\\ failed /\\ poisoned /\\ phase = "ready"'),
            claim("FreshEpochCanPublish", "a live codec can publish in a fresh key epoch", "epoch = 1 /\\ published"),
            claim("FreshKeyCanReuseSequence", "both fresh key namespaces can consume sequence zero without erasing earlier reservations",
                  "epoch = 1 /\\ published /\\ reserved0 # 0 /\\ reserved1 # 0"),
            claim("PartialWorkerSuccessIsBuffered", "one result can succeed while its sibling remains unpublished",
                  'phase = "reserved" /\\ next = 2 /\\ base = 0 /\\ remaining = 1 /\\ ~published'),
        ),
        terminal='phase = "closed"',
    )


def fragments_machine() -> Machine:
    """Every valid partition up to three bytes, and two successive PX1F frames.

    Offset, total, and length validation are abstracted into their reject classes.
    A caller aborts the frame/session on error; retrying a rejected reassembler
    is outside this model. Byte values and allocator behavior are not modeled.
    """
    actions = []
    for total in (1, 2, 3):
        for offset in range(total):
            for count in range(1, total - offset + 1):
                end = offset + count
                complete = end == total
                latch = 0 if offset == 0 else total
                assign = dict(
                    total="0" if complete else str(total),
                    cursor="0" if complete else str(end),
                    last_total=str(total), last_size=str(end),
                    outcome='"complete"' if complete else '"partial"',
                    emitted="TRUE" if complete else "FALSE",
                )
                if complete:
                    assign["frames"] = "frames + 1"
                actions.append(act(
                    f"Chunk{total}At{offset}Len{count}",
                    f'~stopped /\\ frames < 2 /\\ total = {latch} /\\ cursor = {offset}',
                    **assign,
                ))
    # Each reject class stands for arbitrary bytes that fail the corresponding
    # decode_ref/push gate. Earlier successful frames remain observable, but the
    # rejected call emits no payload and cannot be followed by another push.
    for reason in ("Decode", "TooLarge", "ChangedTotal", "WrongOffset"):
        guard = "~stopped /\\ frames < 2"
        if reason == "ChangedTotal":
            guard += " /\\ total # 0"
        actions.append(act(f"Reject{reason}", guard, stopped="TRUE",
                           emitted="FALSE", outcome='"error"'))
    return Machine(
        name="ParallaXFragments",
        blurb="Bounded PX1F partitions, total/offset rejection, and completion reset before the next frame.",
        fields=("total", "cursor", "frames", "last_total", "last_size", "outcome", "emitted", "stopped"),
        defaults={"total": 0, "cursor": 0, "frames": 0, "last_total": 0,
                  "last_size": 0, "outcome": "none", "emitted": False, "stopped": False},
        initials=(),
        actions=tuple(actions),
        invariants=(
            claim("FragmentsStayWithinTotal", "a partial payload cannot exceed its latched total",
                  '(total = 0 => cursor = 0) /\\ (total # 0 => (cursor < total /\\ total \\in {1, 2, 3}))'),
            claim("EmitOnlyCompleteFrame", "only an exactly complete frame can be returned",
                  'emitted => (outcome = "complete" /\\ last_size = last_total /\\ last_total # 0 /\\ frames # 0)'),
            claim("CompletionClearsLatch", "a returned frame clears the latch and buffer before reuse",
                  'outcome = "complete" => (total = 0 /\\ cursor = 0)'),
            claim("RejectedChunkEmitsNothing", "a malformed or inconsistent chunk emits no frame",
                  'outcome = "error" => (stopped /\\ ~emitted)'),
            claim("PartialChunkEmitsNothing", "a partial chunk remains buffered",
                  'outcome = "partial" => (~emitted /\\ total # 0 /\\ cursor # 0)'),
            claim("FrameCountIsBounded", "two frames suffice to exercise completion and reuse",
                  "frames \\in {0, 1, 2}"),
        ),
        witnesses=(
            claim("PartialFrameIsReachable", "a multi-chunk payload remains buffered", 'outcome = "partial"'),
            claim("SecondFrameCanComplete", "the same reassembler accepts a second complete frame", "frames = 2 /\\ emitted"),
            claim("BadContinuationIsRejected", "a malformed continuation after a partial frame fails closed", "stopped /\\ total # 0"),
        ),
        terminal="stopped \\/ frames = 2",
    )


def mux_machine() -> Machine:
    """Two TCP MUX streams, capacity one or two, and asynchronous task exit.

    Task completion and the next admission's prune are one observation step.
    An abort request is deliberately a separate step from task exit. Snapshot
    fields are edge monitors, so isolation and half-close assertions compare
    the real pre/post state instead of assuming a transition is harmless.
    ``turn`` records event parity, permitting repeated ignored/Cover frames
    without a stuttering action in the Python checker. No step bound is used.
    """
    per_stream = ("task", "upload", "up", "down", "charged")
    defaults: dict[str, Scalar] = {
        "phase": "open", "capacity": 1, "turn": 0,
        "focus": 0, "event": "initial", "released": False,
    }
    for sid in (0, 1):
        for field in per_stream:
            value: Scalar = "none" if field == "task" else False
            defaults[f"{field}{sid}"] = value
            defaults[f"before_{field}{sid}"] = value
    actions = []

    def local(sid: int, name: str, guard: str, **assign: str) -> None:
        snapshots = {f"before_{field}{i}": f"{field}{i}"
                     for i in (0, 1) for field in per_stream}
        phase = 'phase \\in {"open", "closing"}' if name == "CancellationDone" else 'phase = "open"'
        for turn in (0, 1):
            actions.append(act(
                f"{name}{sid}Turn{turn}",
                f'{phase} /\\ turn = {turn} /\\ ({guard})',
                **snapshots, **assign, turn=str(1 - turn),
                focus=str(sid), event=f'"{name}"',
            ))

    for sid in (0, 1):
        peer = 1 - sid
        live = f'task{sid} \\in {{"connecting", "relaying"}}'
        abort = {f"task{sid}": '"cancelling"', f"upload{sid}": "FALSE"}
        release = {f"task{sid}": '"none"', f"upload{sid}": "FALSE",
                   f"up{sid}": "FALSE", f"down{sid}": "FALSE",
                   f"charged{sid}": "FALSE", "released": "TRUE"}
        local(sid, "Open", f'task{sid} = "none" /\\ (capacity = 2 \\/ ~charged{peer})',
              **{f"task{sid}": '"connecting"', f"upload{sid}": "TRUE",
                 f"up{sid}": "TRUE", f"down{sid}": "TRUE", f"charged{sid}": "TRUE"})
        local(sid, "DuplicateOpen", f'task{sid} # "none"')
        local(sid, "CapacityReject", f'task{sid} = "none" /\\ capacity = 1 /\\ charged{peer}')
        local(sid, "ConnectOk", f'task{sid} = "connecting"', **{f"task{sid}": '"relaying"'})
        for failure in ("ResolveFailure", "ConnectFailure", "TuneFailure", "InitialWriteFailure"):
            local(sid, failure, f'task{sid} = "connecting"', **abort)
        local(sid, "DataDelivered", f'{live} /\\ upload{sid} /\\ up{sid}')
        local(sid, "DataIgnored", f'~upload{sid}')
        local(sid, "Fin", f'upload{sid}', **{f"upload{sid}": "FALSE"})
        local(sid, "DuplicateFin", f'~upload{sid}')
        local(sid, "UploadDrained", f'task{sid} = "relaying" /\\ ~upload{sid} /\\ up{sid}',
              **{f"up{sid}": "FALSE"})
        local(sid, "TargetFin", f'task{sid} = "relaying" /\\ down{sid}',
              **{f"down{sid}": "FALSE"})
        local(sid, "BothDirectionsDone", f'task{sid} = "relaying" /\\ ~up{sid} /\\ ~down{sid}',
              **release)
        local(sid, "Reset", f'task{sid} # "none"', **abort)
        local(sid, "UnknownReset", f'task{sid} = "none"')
        local(sid, "UploadStall", f'{live} /\\ upload{sid}', **abort)
        local(sid, "TargetReadError", f'task{sid} = "relaying"', **abort)
        local(sid, "StreamIdle", f'task{sid} = "relaying"', **release)
        local(sid, "CancellationDone", f'task{sid} = "cancelling"', **release)
        actions.append(act(
            f"TeardownAbort{sid}", f'phase = "closing" /\\ {live}',
            event='"teardown"', **abort,
        ))
    local(0, "Cover", 'phase = "open"')
    actions.append(act("CarrierTeardown", 'phase = "open"', phase='"closing"',
                       event='"teardown"', upload0="FALSE", upload1="FALSE"))
    actions.append(act("CarrierTeardownComplete", 'phase = "closing" /\\ task0 = "none" /\\ task1 = "none"',
                       phase='"closed"', event='"teardown"'))
    same = lambda sid: " /\\ ".join(f"{field}{sid} = before_{field}{sid}" for field in per_stream)
    invariants = [
        claim("MuxCapacityCountsBothHalves", "a one-slot carrier never owns two unfinished supervisors",
              "capacity = 1 => ~(charged0 /\\ charged1)"),
        claim("MuxLocalEventsPreserveSibling", "a frame, setup failure, or cancellation affects only its own stream",
              f'event # "teardown" => ((focus = 0 => ({same(1)})) /\\ (focus = 1 => ({same(0)})))'),
        claim("MuxRejectedOpenAndCoverAreInert", "duplicate/capacity Open rejection and Cover change neither stream",
              f'event \\in {{"DuplicateOpen", "CapacityReject", "Cover"}} => ({same(0)} /\\ {same(1)})'),
        claim("MuxTeardownReleasesAllSlots", "carrier teardown leaves no owned supervisor or target half",
              'phase = "closed" => (~charged0 /\\ ~charged1 /\\ ~up0 /\\ ~up1 /\\ ~down0 /\\ ~down1)'),
    ]
    for sid in (0, 1):
        invariants.extend((
            claim(f"MuxOwnership{sid}", "a live task and its slot remain paired until task exit",
                  f'(charged{sid} => task{sid} # "none") /\\ (task{sid} # "none" => charged{sid}) /\\ (upload{sid} => charged{sid})'),
            claim(f"MuxLiveHalfKeepsSlot{sid}", "one remaining relay direction still consumes capacity",
                  f'(up{sid} \\/ down{sid}) => charged{sid}'),
            claim(f"MuxFinIsHalfClose{sid}", "FIN removes upload routing while preserving the supervisor and both target halves",
                  f'event = "Fin" /\\ focus = {sid} => (~upload{sid} /\\ charged{sid} /\\ task{sid} = before_task{sid} /\\ up{sid} = before_up{sid} /\\ down{sid} = before_down{sid})'),
            claim(f"MuxDataRequiresUploadRoute{sid}", "no new DATA is enqueued after upload routing is removed",
                  f'event = "DataDelivered" /\\ focus = {sid} => (upload{sid} /\\ up{sid} /\\ charged{sid})'),
            claim(f"MuxResetKeepsSlotUntilExit{sid}", "requesting cancellation does not prematurely release its slot",
                  f'event = "Reset" /\\ focus = {sid} => (task{sid} = "cancelling" /\\ charged{sid} /\\ ~upload{sid})'),
        ))
    return Machine(
        name="ParallaXMux", blurb="Two TCP MUX streams: admission, half-close, local reset, task exit, and sibling isolation.",
        fields=tuple(defaults), defaults=defaults, initials=({"capacity": 1}, {"capacity": 2}),
        actions=tuple(actions), invariants=tuple(invariants),
        witnesses=(
            claim("MuxTwoStreamsCanRelay", "two streams can coexist on a two-slot carrier",
                  'task0 = "relaying" /\\ task1 = "relaying" /\\ capacity = 2'),
            claim("MuxHalfCloseStillConsumesCapacity", "an upload FIN cannot free a slot while the download remains live",
                  'capacity = 1 /\\ charged0 /\\ ~upload0 /\\ ~up0 /\\ down0'),
            claim("MuxResetExitIsAsynchronous", "an aborted supervisor still consumes its slot before task exit",
                  'task0 = "cancelling" /\\ charged0 /\\ up0'),
            claim("MuxFreedSlotCanBeReused", "task exit permits a later admission",
                  'released /\\ event = "Open" /\\ capacity = 1'),
            claim("MuxSetupFailureLeavesSiblingLive", "a failed target setup leaves another active stream intact",
                  'event = "ConnectFailure" /\\ focus = 0 /\\ task1 = "relaying"'),
            claim("MuxCarrierWaitsForTaskExit", "carrier teardown still owns aborted supervisors until they exit",
                  'phase = "closing" /\\ task0 = "cancelling" /\\ charged0'),
        ), terminal='phase = "closed"',
    )


def identity_chunks_machine() -> Machine:
    """PX1I caller parsing with exhaustive bounded candidate metadata.

    Total 0..4, offset 0..3, length 0..4 are external inputs, not valid-input
    assumptions. Capacity is scaled to three bytes. AEAD/ML-DSA outcomes are
    opaque checks; arbitrary byte strings, signature math, and clocks are not
    proved. The outer establishment deadline may interrupt every pre-CONNECT
    state, including partial records and the blocking verification await.
    """
    actions = []
    for total in range(5):
        for offset in range(4):
            for count in range(5):
                actions.append(act(
                    f"ReadT{total}O{offset}L{count}", 'phase = "reading"',
                    phase='"auth"', incoming_total=str(total), incoming_offset=str(offset),
                    incoming_len=str(count), incoming_end=str(offset + count),
                ))
    fail = lambda reason: dict(phase='"failed"', reason=f'"{reason}"')
    actions.extend((
        act("IdentityReadEof", 'phase = "reading"', **fail("eof")),
        act("IdentityReadIoError", 'phase = "reading"', **fail("io")),
        act("IdentityAuthFails", 'phase = "auth"', **fail("aead")),
        act("IdentityAuthOk", 'phase = "auth"', phase='"decode"'),
        act("IdentityDecodeReject", 'phase = "decode" /\\ (incoming_total = 0 \\/ incoming_len = 0 \\/ incoming_total < incoming_end)', **fail("decode")),
        act("IdentityDecodeOk", 'phase = "decode" /\\ incoming_total # 0 /\\ incoming_len # 0 /\\ ~(incoming_total < incoming_end)', phase='"cap"'),
        act("IdentityCapReject", 'phase = "cap" /\\ incoming_total = 4', **fail("capacity")),
        act("IdentityCapOk", 'phase = "cap" /\\ incoming_total < 4', phase='"total"'),
        act("IdentityLatchFirstTotal", 'phase = "total" /\\ total = 0', total="incoming_total", phase='"offset"'),
        act("IdentityCheckTotal", 'phase = "total" /\\ total # 0 /\\ incoming_total = total', phase='"offset"'),
        act("IdentityChangedTotal", 'phase = "total" /\\ total # 0 /\\ incoming_total # total', **fail("changed_total")),
        act("IdentityWrongOffset", 'phase = "offset" /\\ incoming_offset # cursor', **fail("offset")),
        act("IdentityAppend", 'phase = "offset" /\\ incoming_offset = cursor',
            before_cursor="cursor", cursor="incoming_end", phase='"completion"'),
        act("IdentityPartial", 'phase = "completion" /\\ cursor < total', phase='"reading"'),
        act("IdentityAssembled", 'phase = "completion" /\\ cursor = total', phase='"assembled"'),
        act("IdentityMissingBinding", 'phase = "assembled" /\\ ~binding', **fail("binding")),
        act("IdentityBadSignature", 'phase = "assembled" /\\ binding', **fail("signature")),
        act("IdentityVerifyOk", 'phase = "assembled" /\\ binding', phase='"verified"', verified="TRUE"),
        act("IdentityThenConnect", 'phase = "verified"', phase='"connect"', connect_sent="TRUE"),
        act("IdentityEstablishmentTimeout", 'phase \\in {"reading", "auth", "decode", "cap", "total", "offset", "completion", "assembled", "verified"}', **fail("deadline")),
    ))
    return Machine(
        name="ParallaXIdentityChunks", blurb="PX1I caller: bounded arbitrary chunk metadata, AEAD, reassembly, verification, deadline, CONNECT gate.",
        fields=("phase", "total", "cursor", "before_cursor", "incoming_total", "incoming_offset", "incoming_len", "incoming_end", "binding", "verified", "connect_sent", "reason"),
        defaults={"phase": "reading", "total": 0, "cursor": 0, "incoming_total": 0,
                  "before_cursor": 0, "incoming_offset": 0, "incoming_len": 0, "incoming_end": 0,
                  "binding": True, "verified": False, "connect_sent": False, "reason": "none"},
        initials=({"binding": True}, {"binding": False}), actions=tuple(actions),
        invariants=(
            claim("IdentityBufferNeverExceedsCap", "no accepted metadata can grow the caller buffer beyond its bounded capacity",
                  "cursor \\in {0, 1, 2, 3} /\\ total \\in {0, 1, 2, 3} /\\ ~(total < cursor)"),
            claim("IdentityAppendRequiresValidatedMetadata", "append follows a matching total, exact offset, positive length, and in-range end",
                  'phase = "completion" => (total = incoming_total /\\ incoming_offset = before_cursor /\\ cursor = incoming_end /\\ incoming_len # 0 /\\ incoming_offset < cursor /\\ ~(total < cursor))'),
            claim("IdentityPartialCannotVerify", "partial accumulation cannot be returned or verified",
                  'phase \\in {"assembled", "verified", "connect"} => (total # 0 /\\ cursor = total)'),
            claim("IdentityVerificationNeedsWholeBoundPayload", "verification success requires the full payload and the PQ identity binding",
                  "verified => (binding /\\ total # 0 /\\ cursor = total)"),
            claim("IdentityFailureBlocksConnect", "EOF, AEAD, framing, signature, or deadline failure cannot send CONNECT",
                  'phase = "failed" => ~connect_sent'),
            claim("IdentityConnectWaitsForVerification", "CONNECT follows complete reassembly and successful identity verification",
                  'connect_sent => (phase = "connect" /\\ verified /\\ binding /\\ cursor = total /\\ total # 0)'),
        ),
        witnesses=(
            claim("IdentityCanConnect", "a complete authenticated and verified payload permits CONNECT", "connect_sent"),
            claim("IdentityPartialReadCanTimeout", "the deadline can abort a partially assembled payload", 'reason = "deadline" /\\ cursor # 0 /\\ cursor < total'),
            claim("IdentityTotalChangeIsRejected", "an inconsistent continuation is rejected", 'reason = "changed_total"'),
            claim("IdentityOutOfOrderIsRejected", "a gap, overlap, or duplicate offset is rejected", 'reason = "offset"'),
            claim("IdentityCapacityIsChecked", "an over-cap but structurally valid chunk is rejected", 'reason = "capacity"'),
            claim("IdentityMissingPqBindingFails", "complete chunks alone cannot bypass a missing PQ binding", 'reason = "binding"'),
            claim("IdentitySignatureFailureBlocksConnect", "complete chunks can still fail identity verification", 'reason = "signature"'),
            claim("IdentityPartialEofIsFailure", "EOF after partial accumulation is a failure", 'reason = "eof" /\\ cursor # 0'),
        ), terminal='phase \\in {"failed", "connect"}',
    )


def machines() -> tuple[Machine, ...]:
    return (
        session_machine(),
        quic_machine(),
        zero_rtt_machine(),
        replay_machine(),
        probe_machine(),
        inbound_machine(),
        keys_machine(),
        close_machine(),
        bbr_machine(),
        packet_machine(),
        records_machine(),
        fragments_machine(),
        mux_machine(),
        identity_chunks_machine(),
    )


def _tla_scalar(value: Scalar) -> str:
    if isinstance(value, bool):
        return "TRUE" if value else "FALSE"
    if isinstance(value, int):
        return str(value)
    return f'"{value}"'


def _unchanged(fields: Iterable[str]) -> str:
    names = list(fields)
    if not names:
        return ""
    return "UNCHANGED << " + ", ".join(names) + " >>"


def render_tla(machine: Machine) -> str:
    lines = [
        f"\\* Generated by formal/plx_formal.py from the {machine.name} tables.",
        "\\* Do not edit by hand. Run: python3 formal/plx_formal.py emit",
        "\\*",
        f"\\* {machine.blurb}",
        "\\*",
        "\\* Safety claims (states and steps that must be unreachable):",
    ]
    for item in machine.invariants:
        lines.append(f"\\*   {item.name}: {item.summary}")
    lines.extend(
        [
            "",
            "---- MODULE " + machine.name + " ----",
            "EXTENDS Integers",
            "",
            "VARIABLES " + ", ".join(machine.fields),
            "",
            "vars == << " + ", ".join(machine.fields) + " >>",
            "",
            "Init ==",
        ]
    )
    initial_states = _initials(machine)
    if len(initial_states) == 1:
        state = initial_states[0]
        for field in machine.fields:
            lines.append(f"  /\\ {field} = {_tla_scalar(state[field])}")
    else:
        for state in initial_states:
            conj = " /\\ ".join(
                f"{field} = {_tla_scalar(state[field])}" for field in machine.fields
            )
            lines.append(f"  \\/ ({conj})")
    lines.append("")
    for action in machine.actions:
        lines.append(f"{action.name} ==")
        lines.append(f"  /\\ ({action.guard})")
        assigned = []
        for field in machine.fields:
            if field not in action.assign:
                continue
            lines.append(f"  /\\ {field}' = {action.assign[field]}")
            assigned.append(field)
        rest = [field for field in machine.fields if field not in assigned]
        unchanged = _unchanged(rest)
        if unchanged:
            lines.append(f"  /\\ {unchanged}")
        lines.append("")
    lines.append("Next ==")
    for action in machine.actions:
        lines.append(f"  \\/ {action.name}")
    lines.extend(["", "Spec == Init /\\ [][Next]_vars", ""])
    for item in machine.invariants:
        lines.append(f"\\* {item.summary}")
        lines.append(f"{item.name} ==")
        lines.append(f"  {item.formula}")
        lines.append("")
    lines.append("====")
    lines.append("")
    return "\n".join(lines)


def render_cfg(machine: Machine) -> str:
    lines = [
        f"\\* Generated by formal/plx_formal.py for {machine.name}.",
        "SPECIFICATION Spec",
    ]
    for item in machine.invariants:
        lines.append(f"INVARIANT {item.name}")
    lines.append("")
    return "\n".join(lines)


def emitted_paths(machine: Machine) -> tuple[Path, Path]:
    return FORMAL / f"{machine.name}.tla", FORMAL / f"{machine.name}.cfg"


def emit_files() -> list[Path]:
    written = []
    for machine in machines():
        tla, cfg = emitted_paths(machine)
        tla.write_text(render_tla(machine))
        cfg.write_text(render_cfg(machine))
        written.extend((tla, cfg))
    return written


def check_fresh() -> None:
    stale = []
    for machine in machines():
        tla, cfg = emitted_paths(machine)
        expected_tla = render_tla(machine)
        expected_cfg = render_cfg(machine)
        if not tla.is_file() or tla.read_text() != expected_tla:
            stale.append(str(tla.relative_to(ROOT)))
        if not cfg.is_file() or cfg.read_text() != expected_cfg:
            stale.append(str(cfg.relative_to(ROOT)))
    if stale:
        joined = ", ".join(stale)
        raise FormalError(
            "TLA+ output does not match the model tables. "
            f"Run: python3 formal/plx_formal.py emit\n  stale: {joined}"
        )


def check_all() -> list[Report]:
    reports = [check_machine(machine) for machine in machines()]
    check_packet_bytes()
    check_probe_status_bytes()
    check_ledger()
    check_fresh()
    return reports


_LEDGER_CLASSES = {"exhaustive", "bounded-elsewhere", "not-exhaustive"}


def rust_sources(root: Path = ROOT) -> set[str]:
    src = root / "src"
    return {path.relative_to(root).as_posix() for path in src.rglob("*.rs")}


def _parse_ledger(text: str) -> dict[str, tuple[str, str]]:
    rows: dict[str, tuple[str, str]] = {}
    for line_no, line in enumerate(text.splitlines(), 1):
        if not line.startswith("| `src/"):
            continue
        cells = [cell.strip() for cell in line.strip().strip("|").split("|")]
        if len(cells) != 3:
            raise FormalError(f"formal/COVERAGE.md:{line_no} expected 3 cells")
        path = cells[0].strip("`").strip()
        kind = cells[1]
        why = cells[2]
        if path in rows:
            raise FormalError(f"formal/COVERAGE.md lists {path} twice")
        rows[path] = (kind, why)
    if not rows:
        raise FormalError("formal/COVERAGE.md has no source rows")
    return rows


# Snippets correspond() requires in a file whose COVERAGE.md Why names that machine.
# check() fails when the Why cell names a machine and the file lacks one of these.
MACHINE_ANCHORS: dict[str, dict[str, tuple[str, ...]]] = {
    "ParallaXSession": {
        "src/handshake/server.rs": (
            "cache.reserve_pending(&entry, now)",
            "if !fresh",
            "if !commit_pending_replay_entry",
            "apply_server_pq_rekey(",
        ),
        "src/client/runtime.rs": (
            "fn verify_server_identity_payload_blocking",
            "pq_identity_binding()",
            "verify_server_identity(",
        ),
        "src/handshake/client.rs": (
            "MissingPqIdentityBinding",
            "verify_server_identity(",
        ),
        "src/crypto/session.rs": (
            "ct_eq(&[0u8; KEY_LEN])",
            "DegenerateSharedSecret",
        ),
        "src/crypto/pq.rs": (
            "ct_eq(&[0_u8; 32])",
            "DegenerateSharedSecret",
        ),
        "src/crypto/replay.rs": (
            "fn reserve_pending(",
            "self.pending_transcripts.len() >= self.capacity.max(1)",
            "self.is_fresh(entry.timestamp, now)",
        ),
    },
    "ParallaXQuic": {
        "src/tls/quic/handshake.rs": (
            "if self.psk_accepted",
            "ReadState::Finished",
            "ReadState::Certificate",
        ),
        "src/tls/quic/server.rs": (
            "self.handshake_complete = true",
            "self.issue_session_ticket()",
        ),
    },
    "ParallaXZeroRtt": {
        "src/transport/udp/zero_rtt.rs": ("== ReplayInsertOutcome::Inserted",),
        "src/client/runtime.rs": (
            "is_safari26_settings(&settings)",
            "take_session_ticket(",
        ),
        "src/tls/quic/server.rs": (
            "expected.ct_eq(binder)",
            "accept_ticket(",
        ),
    },
    "ParallaXReplay": {
        "src/crypto/replay.rs": (
            "self.prune_expired(now)",
            "ReplayInsertOutcome::Stale",
            "ReplayInsertOutcome::CacheFull",
        ),
    },
    "ParallaXProbe": {
        "src/transport/udp/probe.rs": (
            "reply.len() == PROBE_RESPONSE_WIRE_LEN",
            "ProbeOutcome::Failed",
        ),
        "src/handshake/server.rs": (
            "fn udp_retention_decision(",
            "UdpRetentionDecision::StayOnTcp",
        ),
        "src/protocol/command.rs": (
            "0 => Ok(Self::Verified)",
            "UdpProbeAckError::InvalidStatus",
        ),
    },
    "ParallaXInbound": {
        "src/handshake/server.rs": (
            "FallbackReason::AuthFailed",
            "FallbackReason::MissingSni",
            "ConnectionDecision::Authenticated",
        ),
    },
    "ParallaXKeys": {
        "src/tls/quic/handshake.rs": (
            "KeyChange::ZeroRtt",
            "KeyChange::OneRtt",
        ),
        "src/tls/quic/server.rs": (
            "KeyChange::OneRtt",
            "pending_post_handshake",
        ),
    },
    "ParallaXClose": {
        "src/transport/udp/quic/conn.rs": (
            "build_close_packet(",
            "CloseReason::IdleTimeout",
        ),
    },
    "ParallaXBbr": {
        "src/transport/udp/quic/congestion.rs": (
            "self.check_probe_rtt(",
            "BBR_FULL_BW_THRESHOLD",
        ),
    },
    "ParallaXPacket": {
        "src/transport/udp/quic/packet.rs": (
            "datagram.first()?",
            "_ => LongType::Retry",
        ),
    },
    "ParallaXRecords": {
        "src/crypto/session.rs": (
            "self.ensure_usable()?;",
            "self.next = end;",
            "self.records.reset_for_rekey();",
        ),
        "src/protocol/data.rs": (
            "self.aead.reserve_sequence(record_count as u64)?",
            "self.aead.poison();",
            "out.extend_from_slice(segment);",
        ),
    },
    "ParallaXFragments": {
        "src/protocol/command.rs": (
            "FramedChunk::decode_ref(chunk)?",
            "FramedChunkError::InconsistentTotal",
            "self.expected_total = None;",
            "std::mem::take(&mut self.assembled)",
        ),
    },
    "ParallaXMux": {
        "src/handshake/server.rs": (
            "self.tasks.retain(|_, h| !h.is_finished())",
            "streams.live_count() >= context.max_streams",
            "streams.uploads.remove(&frame.stream_id)",
            "tokio::try_join!(reader, writer)",
        ),
    },
    "ParallaXIdentityChunks": {
        "src/client/runtime.rs": (
            "read_server_identity_payload(&mut server, &mut data_session).await?",
            "total_len > MAX_SERVER_IDENTITY_PAYLOAD",
            "chunk.offset as usize != assembled.len()",
            "CLIENT_ESTABLISH_TIMEOUT",
        ),
    },
}


def check_ledger(root: Path = ROOT, files: Optional[set[str]] = None) -> None:
    """Fail when ``src/**/*.rs`` gains a file the coverage ledger does not name."""

    text = (root / "formal" / "COVERAGE.md").read_text()
    rows = _parse_ledger(text)
    on_disk = rust_sources(root) if files is None else set(files)
    missing = sorted(on_disk - set(rows))
    extra = sorted(set(rows) - on_disk)
    if missing or extra:
        parts = []
        if missing:
            parts.append("not in formal/COVERAGE.md: " + ", ".join(missing))
        if extra:
            parts.append("ledger lists missing files: " + ", ".join(extra))
        raise FormalError("; ".join(parts))
    names = {machine.name for machine in machines()}
    for path, (kind, why) in rows.items():
        if kind not in _LEDGER_CLASSES:
            raise FormalError(f"{path} has unknown coverage class {kind!r}")
        if kind == "exhaustive" and not any(name in why for name in names):
            raise FormalError(f"{path} is marked exhaustive but names no machine")
        if kind == "bounded-elsewhere" and "kani::proof" not in (root / path).read_text():
            raise FormalError(f"{path} is bounded-elsewhere but has no kani::proof")
    for path in sorted(on_disk):
        if "kani::proof" in (root / path).read_text() and rows[path][0] != "bounded-elsewhere":
            raise FormalError(f"{path} has a kani::proof but is not bounded-elsewhere")
    for name in sorted(names):
        if name not in text:
            raise FormalError(f"formal/COVERAGE.md does not mention {name}")
    for path, (_kind, why) in rows.items():
        source = (root / path).read_text() if (root / path).is_file() else ""
        for name in sorted(names):
            if name not in why:
                continue
            anchors = MACHINE_ANCHORS.get(name, {}).get(path)
            if not anchors:
                raise FormalError(
                    f"{path} names {name} but has no correspond anchor for that file"
                )
            for snippet in anchors:
                if snippet not in source:
                    raise FormalError(
                        f"{path} names {name} but is missing correspond anchor {snippet!r}"
                    )


def _rust_u8(src: str, name: str) -> int:
    match = re.search(
        rf"const\s+{re.escape(name)}\s*:\s*u8\s*=\s*(0x[0-9a-fA-F]+)\s*;",
        src,
    )
    if match is None:
        raise FormalError(f"missing u8 const {name}")
    return int(match.group(1), 16)


def check_packet_bytes(root: Path = ROOT) -> None:
    """Classify every first-byte value and require the Rust masks to match the table.

    This is the 256-value half of ``ParallaXPacket``. TLC checks the seven header
    classes. Here the masks and long-type arms are read from ``packet.rs``, then
    every byte is run through those bits.
    """

    src = (root / "src/transport/udp/quic/packet.rs").read_text()
    fixed = _rust_u8(src, "FIXED_BIT")
    form_bit = _rust_u8(src, "LONG_HEADER_FORM")
    mask = _rust_u8(src, "LONG_TYPE_MASK")
    if (fixed, form_bit, mask) != (0x40, 0x80, 0x30):
        raise FormalError(
            "QUIC first-byte masks changed: "
            f"FIXED_BIT={fixed:#x} LONG_HEADER_FORM={form_bit:#x} LONG_TYPE_MASK={mask:#x}"
        )
    body = _extract_fn(src, "from_first_byte")
    space_fn = _extract_fn(src, "first_packet_space")
    if "datagram.first()?" not in space_fn:
        raise FormalError("empty datagram must return None via datagram.first()?")
    if "datagram[0]" in space_fn:
        raise FormalError("first_packet_space indexes an empty datagram")
    arms = {
        int(hexval, 16): name
        for hexval, name in re.findall(
            r"(0x[0-9a-fA-F]+)\s*=>\s*LongType::(Initial|ZeroRtt|Handshake|Retry)",
            body,
        )
    }
    if arms != {0x00: "Initial", 0x10: "ZeroRtt", 0x20: "Handshake"}:
        raise FormalError(f"long-header type arms changed: {sorted(arms.items())}")
    wild = re.search(r"_\s*=>\s*LongType::(\w+)", body)
    if wild is None:
        raise FormalError("from_first_byte has no wildcard arm")
    if wild.group(1) != "Retry":
        raise FormalError(
            f"from_first_byte wildcard is LongType::{wild.group(1)}, not Retry"
        )
    space_of_type = {
        "Initial": "initial",
        "ZeroRtt": "0rtt",
        "Handshake": "handshake",
        "Retry": "none",
    }
    klass_of_type = {
        "Initial": "initial",
        "ZeroRtt": "zerortt",
        "Handshake": "handshake",
        "Retry": "retry",
    }
    counts: dict[str, int] = {}
    for value in range(256):
        if value & fixed == 0:
            klass = "bad_fixed"
            space = "none"
        elif value & form_bit == 0:
            klass = "short"
            space = "1rtt"
        else:
            name = arms[value & mask] if (value & mask) in arms else wild.group(1)
            klass = klass_of_type[name]
            space = space_of_type[name]
        if PACKET_SPACE[klass] != space:
            raise FormalError(
                f"first byte {value:#x} is {klass}->{space}, table says {PACKET_SPACE[klass]}"
            )
        counts[klass] = counts.get(klass, 0) + 1
    expect = {
        "bad_fixed": 128,
        "short": 64,
        "initial": 16,
        "zerortt": 16,
        "handshake": 16,
        "retry": 16,
    }
    if counts != expect:
        raise FormalError(f"first-byte class counts {counts} != {expect}")
    if PACKET_SPACE["empty"] != "none":
        raise FormalError("empty datagram must not be a packet space")


def check_probe_status_bytes(root: Path = ROOT) -> None:
    """Exhaust the PX1P status byte using the arms parsed from ``command.rs``."""

    src = (root / "src/protocol/command.rs").read_text()
    decoded = {
        int(num): name
        for num, name in re.findall(
            r"(\d+)\s*=>\s*Ok\(Self::(\w+)\)",
            _extract_fn(src, "from_byte"),
        )
    }
    if decoded != {0: "Verified", 1: "Unreachable", 2: "Failed"}:
        raise FormalError(f"UdpProbeStatus::from_byte changed: {sorted(decoded.items())}")
    from_byte = _extract_fn(src, "from_byte")
    if re.search(r"_\s*=>", from_byte):
        raise FormalError("UdpProbeStatus::from_byte has a wildcard arm")
    if "InvalidStatus" not in from_byte:
        raise FormalError("UdpProbeStatus::from_byte no longer rejects other bytes")
    encoded = {
        name: int(num)
        for name, num in re.findall(
            r"Self::(\w+)\s*=>\s*(\d+)",
            _extract_fn(src, "to_byte"),
        )
    }
    if encoded != {"Verified": 0, "Unreachable": 1, "Failed": 2}:
        raise FormalError(f"UdpProbeStatus::to_byte changed: {sorted(encoded.items())}")
    invalid = 0
    for value in range(256):
        name = decoded.get(value)
        if name is None:
            invalid += 1
            continue
        if encoded.get(name) != value:
            raise FormalError(f"status {name} does not round-trip byte {value}")
    if invalid != 253:
        raise FormalError(f"{invalid} invalid probe-status bytes, expected 253")
    runtime = (root / "src/client/runtime.rs").read_text()
    probe_fn = _extract_fn(runtime, "run_client_udp_probe")
    failed = ".unwrap_or(ProbeOutcome::Failed)"
    if probe_fn.count(failed) != 2:
        raise FormalError(
            "run_client_udp_probe must map both probe setup failures with "
            f"{failed}, found {probe_fn.count(failed)}"
        )
    zero_rtt = probe_fn.find("probe_client_read_and_verify(")
    cold = probe_fn.find("probe_client_over_bidi(")
    first_failed = probe_fn.find(failed)
    second_failed = probe_fn.find(failed, first_failed + len(failed))
    if not (0 <= zero_rtt < first_failed < cold < second_failed):
        raise FormalError(
            "unwrap_or(ProbeOutcome::Failed) must follow the 0-RTT read and the cold probe"
        )


def _extract_fn(src: str, name: str) -> str:
    """Return the body of ``fn name``.

    The character after the name must be ``(``, ``<``, or whitespace, so
    ``fn insert_new_outcome`` does not bind ``fn insert_new_outcome_deferred``.
    """

    marker = f"fn {name}"
    start = 0
    while True:
        at = src.find(marker, start)
        if at < 0:
            raise FormalError(f"missing fn {name}")
        before = src[at - 1] if at else "\n"
        after_at = at + len(marker)
        after = src[after_at] if after_at < len(src) else ""
        if before.isalnum() or before == "_" or not (after.isspace() or after in "(<"):
            start = at + len(marker)
            continue
        break
    brace = src.find("{", at)
    if brace < 0:
        raise FormalError(f"missing body for fn {name}")
    return src[at : brace + 1] + _scan_block(src, brace)


def _scan_block(src: str, start_brace: int) -> str:
    i = start_brace
    depth = 0
    n = len(src)
    while i < n:
        c = src[i]
        if c == '"':
            i += 1
            while i < n and src[i] != '"':
                if src[i] == "\\":
                    i += 2
                    continue
                i += 1
            i += 1
            continue
        if c == "/" and i + 1 < n and src[i + 1] == "/":
            newline = src.find("\n", i)
            i = n if newline < 0 else newline
            continue
        if c == "/" and i + 1 < n and src[i + 1] == "*":
            end = src.find("*/", i + 2)
            i = n if end < 0 else end + 2
            continue
        if c == "{":
            depth += 1
        elif c == "}":
            depth -= 1
            if depth == 0:
                return src[start_brace + 1 : i + 1]
        i += 1
    raise FormalError("unbalanced brace while extracting a function")


def _extract_at(src: str, marker: str) -> str:
    at = src.find(marker)
    if at < 0:
        raise FormalError(f"missing {marker}")
    brace = src.find("{", at)
    if brace < 0:
        raise FormalError(f"missing body after {marker}")
    return src[at : brace + 1] + _scan_block(src, brace)


def _order(text: str, snippets: Sequence[str], label: str, problems: list[str]) -> None:
    pos = 0
    for snippet in snippets:
        found = text.find(snippet, pos)
        if found < 0:
            problems.append(f"{label}: missing {snippet!r}")
            return
        pos = found + len(snippet)


def correspond(root: Path = ROOT) -> None:
    """Fail when the Rust control flow no longer matches the model assumptions."""

    problems: list[str] = []
    text = {rel: (root / rel).read_text() for rel in CORRESPOND_FILES}
    server = text["src/handshake/server.rs"]
    client = text["src/handshake/client.rs"]
    runtime = text["src/client/runtime.rs"]
    quic_client = text["src/tls/quic/handshake.rs"]
    quic_server = text["src/tls/quic/server.rs"]
    zero_rtt = text["src/transport/udp/zero_rtt.rs"]
    session = text["src/crypto/session.rs"]
    pq = text["src/crypto/pq.rs"]
    replay = text["src/crypto/replay.rs"]
    probe_src = text["src/transport/udp/probe.rs"]
    conn = text["src/transport/udp/quic/conn.rs"]
    bbr = text["src/transport/udp/quic/congestion.rs"]
    packet = text["src/transport/udp/quic/packet.rs"]
    command = text["src/protocol/command.rs"]
    data = text["src/protocol/data.rs"]

    reserve = _extract_fn(session, "reserve")
    _order(reserve, ("self.ensure_usable()?", ".checked_add(count)", "self.next = end", "Ok(base)"),
           "record sequence reservation consumes its checked range before returning", problems)
    reset = _extract_fn(session, "reset_for_rekey")
    if reset[reset.index("{") + 1 : reset.rfind("}")].strip() != "self.next = 0;":
        problems.append("record rekey must reset the counter without clearing poison")
    batch = _extract_fn(data, "seal_records_into_parallel")
    _order(batch, ("self.ensure_seal_budget(record_count)?", "self.aead.reserve_sequence(record_count as u64)?",
                   "pool.run_ordered(jobs)", "self.aead.poison();", "return Err(err)",
                   "out.extend_from_slice(segment)"),
           "record batch reserves before dispatch and rejects failures before publication", problems)
    push = _extract_fn(command, "push")
    _order(push, ("FramedChunk::decode_ref(chunk)?", "total_len > cap", "FramedChunkError::InconsistentTotal",
                  "chunk.offset as usize != self.assembled.len()", "self.assembled.extend_from_slice(chunk.bytes)",
                  "self.assembled.len() == total_len", "self.expected_total = None",
                  "std::mem::take(&mut self.assembled)"),
           "framed reassembly validates before append and clears state before emission", problems)

    mux = _extract_fn(server, "process_server_mux_frame")
    mux_open = _extract_at(mux, "MuxFrameKind::Open =>")
    _order(mux_open, ("streams.prune_finished()", "streams.uploads.contains_key", "streams.tasks.contains_key",
                      "downlink.reset_unregistered", "return Ok(())", "streams.live_count() >= context.max_streams",
                      "downlink.register", "tokio::spawn", "streams.uploads.insert", "streams.tasks.insert"),
           "MUX Open rejects duplicates and exhausted live-task capacity before spawning", problems)
    mux_fin = _extract_at(mux, "MuxFrameKind::Fin =>")
    if "streams.uploads.remove(&frame.stream_id)" not in mux_fin or "streams.tasks" in mux_fin or ".abort(" in mux_fin:
        problems.append("MUX Fin must remove only upload routing and retain the live supervisor slot")
    mux_reset = _extract_at(mux, "MuxFrameKind::Reset =>")
    _order(mux_reset, ("streams.uploads.remove", "streams.tasks.get", "handle.abort()", "downlink.purge"),
           "MUX Reset requests cancellation and purges without releasing the task slot early", problems)
    if re.search(r"streams\.tasks\.(remove|clear|drain)\s*\(", mux_reset):
        problems.append("MUX Reset cannot remove the task slot before cancellation completes")
    if _extract_at(mux, "MuxFrameKind::Cover =>").strip() != "MuxFrameKind::Cover => {}":
        problems.append("MUX Cover must not change substream lifecycle state")
    live_count = _extract_fn(server, "live_count")
    _order(live_count, ("self.prune_finished()", "self.tasks.len()"),
           "MUX admission counts unfinished supervisors, including half-closed streams", problems)
    prune = _extract_fn(server, "prune_finished")
    _order(prune, ("self.tasks.retain(|_, h| !h.is_finished())", "self.uploads.retain"),
           "MUX pruning releases only completed supervisors before dropping stale routes", problems)
    teardown = _extract_fn(server, "teardown")
    _order(teardown, ("self.uploads.clear()", "handle.abort()", "self.tasks.drain()", "handle.await"),
           "MUX completed teardown awaits aborted supervisors before releasing their targets", problems)
    supervisor = _extract_fn(server, "server_mux_upstream_task")
    _order(supervisor, ("resolve_connect_target(", "connect_outbound_target(", "tune_tcp_stream(",
                        "target.write_all(&initial)", "tokio::try_join!(reader, writer)"),
           "MUX setup and both relay directions remain owned by the stream supervisor", problems)
    if supervisor.count("downlink.reset().await") < 4:
        problems.append("MUX setup resolve/connect/tune/initial-write failure must reset the affected stream")
    identity_read = _extract_fn(runtime, "read_server_identity_payload")
    _order(identity_read, ("server_records.read_record_into(&mut record).await?",
                           "data_session.open_server_record_in_place(&mut record)?", "ServerIdentityChunk::decode_ref(&record)",
                           "total_len > MAX_SERVER_IDENTITY_PAYLOAD", "Some(expected) if expected != total_len",
                           "chunk.offset as usize != assembled.len()", "assembled.extend_from_slice(chunk.bytes)",
                           "assembled.len() == total_len", "return Ok(assembled)"),
           "PX1I caller authenticates and validates capacity/total/offset before completion", problems)
    establish = _extract_fn(runtime, "establish_authenticated_data_session_with_resolver")
    _order(establish, ("match timeout(", "CLIENT_ESTABLISH_TIMEOUT", "establish_authenticated_data_session_inner(",
                       "Err(_) => Err", "io::ErrorKind::TimedOut"),
           "PX1I caller and verification remain inside one establishment deadline", problems)

    if "FallbackReason::Replay" in server:
        problems.append(
            "src/handshake/server.rs now constructs FallbackReason::Replay; "
            "update the modeled early pending-splice and late PQ-commit-close branches"
        )

    inbound = _extract_fn(server, "handle_connection_inner")
    authenticated = _extract_at(inbound, "ConnectionDecision::Authenticated(authenticated) =>")
    _order(authenticated, ("cache.gate.try_lock()", "cache.reserve_pending(&entry, now)",
                            "if !fresh", "return relay_admitted_fallback(",
                            "Some(PendingReplayEntry", "reserved: true", "accept_authenticated_with_origin("),
           "early pending admission refuses through origin splice before authenticated establishment", problems)
    refuse_pending = _extract_at(authenticated, "if !fresh")
    if "return relay_admitted_fallback(" not in refuse_pending:
        problems.append("early pending refusal must return the admitted origin fallback")
    if "Err(std::sync::TryLockError::WouldBlock) => false" not in authenticated:
        problems.append("a busy replay-cache lock must refuse early pending admission")
    pending_gate = _extract_fn(replay, "reserve_pending")
    _order(pending_gate, ("self.prune_expired(now)",
                          "self.pending_transcripts.len() >= self.capacity.max(1)", "return false",
                          "self.is_fresh(entry.timestamp, now)", "!self.nonces.contains(&entry.nonce)",
                          "!self.transcripts.contains(&entry.transcript_fingerprint)",
                          ".pending_transcripts", ".insert(entry.transcript_fingerprint)"),
           "pending gate checks capacity, freshness, committed replay, then reserves a unique in-flight transcript", problems)

    inner = _extract_fn(runtime, "establish_authenticated_data_session_inner")
    _order(
        inner,
        (
            "connect_and_establish_data_session(",
            "build_pq_rekey_record(",
            "apply_server_key_exchange_after_residuals(",
            "read_server_identity_payload(&mut server, &mut data_session).await?",
            "verify_server_identity_payload_blocking(",
        ),
        "client establish order",
        problems,
    )
    if "build_connect_record(" in inner:
        problems.append(
            "build_connect_record moved into establish_authenticated_data_session_inner, "
            "before the caller can rely on identity verification having returned"
        )
    handler = _extract_fn(runtime, "handle_local_connection_with_cid")
    _order(
        handler,
        (
            "establish_authenticated_data_session_with_resolver(",
            "build_connect_record(",
        ),
        "CONNECT after establish",
        problems,
    )

    data_mode = _extract_fn(server, "run_authenticated_data_mode")
    _order(
        data_mode,
        (
            "let pq_rekey = match PqRekeyRequest::decode_ref(",
            "if !commit_pending_replay_entry",
            "return Ok(())",
            "apply_server_pq_rekey(",
        ),
        "replay commit in run_authenticated_data_mode returns before apply_server_pq_rekey",
        problems,
    )
    identity_at = data_mode.find("write_server_identity_chunks(")
    data_at = data_mode.find("read_record_into(", identity_at if identity_at >= 0 else 0)
    rekey_at = data_mode.find("apply_server_pq_rekey(")
    if not (0 <= rekey_at < identity_at < data_at):
        problems.append(
            "server data-mode read must stay after PQ rekey and the identity flight"
        )
    entry = _extract_fn(server, "handle_connection")
    if "shared_replay_cache(" not in entry or "Some(replay_cache)" not in entry:
        problems.append(
            "handle_connection must pass in the shared replay cache, as run() passes its cache"
        )
    shared = _extract_fn(server, "shared_replay_cache")
    _order(
        shared,
        (
            ".entry(key)",
            "initialize_shared_replay_cache(slot,",
            "load_or_create_authenticated_with_window(",
        ),
        "direct callers publish one initialization slot before loading the journal",
        problems,
    )
    initialize = _extract_fn(server, "initialize_shared_replay_cache")
    _order(
        initialize,
        (
            "tokio::task::spawn_blocking(move ||",
            "slot.lock()",
            "initialized.as_ref()",
            "return Ok(Arc::clone(cache))",
            "load()?",
            "*initialized = Some(Arc::clone(&cache))",
        ),
        "journal load and publication stay under the blocking task's single-flight lock",
        problems,
    )
    commit_fn = _extract_fn(server, "commit_pending_replay_entry")
    if "return Ok(true)" in commit_fn or "return Ok(false)" not in commit_fn:
        problems.append(
            "a missing replay cache must fail closed; it is not a fresh insert"
        )

    rekey = _extract_fn(client, "apply_pq_rekey_shared")
    _order(
        rekey,
        (
            "seal_to_server",
            ".rekey_with_suite(",
            "open_from_server",
            ".rekey_with_suite(",
            "self.keys = next_keys",
        ),
        "client rekey is atomic",
        problems,
    )
    if "saturating_add(1)" not in rekey:
        problems.append("client rekey no longer steps the epoch by one")
    bound = _extract_fn(client, "apply_pq_rekey_shared_with_identity_binding")
    _order(
        bound,
        ("apply_pq_rekey_shared(", "pq_identity_binding = Some"),
        "binding is stored after both directions rekey",
        problems,
    )
    verify = _extract_fn(client, "verify_server_identity_payload")
    _order(
        verify,
        (
            "pq_identity_binding",
            "MissingPqIdentityBinding",
            "verify_server_identity(",
        ),
        "identity verify requires the PQ binding",
        problems,
    )
    live_verify = _extract_fn(runtime, "verify_server_identity_payload_blocking")
    _order(
        live_verify,
        (
            "pq_identity_binding()",
            "verify_server_identity(",
        ),
        "live identity check binds pq_identity_binding before verify_server_identity",
        problems,
    )

    server_rekey = _extract_fn(server, "apply_server_pq_rekey")
    _order(
        server_rekey,
        (
            "saturating_add(1)",
            "client_open.rekey_with_suite(",
            "server_seal.rekey_with_suite(",
            "Ok(next_keys)",
        ),
        "server rekey steps both directions together",
        problems,
    )
    decision = _extract_fn(server, "authenticated_decision")
    _order(
        decision,
        (
            "FallbackReason::AuthFailed",
            "FallbackReason::MissingSni",
            "FallbackReason::UnauthorizedSni",
            "ConnectionDecision::Authenticated",
        ),
        "SNI and auth failures fall back before Authenticated",
        problems,
    )
    _order(
        decision,
        (
            "auth.timestamp",
            "auth.nonce",
            "auth.sni",
            "is_authorized_sni(",
            "ConnectionDecision::Authenticated",
        ),
        "inbound gates run auth material, then SNI, then authorization",
        problems,
    )
    inbound = _extract_fn(server, "decide_connection_inbound")
    if "Fallback(FallbackReason::AuthFailed)" not in inbound:
        problems.append("decide_connection_inbound no longer falls back on auth failure")
    if inbound.find("Fallback(FallbackReason::AuthFailed)") > inbound.find(
        "authenticated_decision("
    ):
        problems.append("auth failure is no longer decided before authenticated_decision")

    replay_fn = _extract_fn(server, "insert_replay_entry_blocking")
    for snippet in (
        "ReplayInsertOutcome::Inserted => true",
        "ReplayInsertOutcome::Replayed | ReplayInsertOutcome::Stale => false",
        "ReplayInsertOutcome::CacheFull =>",
    ):
        if snippet not in replay_fn:
            problems.append(f"replay outcome mapping changed: missing {snippet}")

    derive = _extract_fn(session, "derive_keys_from_shared")
    _order(
        derive,
        ("ct_eq(&[0u8; KEY_LEN])", "DegenerateSharedSecret", "expand_epoch_keys("),
        "degenerate X25519 shared secret is rejected before keys are expanded",
        problems,
    )
    sandwich = _extract_fn(pq, "hybrid_sandwich_rekey")
    _order(
        sandwich,
        ("ct_eq(&[0_u8; 32])", "DegenerateSharedSecret"),
        "hybrid rekey rejects an all-zero X25519 shared secret",
        problems,
    )

    client_hs = _extract_fn(quic_client, "process_message")
    _order(
        client_hs,
        (
            "ReadState::ServerHello, HANDSHAKE_SERVER_HELLO",
            "ReadState::EncryptedExtensions",
            "self.psk_accepted",
            "ReadState::Finished",
            "ReadState::Certificate",
            "HANDSHAKE_CERTIFICATE",
            "HANDSHAKE_COMPRESSED_CERTIFICATE",
            "ReadState::CertificateVerify",
            "ReadState::Finished, HANDSHAKE_FINISHED",
            "ReadState::Complete",
            "HANDSHAKE_NEW_SESSION_TICKET",
            "ALERT_UNEXPECTED_MESSAGE",
        ),
        "QUIC client handshake order",
        problems,
    )
    psk_branch = (
        "if self.psk_accepted {\n"
        "                    ReadState::Finished\n"
        "                } else {\n"
        "                    ReadState::Certificate\n"
        "                }"
    )
    if psk_branch not in client_hs:
        problems.append(
            "PSK resumption must take Finished in the true branch of `if self.psk_accepted` "
            "and Certificate in the else branch"
        )
    server_hs = _extract_fn(quic_server, "process_message")
    _order(
        server_hs,
        (
            "ServerState::ExpectClientHello, HANDSHAKE_CLIENT_HELLO",
            "ServerState::ExpectClientFinished",
            "ServerState::ExpectClientFinished, HANDSHAKE_FINISHED",
            "self.handshake_complete = true",
            "self.issue_session_ticket()",
            "ALERT_UNEXPECTED_MESSAGE",
        ),
        "QUIC server handshake order",
        problems,
    )
    accept_psk = _extract_fn(quic_server, "try_accept_psk")
    _order(
        accept_psk,
        ("expected.ct_eq(binder)", "accept_ticket(", "Some(ticket.psk)"),
        "0-RTT guard runs only after the binder check",
        problems,
    )

    ticket = _extract_fn(zero_rtt, "accept_ticket")
    some_at = ticket.find("Some(cache) =>")
    none_at = ticket.find("None =>", some_at if some_at >= 0 else 0)
    some_arm = ticket[some_at:none_at] if 0 <= some_at < none_at else ""
    if "== ReplayInsertOutcome::Inserted" not in some_arm:
        problems.append(
            "0-RTT Some(cache) arm must accept only `== ReplayInsertOutcome::Inserted`"
        )
    for snippet in ("Err(_) => false", "None => false"):
        if snippet not in ticket:
            problems.append(f"0-RTT accept_ticket no longer fail-closed: missing {snippet}")

    probe = _extract_fn(runtime, "run_client_udp_probe")
    _order(
        probe,
        (
            ".take()",
            "connect_resumption_0rtt_with_dcid(",
            "probe_client_send_request_early(",
            "wait_established()",
            "probe_client_read_and_verify(",
            "probe_client_over_bidi(",
            "ProbeOutcome::Verified",
            "is_safari26_settings(&settings)",
            "take_session_ticket(",
        ),
        "0-RTT probe verifies, then Safari SETTINGS, and only then takes a session ticket",
        problems,
    )
    verified = probe.find("ProbeOutcome::Verified")
    retained_none = probe.find("retained: None", verified if verified >= 0 else 0)
    if verified < 0 or retained_none < 0:
        problems.append("UDP probe failure no longer drops the retained QUIC leg")

    stage = _extract_fn(replay, "stage_insert")
    _order(
        stage,
        (
            "self.prune_expired(now)",
            "ReplayInsertOutcome::Stale",
            "self.nonces.insert(entry.nonce)",
            "ReplayInsertOutcome::Replayed",
            "self.transcripts.insert(entry.transcript_fingerprint)",
            "self.nonces.remove(&entry.nonce)",
            "ReplayInsertOutcome::Replayed",
            "self.order.len() >= self.capacity",
            "self.transcripts.remove(&entry.transcript_fingerprint)",
            "ReplayInsertOutcome::CacheFull",
            "ReplayInsertOutcome::Inserted",
        ),
        "replay insert order is prune, stale, nonce, transcript rollback, capacity rollback",
        problems,
    )
    for fn_name in ("insert_new_outcome", "insert_new_outcome_deferred"):
        body = _extract_fn(replay, fn_name)
        if fn_name == "insert_new_outcome" and "insert_new_outcome_deferred" in body.split("{", 1)[0]:
            problems.append("fn insert_new_outcome bound the deferred function")
        _order(
            body,
            ("self.capacity == 0", "ReplayInsertOutcome::Inserted", "self.stage_insert("),
            f"{fn_name} reports Inserted before staging when protection is off",
            problems,
        )

    classify = _extract_fn(probe_src, "classify_probe_reply")
    chain = (
        "reply.len() == PROBE_RESPONSE_WIRE_LEN\n"
        "        && &reply[..4] == PROBE_RESPONSE_MAGIC\n"
        "        && bool::from(reply[4..].ct_eq(&expected[..]))"
    )
    if chain not in classify:
        problems.append(
            "classify_probe_reply must be one && chain of length, magic, and MAC"
        )
    if "ProbeOutcome::Failed" not in classify.split(chain, 1)[-1]:
        problems.append("a probe reply that fails the && chain must be Failed")
    read_verify = _extract_fn(probe_src, "probe_client_read_and_verify")
    _order(
        read_verify,
        (
            "Err(_) => Ok(ProbeOutcome::Unreachable)",
            "ProbeError::ConnectionLost",
            "Ok(ProbeOutcome::Unreachable)",
            "classify_probe_reply(",
        ),
        "0-RTT probe read treats timeout and connection loss as Unreachable",
        problems,
    )
    bidi = _extract_fn(probe_src, "probe_client_over_bidi")
    _order(
        bidi,
        (
            "Err(_) => Ok(ProbeOutcome::Unreachable)",
            "ProbeError::ConnectionLost",
            "Ok(ProbeOutcome::Unreachable)",
            "classify_probe_reply(",
        ),
        "probe timeout and connection loss are Unreachable, before reply classification",
        problems,
    )
    retention = _extract_at(server, "fn udp_retention_decision(")
    _order(
        retention,
        (
            "(Some(UdpProbeStatus::Verified), true) => UdpRetentionDecision::Retain",
            "(Some(UdpProbeStatus::Verified), false) => UdpRetentionDecision::HardFail",
            "_ => UdpRetentionDecision::StayOnTcp",
        ),
        "QUIC is retained only for Verified while the probed connection is held",
        problems,
    )

    client_write = _extract_fn(quic_client, "write_handshake")
    _order(
        client_write,
        (
            "client_hello_sent",
            "pending_0rtt_keys.take()",
            "KeyChange::ZeroRtt",
            "pending_handshake_keys.take()",
            "KeyChange::Handshake",
            "pending_client_finished.take()",
            "pending_1rtt_keys",
            "KeyChange::OneRtt",
        ),
        "client installs 0-RTT, then Handshake keys, then 1-RTT keys",
        problems,
    )
    server_write = _extract_fn(quic_server, "write_handshake")
    _order(
        server_write,
        (
            "pending_0rtt_keys.take()",
            "KeyChange::ZeroRtt",
            "pending_server_hello.take()",
            "pending_handshake_keys.take()",
            "KeyChange::Handshake",
            "pending_handshake_flight.take()",
            "pending_1rtt_keys",
            "KeyChange::OneRtt",
            "pending_post_handshake",
        ),
        "server installs 0-RTT before ServerHello, then Handshake keys, then 1-RTT keys, then the ticket",
        problems,
    )

    local_close = _extract_at(conn, "pub fn close(")
    _order(
        local_close,
        ("if self.closed.is_some()", "return;", "CloseReason::LocalApp"),
        "a second local close does not replace the first reason",
        problems,
    )
    transport_close = _extract_at(conn, "pub fn close_transport(")
    _order(
        transport_close,
        ("if self.closed.is_some()", "return;", "CloseReason::LocalTransport"),
        "a second transport close does not replace the first reason",
        problems,
    )
    transmit = _extract_fn(conn, "poll_transmit_inner")
    _order(
        transmit,
        (
            "if self.closed.is_some()",
            "self.close_pending.is_some() && !self.close_sent",
            "build_close_packet(",
            "return None",
            "build_stream_packet(",
        ),
        "a closed connection sends at most the close packet, and no stream data",
        problems,
    )
    timeout = _extract_fn(conn, "handle_timeout")
    _order(
        timeout,
        (
            "if self.closed.is_some()",
            "self.drained = true",
            "return;",
            "CloseReason::IdleTimeout",
        ),
        "drain completes before any later timeout can idle-close or probe",
        problems,
    )
    peer_close = conn.find("Frame::Close(c) =>")
    peer_end = conn.find("// PING and every other", peer_close if peer_close >= 0 else 0)
    peer_block = conn[peer_close:peer_end] if peer_close >= 0 and peer_end > peer_close else ""
    if "self.closed.is_none()" not in peer_block or "self.close(" in peer_block:
        problems.append(
            "peer CONNECTION_CLOSE must enter draining without calling self.close("
        )

    loss = _extract_at(bbr, "fn on_congestion_event(&mut self, _now: Instant)")
    if "self.mode" in loss:
        problems.append("BBR on_congestion_event now assigns self.mode")
    rounds = _extract_fn(bbr, "on_round_start")
    _order(
        rounds,
        (
            "self.btlbw as f64 >= self.full_bw as f64 * BBR_FULL_BW_THRESHOLD",
            "self.full_bw_count = 0",
            "self.full_bw_count += 1",
            "self.filled_pipe = true",
            "self.mode = BbrMode::ProbeBw",
            "self.probe_bw_phase = 2",
            "self.last_probe_rtt = Some(now)",
        ),
        "a zero sample takes the growth branch, and the fill ack seeds the ProbeRTT clock",
        problems,
    )
    probe_rtt = _extract_fn(bbr, "check_probe_rtt")
    _order(
        probe_rtt,
        (
            "BbrMode::ProbeRtt",
            "self.mode = if self.filled_pipe",
            "BbrMode::ProbeBw",
            "BbrMode::Startup",
            "if due && self.filled_pipe",
            "self.mode = BbrMode::ProbeRtt",
        ),
        "ProbeRTT is entered only when the pipe is full and returns to ProbeBW",
        problems,
    )
    ack = _extract_at(bbr, "fn on_ack(&mut self, info: &AckInfo) {")
    _order(
        ack,
        ("if !info.app_limited", "on_round_start(", "}", "self.check_probe_rtt("),
        "check_probe_rtt runs after the app-limited block closes",
        problems,
    )

    space = _extract_fn(packet, "first_packet_space")
    _order(
        space,
        (
            "datagram.first()?",
            "FIXED_BIT",
            "return None",
            "LONG_HEADER_FORM",
            "PacketSpace::OneRtt",
            "LongType::from_first_byte",
            "LongType::Initial",
            "PacketSpace::Initial",
            "LongType::ZeroRtt",
            "PacketSpace::ZeroRtt",
            "LongType::Handshake",
            "PacketSpace::Handshake",
            "LongType::Retry => None",
        ),
        "first-byte space is fixed bit, then short header, then long type; Retry is not a space",
        problems,
    )
    kind_bits = _extract_fn(packet, "from_first_byte")
    _order(
        kind_bits,
        (
            "0x00 => LongType::Initial",
            "0x10 => LongType::ZeroRtt",
            "0x20 => LongType::Handshake",
            "LongType::Retry",
        ),
        "long-header type bits",
        problems,
    )

    _order(
        _extract_fn(command, "to_byte"),
        ("Self::Verified => 0", "Self::Unreachable => 1", "Self::Failed => 2"),
        "probe status bytes",
        problems,
    )
    _order(
        _extract_fn(command, "from_byte"),
        (
            "0 => Ok(Self::Verified)",
            "1 => Ok(Self::Unreachable)",
            "2 => Ok(Self::Failed)",
            "UdpProbeAckError::InvalidStatus",
        ),
        "probe status decode",
        problems,
    )

    if problems:
        raise FormalError("source no longer matches the formal model:\n- " + "\n- ".join(problems))


def run_tlc(jar: Path) -> None:
    if not jar.is_file():
        raise FormalError(f"TLA+ tools jar not found: {jar}")
    specs = []
    for machine in machines():
        tla, cfg = emitted_paths(machine)
        if not tla.is_file() or not cfg.is_file():
            raise FormalError(f"missing {tla.name}; run emit first")
        specs.append((machine, tla, cfg))
    # One JVM per machine, started together. Each graph is tiny, so extra TLC
    # workers inside one model only add overhead; -workers stays 1. -deadlock
    # tells TLC not to treat an intentional terminal as a deadlock. The Python
    # checker still rejects a dead end that misses the machine's terminal formula.
    # ParallaXBbr has no terminal state, so a stuck mode fails in Python and a
    # cycle is expected in TLC.
    metas: list[tempfile.TemporaryDirectory[str]] = []
    procs: list[tuple[Machine, subprocess.Popen[str]]] = []
    try:
        for machine, tla, cfg in specs:
            meta = tempfile.TemporaryDirectory(prefix=f"tlc-{machine.name}-")
            metas.append(meta)
            cmd = [
                "java",
                "-XX:+UseParallelGC",
                "-XX:TieredStopAtLevel=1",
                "-Xms32m",
                "-Xmx256m",
                # TLC extracts Integers.tla into java.io.tmpdir. Parallel JVMs
                # sharing that directory race and fail module lookup.
                f"-Djava.io.tmpdir={meta.name}",
                "-jar",
                str(jar),
                "-deadlock",
                "-nowarning",
                "-workers",
                "1",
                "-metadir",
                meta.name,
                "-config",
                str(cfg),
                str(tla),
            ]
            procs.append(
                (
                    machine,
                    subprocess.Popen(
                        cmd,
                        cwd=ROOT,
                        text=True,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                    ),
                )
            )
        errors = []
        for machine, proc in procs:
            stdout, stderr = proc.communicate()
            sys.stdout.write(stdout)
            sys.stderr.write(stderr)
            if proc.returncode != 0:
                errors.append(f"TLC failed on {machine.name} (exit {proc.returncode})")
            elif "Model checking completed. No error has been found." not in stdout:
                errors.append(f"TLC did not report success for {machine.name}")
        if errors:
            raise FormalError("\n".join(errors))
    finally:
        for meta in metas:
            meta.cleanup()


def _print_report(report: Report) -> None:
    print(
        f"{report.name}: {report.states} reachable states, "
        f"{report.terminals} terminal states"
    )
    for name in report.invariant_names:
        print(f"  proved  {name}")
    for name in report.witness_names:
        print(f"  saw     {name}")


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "command",
        nargs="?",
        default="check",
        choices=("check", "correspond", "emit", "tlc", "all"),
    )
    parser.add_argument(
        "--jar",
        type=Path,
        help="explicit trusted path to tla2tools.jar (required for tlc and all)",
    )
    args = parser.parse_args(argv)
    if args.command in ("tlc", "all") and args.jar is None:
        parser.error("tlc and all require --jar with an explicitly selected trusted jar")
    try:
        if args.command == "emit":
            for path in emit_files():
                print(f"wrote {path.relative_to(ROOT)}")
            return 0
        if args.command == "correspond":
            correspond()
            print("correspondence: rust control flow matches the model")
            return 0
        if args.command == "tlc":
            run_tlc(args.jar)
            print("TLC: no error found")
            return 0
        if args.command == "check":
            for report in check_all():
                _print_report(report)
            print("TLA+ files match the model tables")
            return 0
        for report in check_all():
            _print_report(report)
        print("TLA+ files match the model tables")
        correspond()
        print("correspondence: rust control flow matches the model")
        run_tlc(args.jar)
        print("TLC: no error found")
        return 0
    except FormalError as exc:
        print(f"formal: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
