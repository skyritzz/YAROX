"""
Sigma ``condition`` expression parsing and evaluation (Phase 16 / D-3).

Deliberately kept separate from ``rules/sigma/engine.py`` (rule loading,
field mapping) and from ``detection/rules.py`` (YAROX's native Python
detection rules) — this module knows nothing about events, fields, or
YAROX's canonical schema. It only parses a Sigma ``condition`` string into
an AST and evaluates that AST against a dict of already-computed
per-selection booleans ({"selection1": True, "filter": False, ...}).

Supported grammar (a documented subset of the real Sigma spec — see
docs/PHASE_16_SIGMA_ENGINE.md "Supported Sigma syntax" for the full list):

    condition     := or_expr
    or_expr       := and_expr ("or" and_expr)*
    and_expr      := not_expr ("and" not_expr)*
    not_expr      := "not" not_expr | atom
    atom          := "(" or_expr ")" | quantifier | NAME
    quantifier    := ("1" | "all") "of" (NAME_PATTERN | "them")

Not supported (raises ``UnsupportedConditionError`` explicitly — never
silently ignored or treated as an always-true/always-false match): Sigma's
newer "near", cross-file "correlation" conditions, and anything not covered
by the grammar above.
"""
import re
from dataclasses import dataclass
from fnmatch import fnmatch
from typing import Dict, List, Union


class SigmaConditionError(ValueError):
    """Base for any problem parsing or evaluating a condition string."""


class UnsupportedConditionError(SigmaConditionError):
    """Raised for syntactically-recognizable but explicitly unsupported constructs
    (e.g. Sigma's 'near'/correlation conditions) — distinct from a plain syntax
    error, so callers can report *why* a rule is unsupported precisely."""


_TOKEN_RE = re.compile(r"""
    \s*(?:
        (?P<lparen>\()
      | (?P<rparen>\))
      | (?P<and>\band\b)
      | (?P<or>\bor\b)
      | (?P<not>\bnot\b)
      | (?P<of>\bof\b)
      | (?P<them>\bthem\b)
      | (?P<number>\d+)
      | (?P<name>[A-Za-z_][A-Za-z0-9_*]*)
    )
""", re.VERBOSE | re.IGNORECASE)

_UNSUPPORTED_KEYWORDS = ("near", "|", "count(", "correlate")


# ---- AST nodes --------------------------------------------------------

@dataclass(frozen=True)
class _Name:
    name: str


@dataclass(frozen=True)
class _Not:
    operand: "ConditionNode"


@dataclass(frozen=True)
class _And:
    left: "ConditionNode"
    right: "ConditionNode"


@dataclass(frozen=True)
class _Or:
    left: "ConditionNode"
    right: "ConditionNode"


@dataclass(frozen=True)
class _Quantifier:
    """'1 of selection*' / 'all of them' etc."""
    require_all: bool
    pattern: str  # a glob pattern (e.g. 'selection*') or '*' for 'them'


ConditionNode = Union[_Name, _Not, _And, _Or, _Quantifier]


def _tokenize(condition: str) -> List[str]:
    tokens: List[str] = []
    pos = 0
    lowered = condition.lower()
    for bad in _UNSUPPORTED_KEYWORDS:
        if bad in lowered:
            raise UnsupportedConditionError(f"condition uses an unsupported construct: {bad!r} in {condition!r}")
    while pos < len(condition):
        m = _TOKEN_RE.match(condition, pos)
        if not m or m.end() == pos:
            remainder = condition[pos:].strip()
            if not remainder:
                break
            raise SigmaConditionError(f"could not tokenize condition at {remainder!r} in {condition!r}")
        pos = m.end()
        kind = m.lastgroup
        text = m.group(kind)
        if kind in ("and", "or", "not", "of", "them"):
            tokens.append(text.lower())
        elif kind in ("lparen", "rparen", "number", "name"):
            tokens.append(text)
    return tokens


class _Parser:
    def __init__(self, tokens: List[str]):
        self.tokens = tokens
        self.pos = 0

    def _peek(self):
        return self.tokens[self.pos] if self.pos < len(self.tokens) else None

    def _advance(self):
        tok = self._peek()
        self.pos += 1
        return tok

    def _expect(self, expected: str):
        tok = self._advance()
        if tok != expected:
            raise SigmaConditionError(f"expected {expected!r}, got {tok!r}")

    def parse(self) -> ConditionNode:
        node = self._or_expr()
        if self.pos != len(self.tokens):
            raise SigmaConditionError(f"unexpected trailing tokens: {self.tokens[self.pos:]}")
        return node

    def _or_expr(self) -> ConditionNode:
        node = self._and_expr()
        while self._peek() == "or":
            self._advance()
            node = _Or(node, self._and_expr())
        return node

    def _and_expr(self) -> ConditionNode:
        node = self._not_expr()
        while self._peek() == "and":
            self._advance()
            node = _And(node, self._not_expr())
        return node

    def _not_expr(self) -> ConditionNode:
        if self._peek() == "not":
            self._advance()
            return _Not(self._not_expr())
        return self._atom()

    def _atom(self) -> ConditionNode:
        tok = self._peek()
        if tok is None:
            raise SigmaConditionError("unexpected end of condition")
        if tok == "(":
            self._advance()
            node = self._or_expr()
            self._expect(")")
            return node
        if tok.isdigit() or tok == "all":
            return self._quantifier()
        self._advance()
        return _Name(tok)

    def _quantifier(self) -> ConditionNode:
        head = self._advance()  # '1' or 'all'
        if head == "1":
            require_all = False
        elif head == "all":
            require_all = True
        else:
            raise SigmaConditionError(f"expected '1' or 'all' before 'of', got {head!r}")
        self._expect("of")
        target = self._advance()
        if target == "them":
            return _Quantifier(require_all=require_all, pattern="*")
        if target is None:
            raise SigmaConditionError("expected a selection name or 'them' after 'of'")
        return _Quantifier(require_all=require_all, pattern=target)


def parse_condition(condition: str) -> ConditionNode:
    """Raises SigmaConditionError (or its subclass UnsupportedConditionError) on
    anything outside the documented grammar — never silently accepted."""
    if not isinstance(condition, str) or not condition.strip():
        raise SigmaConditionError("condition must be a non-empty string")
    return _Parser(_tokenize(condition)).parse()


def evaluate_condition(node: ConditionNode, selection_results: Dict[str, bool]) -> bool:
    """``selection_results`` must already contain every named selection the rule
    defines (computed by the caller — this function does no field matching)."""
    if isinstance(node, _Name):
        if node.name not in selection_results:
            raise SigmaConditionError(f"condition references undefined selection '{node.name}'")
        return selection_results[node.name]
    if isinstance(node, _Not):
        return not evaluate_condition(node.operand, selection_results)
    if isinstance(node, _And):
        return evaluate_condition(node.left, selection_results) and evaluate_condition(node.right, selection_results)
    if isinstance(node, _Or):
        return evaluate_condition(node.left, selection_results) or evaluate_condition(node.right, selection_results)
    if isinstance(node, _Quantifier):
        matching_names = [name for name in selection_results if fnmatch(name, node.pattern)]
        if not matching_names:
            raise SigmaConditionError(f"quantifier pattern {node.pattern!r} matched no defined selections")
        values = [selection_results[name] for name in matching_names]
        return all(values) if node.require_all else any(values)
    raise SigmaConditionError(f"unknown condition AST node: {node!r}")
