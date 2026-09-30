"""Aegis case query language: tokenizer, parser, field registry and AST.

Turns the Operations Overview search text into a validated, normalised
query tree. This module is pure -- no Flask, no database, no SQL. The tree
is compiled to parameterised SQL by case_service.py, which owns the one
field -> SQL mapping.

Two modes, decided per search:

  * Free text: the input contains no field expression (``severity:HIGH``,
    ``created:>=2026-09-01``, ``random_field:x``). The whole input is one
    legacy phrase search, so ``command and control`` is never read as
    Boolean logic.
  * Structured: at least one field expression is present. Then AND / OR /
    NOT (any case) and parentheses are operators, adjacent terms are ANDed,
    and each run of bare words is one contains-phrase
    (``PowerShell severity:HIGH`` = phrase "PowerShell" AND severity HIGH).

Grammar (structured mode)::

    query      := or_expr
    or_expr    := and_expr ( OR and_expr )*
    and_expr   := not_expr ( AND? not_expr )*
    not_expr   := NOT not_expr | primary
    primary    := "(" or_expr ")" | field_term | phrase | "quoted phrase"
    field_term := FIELD ":" op? value | FIELD ":(" value ( OR value )* ")"
    op         := ">" | ">=" | "<" | "<=" | "="

Adding a field (e.g. a V2 ``user:``) means one QueryField entry here, one
compiler entry in case_service._TERM_COMPILERS, and tests; the tokenizer
and parser do not change.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Iterator, Union


MAX_QUERY_LENGTH = 1000
MAX_TERMS = 64
MAX_DEPTH = 16

KEYWORDS = ("AND", "OR", "NOT")
# Typed operator -> AST operator. ":" and ":=" both mean equality.
OPERATORS = {"": "eq", "=": "eq", ">": "gt", ">=": "ge", "<": "lt", "<=": "le"}
_OPERATOR_SYMBOLS = {"eq": "", "gt": ">", "ge": ">=", "lt": "<", "le": "<="}
_OPERATOR_SCAN_ORDER = (">=", "<=", ">", "<", "=")
_COMPARISONS = frozenset({"eq", "gt", "ge", "lt", "le"})
_EQUALITY = frozenset({"eq"})


class QueryError(ValueError):
    """A syntax or validation error, positioned in the query text."""

    def __init__(self, message: str, *, start: int = 0, end: int = 0, hint: str = "") -> None:
        super().__init__(message)
        self.message = message
        self.start = start
        self.end = max(end, start)
        self.hint = hint

    def details(self) -> dict[str, Any]:
        return {"param": "query", "start": self.start, "end": self.end, "hint": self.hint}


# ── AST ──────────────────────────────────────────────────────────────────


@dataclass(frozen=True)
class DateValue:
    """A timestamp at the precision it was typed: [start, end) in naive UTC
    "YYYY-MM-DDTHH:MM:SS", the format sync_service stores NetWitness times in."""

    start: str
    end: str
    text: str

    @classmethod
    def at_second(cls, value: str) -> "DateValue":
        start = datetime.strptime(value, "%Y-%m-%dT%H:%M:%S")
        return cls(value, _stamp(start + timedelta(seconds=1)), value)


@dataclass(frozen=True)
class Text:
    """Contains-phrase over the legacy free-text columns (title, assignee, id)."""

    text: str
    span: tuple[int, int] = (0, 0)


@dataclass(frozen=True)
class Term:
    """field <op> value, with the value already normalised by the registry."""

    field: str
    op: str
    value: Any
    span: tuple[int, int] = (0, 0)


@dataclass(frozen=True)
class And:
    items: tuple["Node", ...]


@dataclass(frozen=True)
class Or:
    items: tuple["Node", ...]


@dataclass(frozen=True)
class Not:
    item: "Node"


Node = Union[Text, Term, And, Or, Not]


@dataclass(frozen=True)
class ParsedQuery:
    mode: str  # "empty" | "text" | "structured"
    root: Node | None
    text: str


# ── Field registry ───────────────────────────────────────────────────────


def _fold(value: str) -> str:
    """Spelling-insensitive key: "In Progress" == "in_progress" == "IN-PROGRESS"."""
    value = str(value or "").strip().lower().replace("&", " and ")
    return " ".join(re.split(r"[\s_\-]+", value)).strip()


@dataclass(frozen=True)
class EnumValue:
    key: str              # canonical value handed to the SQL compiler
    token: str            # what analysts type and autocomplete inserts
    label: str            # human-readable label
    stored: str | None = None  # backend-stored value, where it differs from key
    spellings: tuple[str, ...] = ()
    rank: int = 0         # ordering for ordered enums (severity)


@dataclass(frozen=True)
class QueryField:
    name: str
    kind: str             # "id" | "text" | "enum" | "date"
    noun: str             # used in messages: 'Unknown <noun> "x"'
    description: str
    operators: frozenset[str] = _EQUALITY
    values: tuple[EnumValue, ...] = ()
    aliases: tuple[str, ...] = ()
    ordered: bool = False

    def lookup(self, raw: str) -> EnumValue | None:
        wanted = _fold(raw)
        for value in self.values:
            if wanted in {_fold(value.key), _fold(value.token), _fold(value.label),
                          *(_fold(spelling) for spelling in value.spellings)}:
                return value
        return None

    def value_for(self, key: str) -> EnumValue:
        return next(value for value in self.values if value.key == key)

    def expected(self) -> str:
        return "Expected: " + ", ".join(_render_token(value.token) for value in self.values) + "."


_SEVERITY_VALUES = (
    EnumValue("CRITICAL", "CRITICAL", "Critical", rank=4),
    EnumValue("HIGH", "HIGH", "High", rank=3),
    EnumValue("MEDIUM", "MEDIUM", "Medium", rank=2),
    EnumValue("LOW", "LOW", "Low", rank=1),
)

# Analyst-facing workflow state -> incidents.workflow_status as written by
# the workflow engine. stored=None: never entered the workflow (NULL/empty).
_WORKFLOW_STATUS_VALUES = (
    EnumValue("not_started", "Not Started", "Not Started", None),
    EnumValue("in_progress", "In Progress", "In Progress", "Processing", ("processing",)),
    EnumValue("awaiting_action", "Awaiting Action", "Awaiting Action", "Awaiting Action"),
    EnumValue("awaiting_approval", "Awaiting Approval", "Awaiting Approval", "Awaiting Approval"),
    EnumValue("rejected", "Rejected", "Rejected", "Rejected"),
    EnumValue("failed", "Failed", "Failed", "Failed"),
    EnumValue("complete", "Complete", "Complete", "Complete", ("completed",)),
)

# Keys and names match case_service._STAGE_DEFINITIONS (a test enforces it).
_STAGE_VALUES = (
    EnumValue("parsing", "parsing", "Parsing & Normalisation",
              spellings=("parsing and normalization",)),
    EnumValue("triage", "triage", "Triage"),
    EnumValue("threat_intel", "threat_intel", "Threat Intelligence Enrichment",
              spellings=("threat intelligence", "threat intel")),
    EnumValue("investigation", "investigation", "Investigation"),
    EnumValue("reporting", "reporting", "Reporting"),
)

_VERDICT_VALUES = (
    EnumValue("critical", "CRITICAL", "Critical"),
    EnumValue("high", "HIGH", "High"),
    EnumValue("medium", "MEDIUM", "Medium"),
    EnumValue("low", "LOW", "Low"),
    EnumValue("unrated", "UNRATED", "Unrated"),
)

# The only stages with an approval gate (workflow/state_store.py).
_APPROVAL_STAGE_VALUES = (
    EnumValue("triage", "triage", "Triage"),
    EnumValue("investigation", "investigation", "Investigation"),
    EnumValue("reporting", "reporting", "Reporting"),
)

# NetWitness incident `sources` values observed in the case database.
_SOURCE_VALUES = (
    EnumValue("esa", "ESA", "Event Stream Analysis", "Event Stream Analysis"),
    EnumValue("ecat", "ECAT", "ECAT", "ECAT"),
    EnumValue("risk_scoring", "Risk Scoring", "Risk Scoring", "Risk Scoring"),
)

FIELDS: dict[str, QueryField] = {field.name: field for field in (
    QueryField("case", "id", "case", "Exact incident ID, e.g. INC-53027.", aliases=("id",)),
    QueryField("title", "text", "title", "Title contains the text (case-insensitive)."),
    QueryField("severity", "enum", "severity", "NetWitness severity. Order: CRITICAL > HIGH > MEDIUM > LOW.",
               operators=_COMPARISONS, values=_SEVERITY_VALUES, ordered=True),
    QueryField("workflow_status", "enum", "workflow status", "Aegis workflow state.",
               values=_WORKFLOW_STATUS_VALUES),
    QueryField("stage", "enum", "stage", "Current workflow stage.", values=_STAGE_VALUES),
    QueryField("verdict", "enum", "verdict", "Unified Verdict.", values=_VERDICT_VALUES),
    QueryField("approval_stage", "enum", "approval stage", "Stage waiting for analyst approval.",
               values=_APPROVAL_STAGE_VALUES),
    QueryField("source", "enum", "source", "NetWitness incident source.", values=_SOURCE_VALUES),
    QueryField("created", "date", "date", "NetWitness created time (UTC).", operators=_COMPARISONS),
    QueryField("updated", "date", "date", "NetWitness last-updated time (UTC).", operators=_COMPARISONS),
)}

_FIELD_LOOKUP = {name: field for name, field in FIELDS.items()}
_FIELD_LOOKUP.update({alias: field for field in FIELDS.values() for alias in field.aliases})
# Names analysts plausibly type that are deliberately NOT fields; they are
# recognised as field attempts so they get a pointed error, never free text.
FIELD_HINTS = {"status": "workflow_status"}

_DATE_HINT = ("Use YYYY-MM-DD, YYYY-MM-DDTHH:MM or YYYY-MM-DDTHH:MM:SS, optionally ending in "
              "Z or ±HH:MM. Dates without a timezone are interpreted as UTC.")
_DATE_PATTERN = re.compile(
    r"([0-9]{4})-([0-9]{2})-([0-9]{2})"
    r"(?:T([0-9]{2}):([0-9]{2})(?::([0-9]{2}))?(Z|[+-][0-9]{2}:[0-9]{2})?)?"
)


def resolve_field(name: str) -> QueryField | None:
    return _FIELD_LOOKUP.get(name.lower())


def stored_values(field_name: str) -> dict[str, str | None]:
    """Canonical key -> backend-stored value for an enum field."""
    return {value.key: value.stored for value in FIELDS[field_name].values}


def value_keys(field_name: str) -> tuple[str, ...]:
    return tuple(value.key for value in FIELDS[field_name].values)


def _stamp(value: datetime) -> str:
    return value.strftime("%Y-%m-%dT%H:%M:%S")


def parse_date(raw: str) -> DateValue | None:
    """Strict ISO 8601 date/date-time -> DateValue spanning its precision.
    No offset means UTC. Returns None for anything malformed."""
    match = _DATE_PATTERN.fullmatch(raw.strip())
    if not match:
        return None
    year, month, day, hour, minute, second, offset = match.groups()
    try:
        value = datetime(int(year), int(month), int(day), int(hour or 0),
                         int(minute or 0), int(second or 0))
        if offset and offset != "Z":
            sign = 1 if offset[0] == "+" else -1
            hours, minutes = int(offset[1:3]), int(offset[4:6])
            if hours > 23 or minutes > 59:
                return None
            value = value.replace(tzinfo=timezone(sign * timedelta(hours=hours, minutes=minutes)))
            value = value.astimezone(timezone.utc).replace(tzinfo=None)
        step = (timedelta(days=1) if hour is None
                else timedelta(minutes=1) if second is None else timedelta(seconds=1))
        return DateValue(_stamp(value), _stamp(value + step), raw.strip())
    except (ValueError, OverflowError):
        return None


# ── Tokenizer ────────────────────────────────────────────────────────────


@dataclass
class Token:
    kind: str        # FIELD WORD QUOTED LPAREN RPAREN AND OR NOT EOF
    start: int
    end: int
    value: str = ""  # WORD text / QUOTED content / FIELD value
    field: str = ""  # FIELD: name as typed
    op: str = ""     # FIELD: operator as typed ("" for plain ":")
    value_kind: str = ""  # FIELD: "word" | "quoted" | "group" | "" (missing)
    value_start: int = 0  # FIELD: where the value (incl. any opening quote) starts


_WORD_BREAKS = '()"'


def _identifier_end(text: str, start: int) -> int:
    index = start
    if index < len(text) and (text[index].isascii() and (text[index].isalpha() or text[index] == "_")):
        index += 1
        while index < len(text) and text[index].isascii() and (text[index].isalnum() or text[index] == "_"):
            index += 1
    return index


def _is_field_syntax(name: str, following: str) -> bool:
    """`name:` is a field expression when name is a known field (or a hinted
    non-field such as status), or when a value follows the colon directly.
    `Alerts: ESA` (space after the colon) and paths/URLs/IPv6 such as
    `C:\\x`, `http://x`, `fe80::1` stay free text."""
    if resolve_field(name) or name.lower() in FIELD_HINTS:
        return True
    return bool(following) and not following.isspace() and following not in "/\\:)"


def _read_quoted(text: str, start: int, strict: bool) -> tuple[str, int]:
    """Content of the quoted string opening at `start`, and the index after it.
    Backslash escapes \\" and \\\\."""
    chars: list[str] = []
    index = start + 1
    while index < len(text):
        char = text[index]
        if char == "\\" and index + 1 < len(text) and text[index + 1] in '"\\':
            chars.append(text[index + 1])
            index += 2
            continue
        if char == '"':
            return "".join(chars), index + 1
        chars.append(char)
        index += 1
    if strict:
        raise QueryError("Missing closing quote.", start=start, end=len(text),
                         hint='Close the quoted text with ".')
    return "".join(chars), len(text)


def tokenize(text: str, *, strict: bool = True) -> list[Token]:
    """Split query text into tokens. With strict=False it never raises, which
    is what mode detection needs (free text may contain a stray quote)."""
    tokens: list[Token] = []
    index, length = 0, len(text)
    while index < length:
        char = text[index]
        if char.isspace():
            index += 1
        elif char in "()":
            tokens.append(Token("LPAREN" if char == "(" else "RPAREN", index, index + 1))
            index += 1
        elif char == '"':
            value, end = _read_quoted(text, index, strict)
            tokens.append(Token("QUOTED", index, end, value=value))
            index = end
        else:
            name_end = _identifier_end(text, index)
            following = text[name_end + 1] if name_end + 1 < length else ""
            if name_end > index and name_end < length and text[name_end] == ":" \
                    and _is_field_syntax(text[index:name_end], following):
                token, index = _field_token(text, index, name_end, strict)
                tokens.append(token)
                continue
            end = index
            while end < length and not text[end].isspace() and text[end] not in _WORD_BREAKS:
                end += 1
            word = text[index:end]
            kind = word.upper() if word.upper() in KEYWORDS else "WORD"
            tokens.append(Token(kind, index, end, value=word))
            index = end
    tokens.append(Token("EOF", length, length))
    return tokens


def _field_token(text: str, start: int, name_end: int, strict: bool) -> tuple[Token, int]:
    token = Token("FIELD", start, name_end + 1, field=text[start:name_end])
    index = name_end + 1
    for symbol in _OPERATOR_SCAN_ORDER:
        if text.startswith(symbol, index):
            token.op = symbol
            index += len(symbol)
            break
    token.value_start = index
    if index < len(text) and text[index] == '"':
        token.value, index = _read_quoted(text, index, strict)
        token.value_kind = "quoted"
    elif index < len(text) and text[index] == "(":
        token.value_kind = "group"
        index += 1
    elif index < len(text) and not text[index].isspace() and text[index] not in _WORD_BREAKS:
        end = index
        while end < len(text) and not text[end].isspace() and text[end] not in _WORD_BREAKS:
            end += 1
        token.value, token.value_kind, index = text[index:end], "word", end
    token.end = index
    return token, index


def is_structured(text: str) -> bool:
    return any(token.kind == "FIELD" for token in tokenize(str(text or ""), strict=False))


# ── Parser ───────────────────────────────────────────────────────────────


_TERM_START = {"FIELD", "WORD", "QUOTED", "LPAREN", "NOT"}


class _Parser:
    def __init__(self, text: str, tokens: list[Token]) -> None:
        self.text = text
        self.tokens = tokens
        self.index = 0
        self.depth = 0
        self.terms = 0

    def peek(self, offset: int = 0) -> Token:
        return self.tokens[min(self.index + offset, len(self.tokens) - 1)]

    def advance(self) -> Token:
        token = self.peek()
        self.index += 1
        return token

    def error(self, message: str, token: Token, hint: str = "") -> QueryError:
        return QueryError(message, start=token.start, end=token.end, hint=hint)

    def count_term(self, token: Token) -> None:
        self.terms += 1
        if self.terms > MAX_TERMS:
            raise self.error(f"Queries are limited to {MAX_TERMS} search terms.", token)

    def nest(self, token: Token) -> None:
        self.depth += 1
        if self.depth > MAX_DEPTH:
            raise self.error(f"Queries are limited to {MAX_DEPTH} levels of nesting.", token)

    def parse(self) -> Node:
        node = self.or_expr()
        token = self.peek()
        if token.kind == "RPAREN":
            raise self.error('Unexpected ")" without a matching "(".', token)
        return node

    def expect_operand(self, operator: Token) -> None:
        if self.peek().kind not in _TERM_START:
            raise self.error(f'Expected a search term after "{operator.value.upper()}".', operator)

    def or_expr(self) -> Node:
        items = [self.and_expr()]
        while self.peek().kind == "OR":
            operator = self.advance()
            self.expect_operand(operator)
            items.append(self.and_expr())
        return items[0] if len(items) == 1 else Or(tuple(items))

    def and_expr(self) -> Node:
        items = [self.not_expr()]
        while True:
            token = self.peek()
            if token.kind == "AND":
                self.advance()
                self.expect_operand(token)
            elif token.kind not in _TERM_START:
                break
            items.append(self.not_expr())
        return items[0] if len(items) == 1 else And(tuple(items))

    def not_expr(self) -> Node:
        token = self.peek()
        if token.kind != "NOT":
            return self.primary()
        self.advance()
        self.expect_operand(token)
        self.nest(token)
        node = Not(self.not_expr())
        self.depth -= 1
        return node

    def primary(self) -> Node:
        token = self.peek()
        if token.kind == "LPAREN":
            self.advance()
            self.nest(token)
            if self.peek().kind == "RPAREN":
                raise QueryError("Empty parentheses.", start=token.start, end=self.peek().end)
            node = self.or_expr()
            if self.peek().kind != "RPAREN":
                raise self.error('Missing closing parenthesis for "(".', token, hint='Add ")" to close the group.')
            self.advance()
            self.depth -= 1
            return node
        if token.kind == "FIELD":
            return self.field_term()
        if token.kind == "WORD":
            first = last = self.advance()
            while self.peek().kind == "WORD":
                last = self.advance()
            self.count_term(first)
            return Text(self.text[first.start:last.end], (first.start, last.end))
        if token.kind == "QUOTED":
            self.advance()
            if not token.value.strip():
                raise self.error("Empty quoted text.", token)
            self.count_term(token)
            return Text(token.value, (token.start, token.end))
        if token.kind in {"AND", "OR"}:
            raise self.error(f'Expected a search term before "{token.value.upper()}".', token)
        if token.kind == "RPAREN":
            raise self.error('Unexpected ")" without a matching "(".', token)
        raise self.error("Expected a search term.", token)

    def field_term(self) -> Node:
        token = self.advance()
        name = token.field
        spec = resolve_field(name)
        if spec is None:
            suggestion = FIELD_HINTS.get(name.lower())
            if suggestion:
                raise QueryError(f'Unknown field "{name}".', start=token.start, end=token.start + len(name),
                                 hint=f"Did you mean {suggestion}:?")
            raise QueryError(
                f'Unknown field "{name}".', start=token.start, end=token.start + len(name),
                hint=f"Fields: {', '.join(FIELDS)}. To search for this text, wrap it in quotes.")
        operator = OPERATORS[token.op]
        if token.value_kind == "group":
            return self.value_group(token, spec)
        if token.value_kind == "":
            hint = spec.expected() if spec.kind == "enum" else (_DATE_HINT if spec.kind == "date" else "")
            raise self.error(f'Expected a value after "{self.text[token.start:token.end]}".', token, hint)
        self.count_term(token)
        return self.term(spec, operator, token.value, token, (token.value_start, token.end))

    def value_group(self, token: Token, spec: QueryField) -> Node:
        if token.op:
            raise self.error(f'A value list cannot be combined with "{token.op}".', token)
        values: list[Node] = []
        while True:
            first = self.peek()
            if first.kind == "WORD":
                last = self.advance()
                while self.peek().kind == "WORD":
                    last = self.advance()
                raw, span = self.text[first.start:last.end], (first.start, last.end)
            elif first.kind == "QUOTED":
                self.advance()
                raw, span = first.value, (first.start, first.end)
            elif first.kind == "EOF":
                raise self.error(f'Missing closing parenthesis for "{token.field}:(".', token)
            else:
                raise self.error(f'Expected a {spec.noun} value.', first,
                                 spec.expected() if spec.kind == "enum" else "")
            self.count_term(first)
            values.append(self.term(spec, "eq", raw, first, span))
            separator = self.peek()
            if separator.kind == "OR":
                self.advance()
            elif separator.kind == "RPAREN":
                self.advance()
                break
            elif separator.kind == "EOF":
                raise self.error(f'Missing closing parenthesis for "{token.field}:(".', token)
            else:
                raise self.error(f"Only OR can join values inside {token.field}:( ... ).", separator)
        return values[0] if len(values) == 1 else Or(tuple(values))

    def term(self, spec: QueryField, operator: str, raw: str, token: Token, span: tuple[int, int]) -> Term:
        whole = (token.start, span[1])
        if operator not in spec.operators:
            raise QueryError(f'Operator "{token.op}" is not supported for {spec.name}.',
                             start=token.start, end=span[0], hint=f"Use {spec.name}:value.")
        raw = raw.strip()
        if not raw:
            raise QueryError(f'Expected a value after "{spec.name}:".', start=token.start, end=span[1])
        if spec.kind == "id":
            return Term(spec.name, operator, raw.upper(), whole)
        if spec.kind == "text":
            return Term(spec.name, operator, raw, whole)
        if spec.kind == "date":
            value = parse_date(raw)
            if value is None:
                raise QueryError(f'Invalid date "{raw}" for {spec.name}.', start=span[0], end=span[1],
                                 hint=_DATE_HINT)
            return Term(spec.name, operator, value, whole)
        match = spec.lookup(raw)
        if match is None:
            raise QueryError(f'Unknown {spec.noun} "{raw}".', start=span[0], end=span[1],
                             hint=self.unquoted_hint(spec, raw) or spec.expected())
        return Term(spec.name, operator, match.key, whole)

    def unquoted_hint(self, spec: QueryField, raw: str) -> str:
        """workflow_status:Awaiting Approval -> suggest the quoted form."""
        following = self.peek()
        if following.kind == "WORD" and spec.lookup(f"{raw} {following.value}"):
            return f'Quote values that contain spaces: {spec.name}:"{raw} {following.value}".'
        return ""


def parse_query(text: str) -> ParsedQuery:
    """Search text -> ParsedQuery. Raises QueryError for invalid structured
    queries; free text (no field expression) never fails."""
    text = str(text or "")
    stripped = text.strip()
    if not stripped:
        return ParsedQuery("empty", None, "")
    if len(text) > MAX_QUERY_LENGTH:
        raise QueryError(f"Searches are limited to {MAX_QUERY_LENGTH} characters.",
                         start=MAX_QUERY_LENGTH, end=len(text))
    if not is_structured(text):
        start = len(text) - len(text.lstrip())
        return ParsedQuery("text", Text(stripped, (start, start + len(stripped))), stripped)
    return ParsedQuery("structured", _Parser(text, tokenize(text)).parse(), stripped)


# ── Tree helpers ─────────────────────────────────────────────────────────


def iter_terms(node: Node | None) -> Iterator[Text | Term]:
    if node is None:
        return
    if isinstance(node, (And, Or)):
        for item in node.items:
            yield from iter_terms(item)
    elif isinstance(node, Not):
        yield from iter_terms(node.item)
    else:
        yield node


def fields_used(node: Node | None) -> list[str]:
    return sorted({term.field for term in iter_terms(node) if isinstance(term, Term)})


def conjuncts(node: Node | None) -> list[Node]:
    """Top-level AND operands (flattened)."""
    if node is None:
        return []
    if isinstance(node, And):
        return [part for item in node.items for part in conjuncts(item)]
    return [node]


def _render_token(value: str) -> str:
    if value and all(not char.isspace() and char not in '()"' for char in value):
        return value
    return '"' + value.replace("\\", "\\\\").replace('"', '\\"') + '"'


def to_query(node: Node | None) -> str:
    """Canonical query text for a tree (field names, operators and values
    normalised), e.g. `severity:HIGH AND stage:investigation`."""
    if node is None:
        return ""
    if isinstance(node, Text):
        return '"' + node.text.replace("\\", "\\\\").replace('"', '\\"') + '"'
    if isinstance(node, Term):
        spec = FIELDS.get(node.field)
        if isinstance(node.value, DateValue):
            value = node.value.text
        elif spec is not None and spec.kind == "enum":
            value = _render_token(spec.value_for(node.value).token)
        else:
            value = _render_token(str(node.value))
        return f"{node.field}:{_OPERATOR_SYMBOLS[node.op]}{value}"
    if isinstance(node, Not):
        inner = to_query(node.item)
        return f"NOT ({inner})" if isinstance(node.item, (And, Or)) else f"NOT {inner}"
    joiner = " AND " if isinstance(node, And) else " OR "
    parts = [f"({to_query(item)})" if isinstance(item, (And, Or)) else to_query(item) for item in node.items]
    return joiner.join(parts)


# ── Schema (autocomplete + help) ─────────────────────────────────────────


EXAMPLES = (
    ("High-severity investigations", "severity:HIGH AND stage:investigation"),
    ("Cases awaiting approval", 'workflow_status:"Awaiting Approval"'),
    ("High or critical cases", "severity:HIGH OR severity:CRITICAL"),
    ("Recent cases", "updated:>=2026-09-01"),
    ("High unified verdict", "verdict:HIGH"),
)


def schema() -> dict[str, Any]:
    """Vocabulary for the frontend's autocomplete and syntax help, generated
    from the registry so display -> backend mappings live only here."""
    return {
        "fields": [{
            "name": field.name,
            "aliases": list(field.aliases),
            "kind": field.kind,
            "description": field.description,
            "operators": [":" + _OPERATOR_SYMBOLS[op] for op in ("eq", "gt", "ge", "lt", "le")
                          if op in field.operators],
            "ordered": field.ordered,
            "values": [{"value": value.token, "insert": _render_token(value.token), "label": value.label,
                        "key": value.key} for value in field.values],
        } for field in FIELDS.values()],
        "hints": dict(FIELD_HINTS),
        "keywords": list(KEYWORDS),
        "notes": [
            "Dates without a timezone are interpreted as UTC.",
            "Severity order: CRITICAL > HIGH > MEDIUM > LOW.",
            "Searches without a field (e.g. command and control) are plain text searches.",
        ],
        "examples": [{"label": label, "query": query} for label, query in EXAMPLES],
        "limits": {"length": MAX_QUERY_LENGTH, "terms": MAX_TERMS, "depth": MAX_DEPTH},
    }
