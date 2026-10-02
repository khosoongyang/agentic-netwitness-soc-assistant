"""Runtime pass-through wrappers (approved instrumentation mechanism).

No workflow or agent source file is edited. At install time a module/class
attribute that the workflow already looks up *by name at call time* is
replaced with a wrapper that:

  * calls the original with the exact same positional/keyword arguments
    (the very same objects - nothing is copied, injected or mutated);
  * returns the original's return object unchanged (identity preserved);
  * re-raises the original exception object unchanged (bare ``raise``);
  * runs observation hooks around the call, each inside its own
    try/except, so an observability failure can never reach the workflow.

Every replacement is recorded so ``uninstall()`` restores the exact original
object. Each target is declared with the parameter names the hooks rely on;
if the real function's signature no longer matches, that wrapper is simply
not installed (reported via ``install_report``) instead of guessing.
"""

from __future__ import annotations

import functools
import importlib
import inspect
from dataclasses import dataclass, field
from typing import Any, Callable

from . import context

ORIGINAL_ATTR = "__aegis_observability_original__"

_FAILURES = {"hook": 0}

# Callables run whenever a RunScope opens; each returns a zero-argument
# "close" function. Used by the LangChain adapter to activate its
# context-scoped callback handler only inside an observed stage run.
_SCOPE_ACTIVATORS: list[Callable[[context.RunScope], Callable[[], None] | None]] = []


def register_scope_activator(fn) -> None:
    if fn not in _SCOPE_ACTIVATORS:
        _SCOPE_ACTIVATORS.append(fn)


def unregister_scope_activator(fn) -> None:
    if fn in _SCOPE_ACTIVATORS:
        _SCOPE_ACTIVATORS.remove(fn)


def _guard(fn, *args):
    try:
        return fn(*args)
    except Exception:
        _FAILURES["hook"] += 1
        return None


def hook_failures() -> int:
    return _FAILURES["hook"]


@dataclass
class Hooks:
    # scope(call) -> RunScope | None. Opened before `before`, closed after
    # `after`/`error`/`cleanup`. Return None to leave the current scope as is.
    scope: Callable[[dict], context.RunScope | None] | None = None
    # before(call) -> token (anything); passed to after/error/cleanup.
    before: Callable[[dict], Any] | None = None
    after: Callable[[dict, Any, Any], None] | None = None          # (call, token, result)
    error: Callable[[dict, Any, BaseException], None] | None = None  # (call, token, exc)
    cleanup: Callable[[dict, Any], None] | None = None              # always, in finally


def _bind(signature: inspect.Signature | None, args: tuple, kwargs: dict) -> dict:
    if signature is None:
        return {}
    try:
        bound = signature.bind(*args, **kwargs)
        bound.apply_defaults()
        return dict(bound.arguments)
    except Exception:
        return {}


def make_wrapper(original: Callable, hooks: Hooks) -> Callable:
    try:
        signature = inspect.signature(original)
    except (TypeError, ValueError):
        signature = None

    @functools.wraps(original)
    def wrapper(*args, **kwargs):
        call = _bind(signature, args, kwargs)
        closers: list[Callable[[], None]] = []
        if hooks.scope is not None:
            scope = _guard(hooks.scope, call)
            if scope is not None:
                scope_token = _guard(context.set_scope, scope)
                if scope_token is not None:
                    closers.append(lambda t=scope_token: context.reset_scope(t))
                    for activator in list(_SCOPE_ACTIVATORS):
                        closer = _guard(activator, scope)
                        if callable(closer):
                            closers.append(closer)
        hook_token = None
        try:
            if hooks.before is not None:
                hook_token = _guard(hooks.before, call)
            try:
                result = original(*args, **kwargs)
            except BaseException as exc:
                if hooks.error is not None:
                    _guard(hooks.error, call, hook_token, exc)
                raise
            if hooks.after is not None:
                _guard(hooks.after, call, hook_token, result)
            return result
        finally:
            if hooks.cleanup is not None:
                _guard(hooks.cleanup, call, hook_token)
            for closer in reversed(closers):
                _guard(closer)

    setattr(wrapper, ORIGINAL_ATTR, original)
    return wrapper


@dataclass(frozen=True)
class Target:
    """One wrap point: ``module`` + optional ``owner`` (dotted class path
    inside the module) + ``attr``, plus the parameter names the hooks read."""
    module: str
    attr: str
    params: tuple[str, ...]
    owner: str | None = None

    @property
    def label(self) -> str:
        return ".".join(p for p in (self.module, self.owner, self.attr) if p)


def resolve_owner(target: Target):
    obj = importlib.import_module(target.module)
    if target.owner:
        for part in target.owner.split("."):
            obj = getattr(obj, part)
    return obj


def unwrapped(fn):
    return getattr(fn, ORIGINAL_ATTR, fn)


def actual_params(target: Target) -> tuple[str, ...] | None:
    try:
        fn = unwrapped(getattr(resolve_owner(target), target.attr))
        return tuple(inspect.signature(fn).parameters)
    except Exception:
        return None


@dataclass
class Patcher:
    applied: list[tuple[Any, str, Any, Any, bool]] = field(default_factory=list)
    report: dict[str, str] = field(default_factory=dict)

    def wrap(self, target: Target, hooks: Hooks) -> bool:
        try:
            owner = resolve_owner(target)
            current = getattr(owner, target.attr)
        except Exception as exc:  # module/attribute vanished: skip, never break
            self.report[target.label] = f"skipped: {type(exc).__name__}"
            return False
        if hasattr(current, ORIGINAL_ATTR):
            self.report[target.label] = "already instrumented"
            return False
        params = actual_params(target)
        if params != target.params:
            self.report[target.label] = f"skipped: signature mismatch {params!r}"
            return False
        own_attr = target.attr in getattr(owner, "__dict__", {})
        wrapper = make_wrapper(current, hooks)
        setattr(owner, target.attr, wrapper)
        self.applied.append((owner, target.attr, current, wrapper, own_attr))
        self.report[target.label] = "installed"
        return True

    def restore(self) -> list[str]:
        """Restore every original in reverse order. A wrapper that someone
        else has since replaced (e.g. a test monkeypatch) is left alone."""
        not_restored: list[str] = []
        while self.applied:
            owner, attr, original, wrapper, own_attr = self.applied.pop()
            if getattr(owner, "__dict__", {}).get(attr) is not wrapper:
                not_restored.append(f"{getattr(owner, '__name__', owner)}.{attr}")
                continue
            if own_attr:
                setattr(owner, attr, original)
            else:
                delattr(owner, attr)
        return not_restored
