"""Vahid avtorizasiya konteksti — Faza 1 (sadələşdirilmiş scope idarəsi).

Tək səlahiyyətli giriş nöqtəsi: **`ctx.authorization.authorize_url(url)`**.

Prinsip:
  * **Yalnız scope xaricində olan rədd edilir.** Scope daxilində hər şey
    icazəlidir (aktiv fuzz, bypass, PoC, secret replay ...).
  * Proqram qaydaları (`program_rules`) yalnız AÇIQ şəkildə qadağan olunan
    hərəkətləri bağlayır — qalan hər şey açıqdır.
  * Wildcard auto-expansion: `*.example.com` scope-u kəşf olunan alt-domenlərə
    avtomatik şamil olunur (configurable).
  * Deadline və ləğv (cancellation) burada izlənir.

Bu modul `ScopeEnforcer`-i əvəz ETMİR — onun üzərinə avtorizasiya + RoE +
həyat dövrü qatını geyindirir.
"""
from __future__ import annotations

import asyncio
import time
import re
import unicodedata
from contextlib import contextmanager
from contextvars import ContextVar
from fnmatch import fnmatchcase
from urllib.parse import urlsplit, unquote
from pathlib import PurePath
from dataclasses import dataclass, field

from .config import ProgramRules
from .scope import ScopeEnforcer, ScopeError, extract_host, normalize_host


_operation: ContextVar = ContextVar("authorization_operation", default=None)
_ACTION_ALIASES = {"js": "jsanalysis", "param": "param_enum", "api": "api_enum",
                   "hidden_param_detect": "param_enum", "param_fuzz": "param_enum",
                   "schemathesis_fuzz": "api_fuzz", "bypass_matrix": "bypass",
                   "confirm_template": "confirm"}



class AuthorizationError(ScopeError):
    """İcazəsiz resurs / qayda pozuntusu / vaxt bitməsi."""


class NotAuthorized(AuthorizationError):
    """Resurs scope xaricindədir."""


class RuleForbidden(AuthorizationError):
    """Proqram qaydaları bu hərəkəti qadağan edir."""


class ScanExpired(AuthorizationError):
    """Skan deadline-i keçib və ya ləğv edilib."""


def _restriction_host(pattern):
    # These are deny globs, not scope grants: preserve existing fnmatch syntax.
    if any(char in pattern for char in "*?["):
        try:
            return pattern.lower().rstrip(".").encode("idna").decode("ascii")
        except UnicodeError as exc:
            raise RuleForbidden("invalid_restriction_host") from exc
    return normalize_host(pattern)


def policy_paths(url):
    """Conservatively compare every decoding level and its normalized path.

    Keep the transmitted URL unchanged; ambiguous nesting fails closed.
    """
    path = urlsplit(url).path or "/"
    variants = set()
    for _ in range(8):
        path = unicodedata.normalize("NFC", path).replace("\\", "/")
        if any(ord(c) < 32 or ord(c) == 127 for c in path):
            raise RuleForbidden("invalid_path_control")
        variants.add(path)
        segments = []
        for segment in path.split("/"):
            if segment == "..":
                if segments:
                    segments.pop()
            elif segment not in {"", "."}:
                segments.append(segment)
        normalized = "/" + "/".join(segments)
        variants.add(normalized)
        if path.endswith("/"):
            variants.add(normalized.rstrip("/") + "/")
        decoded = unquote(path, errors="strict")
        if decoded == path:
            return variants
        path = decoded
    raise RuleForbidden("excessive_path_encoding")


@dataclass
class Authorization:
    """Skan boyu YEGANƏ avtorizasiya qərar mərkəzi."""

    scan_id: int | None = None
    scope: ScopeEnforcer | None = None
    rules: ProgramRules = field(default_factory=ProgramRules)
    aggressiveness: str = "aggressive"
    deadline: float | None = None            # time.time() əsaslı mütləq vaxt
    canceller: "asyncio.Event | None" = None
    profile_active_fuzz: bool = True
    profile_intrusive: bool = True
    #: Uyğunluq sahəsi: əlavə CLI təsdiqi tələb edilmir; YAML qadağası qüvvədədir.
    allow_state_changing: bool = True
    allowed_ports: tuple = (80, 443)
    dry_run: bool = False
    _cancelled: bool = False
    request_restrictions: list = field(default_factory=list)

    # ------------------------------------------------------------------ scope
    def is_authorized(self, value: str) -> bool:
        """Host/URL scope daxilindədir? Fail-closed (scope boşdursa False)."""
        if self.scope is None or self.scope.is_empty:
            return False
        return self.scope.is_authorized(value)

    def authorize_url(self, url: str) -> str:
        """URL-i yoxlayır və eyni URL-i qaytarır; kənardırsa `NotAuthorized`."""
        if self.scope is None or self.scope.is_empty:
            raise NotAuthorized("scope konfiqurasiyası boşdur — icra dayandırılır")
        try:
            if any(ord(c) < 33 or ord(c) == 127 for c in url):
                raise ScopeError("invalid_url_control")
            parsed = urlsplit(url)
            if parsed.scheme.lower() not in {"http", "https"} or not parsed.hostname:
                raise ScopeError("invalid_http_url")
            if parsed.username is not None or parsed.password is not None or "\\" in parsed.netloc:
                raise ScopeError("ambiguous_url_authority")
            if parsed.port is not None and not 1 <= parsed.port <= 65535:
                raise ScopeError("invalid_port")
            host = normalize_host(extract_host(url))
        except ValueError as exc:
            raise NotAuthorized(f"etibarsız URL: {url!r} ({exc})") from exc
        try:
            self.scope.authorize(host)
        except ScopeError as exc:
            raise NotAuthorized(str(exc)) from exc
        return url

    def authorize_request(self, method, url, action=None, *, destructive=False):
        """One decision point for explicit request restrictions and lifecycle."""
        self.ensure_active()
        if self.dry_run:
            raise RuleForbidden("dry_run_network_forbidden")
        self.authorize_url(url)
        method = method.upper()
        if not re.fullmatch(r"[A-Z!#$%&'*+.^_`|~-]+", method):
            raise RuleForbidden("invalid_http_method")
        if destructive:
            raise RuleForbidden("destructive_operation")
        active = _operation.get()
        actions = {action} if action else set()
        if active is not None and active[0] is self:
            actions.add(active[1])
        for technique in actions:
            self.require(technique)
        if method not in {"GET", "HEAD", "OPTIONS"}:
            self.require("state_changing")
        host = normalize_host(extract_host(url))
        try:
            paths = policy_paths(url)
        except UnicodeError as exc:
            raise RuleForbidden("invalid_path_encoding") from exc
        for rule in self.request_restrictions:
            if not any(fnmatchcase(host, _restriction_host(h)) for h in rule["hosts"]):
                continue
            if not any(fnmatchcase(p, pattern) for p in paths for pattern in rule["paths"]):
                continue
            if method not in rule["methods"] and "*" not in rule["methods"]:
                continue
            denied = {_ACTION_ALIASES.get(name, name) for name in rule["forbidden"]}
            canonical_actions = {_ACTION_ALIASES.get(name, name) for name in actions}
            if "*" in denied or canonical_actions.intersection(denied):
                raise RuleForbidden("explicit_request_restriction")
        return url

    @contextmanager
    def operation(self, action):
        """Bind engine identity to every native request, including redirects.

        ContextVar keeps concurrent Scheduler tasks isolated; explicit sub-actions
        still undergo their own checks at authorize_request().
        """
        token = _operation.set((self, action))
        try:
            yield
        finally:
            _operation.reset(token)

    def authorize_host(self, host: str) -> str:
        """Hostu yoxlayır və kanonik hostu qaytarır; kənardırsa xəta."""
        if self.scope is None or self.scope.is_empty:
            raise NotAuthorized("scope konfiqurasiyası boşdur — icra dayandırılır")
        try:
            return self.scope.authorize(host)
        except ScopeError as exc:
            raise NotAuthorized(str(exc)) from exc

    def filter_hosts(self, hosts) -> list[str]:
        """İcazəli hostları süzür (auto-expansion wildcard qaydası ilə)."""
        out: list[str] = []
        seen: set[str] = set()
        for h in hosts or []:
            try:
                canon = self.authorize_host(h)
            except NotAuthorized:
                continue
            if canon not in seen:
                seen.add(canon)
                out.append(canon)
        return out

    def allows_wildcard_expansion(self) -> bool:
        """`*.example.com` kəşfinə avtomatik genişlənmə icazəlidir?"""
        return bool(self.rules.allow_wildcard_expansion)

    # ------------------------------------------------------------------- RoE
    def allows(self, action: str) -> bool:
        """Proqram qaydaları hərəkətə icazə verir? (default: bəli)"""
        if not self.rules.allows(action) or not self.rules.allows(_ACTION_ALIASES.get(action, action)):
            return False
        if action == "active_fuzz" and not self.profile_active_fuzz:
            return False
        if action == "intrusive_templates" and not self.profile_intrusive:
            return False
        if action in {"destructive", "dos", "data_deletion"}:
            return False
        return True

    def require(self, action: str) -> None:
        """Hərəkət qadağandırsa `RuleForbidden` atır."""
        if not self.allows(action):
            raise RuleForbidden(
                f"proqram qaydaları icazə vermir: {action!r}")

    def require_command(self, command) -> None:
        """Apply tool RoE at the shared process boundary without inspecting secrets."""
        self.ensure_active()
        if self.dry_run:
            raise RuleForbidden("dry_run_process_forbidden")
        args = list(command)
        if not args:
            raise RuleForbidden("empty_command")
        if PurePath(args[0]).name == "firejail":
            args = next((args[i:] for i in range(1, len(args)) if not args[i].startswith("-")), [])
        if not args:
            raise RuleForbidden("empty_command")
        binary = PurePath(args[0]).name
        self.require(binary)
        if binary.startswith("python") or binary in {"bash", "sh", "node", "ruby"}:
            script = next((arg for arg in args[1:] if not arg.startswith("-")), "")
            if script:
                self.require(PurePath(script).stem)

    # ---------------------------------------------------------- ləğv / vaxt
    def cancel(self) -> None:
        self._cancelled = True
        if self.canceller is not None:
            try:
                self.canceller.set()
            except Exception:  # noqa: BLE001 - canceller sadəcə siqnaldır
                pass

    def is_cancelled(self) -> bool:
        if self._cancelled:
            return True
        if self.canceller is not None:
            try:
                return bool(self.canceller.is_set())
            except Exception:  # noqa: BLE001
                return False
        return False

    def expired(self) -> bool:
        return self.deadline is not None and time.time() > self.deadline

    def ensure_active(self) -> None:
        """Ləğv/vaxt bitibsə `ScanExpired` atır (uzun əməliyyatlardan əvvəl)."""
        if self.is_cancelled():
            raise ScanExpired("skan ləğv edildi")
        if self.expired():
            raise ScanExpired("skan deadline-i keçdi")

    def remaining(self) -> float | None:
        if self.deadline is None:
            return None
        return max(0.0, self.deadline - time.time())

    def summary(self) -> dict:
        return {
            "scan_id": self.scan_id,
            "aggressiveness": self.aggressiveness,
            "wildcard_expansion": self.allows_wildcard_expansion(),
            "forbidden": sorted(self.rules.forbidden),
            "state_changing": self.allows("state_changing"),
            "cancelled": self.is_cancelled(),
            "expired": self.expired(),
        }


def from_config(cfg, scan_id: int | None = None, *, deadline: float | None = None,
                canceller: "asyncio.Event | None" = None,
                allow_state_changing: bool = True) -> Authorization:
    """`Config`-dən avtorizasiya konteksti qurur."""
    return Authorization(
        scan_id=scan_id,
        allowed_ports=tuple(getattr(cfg, "network_allowed_ports", (80, 443))),
        scope=cfg.scope,
        rules=cfg.program_rules,
        aggressiveness=cfg.aggressiveness,
        deadline=deadline,
        canceller=canceller,
        profile_active_fuzz=bool(cfg.profile.get("active_fuzz", True)),
        profile_intrusive=bool(cfg.profile.get("intrusive_templates", True)),
        allow_state_changing=True,
        request_restrictions=list(getattr(cfg, "request_restrictions", [])),
    )
