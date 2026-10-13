from __future__ import annotations

import fnmatch
import ipaddress
from urllib.parse import urlsplit

from .store import Store

LOOPBACK_HOSTS = {"localhost", "127.0.0.1", "::1"}


class ScopePolicy:
    """Fail-closed hostname allowlist; exclusions always override inclusions."""

    def __init__(self, store: Store):
        self.store = store

    @staticmethod
    def normalize_host(host: str) -> str:
        """Canonicalize IP literals and IDNA hostnames before applying scope rules."""
        value = str(host or "").strip().casefold().rstrip(".")
        if value.startswith("[") and value.endswith("]"):
            value = value[1:-1]
        if not value or "%" in value:
            return ""
        try:
            address = ipaddress.ip_address(value)
            if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped:
                return str(address.ipv4_mapped)
            return address.compressed.casefold()
        except ValueError:
            pass
        # Canonicalize legacy IPv4 forms some URL stacks accept (127.1, integer,
        # octal, and hexadecimal components) so they cannot bypass exact IP rules.
        parts = value.split(".")
        looks_numeric = all(part.isdigit() or (part.casefold().startswith("0x") and len(part) > 2 and all(c in "0123456789abcdefABCDEF" for c in part[2:])) for part in parts)
        if looks_numeric and 1 <= len(parts) <= 4:
            try:
                nums = []
                for part in parts:
                    low = part.casefold()
                    if low.startswith("0x"):
                        nums.append(int(low[2:], 16))
                    elif len(part) > 1 and part.startswith("0"):
                        nums.append(int(part, 8))
                    else:
                        nums.append(int(part, 10))
                if any(number < 0 or number > 0xFFFFFFFF for number in nums[:-1]):
                    return ""
                if any(number > 255 for number in nums[:-1]):
                    return ""
                tail_bits = 8 * (5 - len(nums))
                if nums[-1] >= (1 << tail_bits):
                    return ""
                address_value = sum(number << (24 - 8 * index) for index, number in enumerate(nums[:-1])) + nums[-1]
                return str(ipaddress.IPv4Address(address_value))
            except (ValueError, OverflowError):
                return ""
        if all(part.isdigit() for part in parts):
            return ""
        try:
            return value.encode("idna").decode("ascii").casefold()
        except (UnicodeError, ValueError):
            return ""

    def _rules(self) -> list[dict]:
        return self.store.list_scope_rules()

    def has_explicit_exclusions(self) -> bool:
        """Whether peer verification may be needed for a scope decision.

        If a proxy runtime cannot expose the actual connected peer, callers that
        would otherwise perform an active send should fail closed when any
        explicit exclusion exists. Hostname checks still apply independently.
        """
        return any(rule.get("mode") == "exclude" for rule in self._rules())

    @classmethod
    def _normalize_pattern(cls, pattern: str) -> str:
        """Canonicalize literal rule targets just like candidate hosts.

        Wildcard host patterns remain patterns, but their literal labels are IDNA
        normalized. This means an exclusion entered as an IPv4-mapped IPv6 or
        legacy IPv4 literal still matches the same address after normalization.
        """
        value = str(pattern or "").strip().casefold().rstrip(".")
        if not value:
            return ""
        if not any(char in value for char in "*?[]"):
            return cls.normalize_host(value)
        labels = value.split(".")
        normalized_labels = []
        for label in labels:
            if any(char in label for char in "*?[]"):
                normalized_labels.append(label)
            else:
                try:
                    normalized_labels.append(label.encode("idna").decode("ascii").casefold())
                except (UnicodeError, ValueError):
                    return ""
        return ".".join(normalized_labels)

    @classmethod
    def _matches(cls, normalized_host: str, pattern: str) -> bool:
        normalized_pattern = cls._normalize_pattern(pattern)
        return bool(normalized_pattern) and fnmatch.fnmatchcase(normalized_host, normalized_pattern)

    def explicitly_excluded(self, host: str) -> bool:
        normalized = self.normalize_host(host)
        if not normalized:
            return True
        return any(
            r["mode"] == "exclude" and self._matches(normalized, r["pattern"])
            for r in self._rules()
        )

    def host_in_scope(self, host: str) -> bool:
        normalized = self.normalize_host(host)
        if not normalized:
            return False
        rules = self._rules()
        # Exclusions always win, including for loopback and canonicalized IP literals.
        if any(r["mode"] == "exclude" and self._matches(normalized, r["pattern"]) for r in rules):
            return False
        if normalized in LOOPBACK_HOSTS:
            return True
        includes = [r for r in rules if r["mode"] == "include"]
        return any(self._matches(normalized, r["pattern"]) for r in includes)

    def address_explicitly_excluded(self, address: str | tuple | None) -> bool:
        """Apply explicit IP exclusions to the resolved peer without requiring IP includes."""
        if isinstance(address, tuple):
            address = address[0] if address else ""
        if not address:
            return False
        normalized = self.normalize_host(str(address))
        if not normalized:
            return True
        return any(
            r["mode"] == "exclude" and self._matches(normalized, r["pattern"])
            for r in self._rules()
        )

    def url_in_scope(self, url: str) -> bool:
        try:
            parsed = urlsplit(url)
            if parsed.scheme.casefold() not in {"http", "https"} or not parsed.hostname:
                return False
            if parsed.username is not None or parsed.password is not None:
                return False
            _ = parsed.port
            return self.host_in_scope(parsed.hostname)
        except (ValueError, UnicodeError):
            return False

    def websocket_url_in_scope(self, url: str) -> bool:
        """Scope check for an already observed ws/wss handshake (also mitmproxy http(s) form)."""
        try:
            parsed = urlsplit(url)
            if parsed.scheme.casefold() not in {"ws", "wss", "http", "https"} or not parsed.hostname:
                return False
            if parsed.username is not None or parsed.password is not None or parsed.fragment:
                return False
            _ = parsed.port
            return self.host_in_scope(parsed.hostname)
        except (ValueError, UnicodeError):
            return False
