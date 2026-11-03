"""Input validation. Everything that reaches a shell or a socket passes here."""

from __future__ import annotations

import ipaddress
import re

_HOSTNAME = re.compile(r"^(?=.{1,253}$)(?!-)[a-z0-9-]{1,63}(?<!-)(\.(?!-)[a-z0-9-]{1,63}(?<!-))*\.?$", re.I)
_USER = re.compile(r"^[a-z_][a-z0-9_.-]{0,31}$", re.I)


class InvalidInput(ValueError):
    def __init__(self, field: str, code: str):
        super().__init__(f"{field}: {code}")
        self.field = field
        self.code = code


def host(value: str, field: str = "host") -> str:
    value = (value or "").strip().strip("[]")
    try:
        ip = ipaddress.ip_address(value)
    except ValueError:
        if _HOSTNAME.match(value) and "." in value:
            return value.lower().rstrip(".")
        raise InvalidInput(field, "invalid_host") from None
    if not ip.is_global:
        raise InvalidInput(field, "private_ip")
    return str(ip)


def port(value, field: str = "port") -> int:
    try:
        number = int(str(value).strip())
    except ValueError:
        raise InvalidInput(field, "invalid_port") from None
    if not 1 <= number <= 65535:
        raise InvalidInput(field, "invalid_port")
    return number


def ports(value: str, field: str = "ports", limit: int = 12) -> list[int]:
    out: list[int] = []
    for part in re.split(r"[\s,]+", value or ""):
        if part:
            p = port(part, field)
            if p not in out:
                out.append(p)
    if len(out) > limit:
        raise InvalidInput(field, "too_many_ports")
    return out


def username(value: str, field: str = "username") -> str:
    value = (value or "root").strip()
    if not _USER.match(value):
        raise InvalidInput(field, "invalid_user")
    return value


def domain(value: str, field: str = "domain") -> str:
    value = (value or "").strip().lower().rstrip(".")
    if not value:
        return ""
    if not _HOSTNAME.match(value) or "." not in value:
        raise InvalidInput(field, "invalid_domain")
    return value


def path(value: str, field: str = "path") -> str:
    value = (value or "").strip()
    if not value:
        return ""
    if len(value) > 200 or not re.match(r"^[A-Za-z0-9_./~{}-]+$", value):
        raise InvalidInput(field, "invalid_path")
    return value
