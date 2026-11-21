import re
from collections.abc import Mapping
from functools import lru_cache
from importlib.resources import files
from urllib.parse import urlsplit

import idna

_INVALID_URL_CHAR = re.compile(r"[\x00-\x20\x7f\\]")
_DEFAULT_PORTS = {"http": 80, "https": 443}


def _normalize_host(host: str) -> str:
    try:
        normalized = idna.encode(host, uts46=True, std3_rules=True).decode("ascii").removesuffix(".")
    except (idna.IDNAError, UnicodeError):
        raise ValueError("Invalid DNS host") from None

    labels = normalized.split(".")
    tld = labels[-1]
    if len(labels) < 2 or not any("a" <= char <= "z" for char in tld):
        raise ValueError("Expected a DNS domain")
    if tld.startswith("0x") and tld[2:] and all(char in "0123456789abcdef" for char in tld[2:]):
        raise ValueError("Expected a DNS domain")
    return normalized


def normalize_origin(url: str) -> str:
    """Retain only a canonical HTTP(S) scheme, DNS host, and optional port."""
    url = url.strip(" ")
    if _INVALID_URL_CHAR.search(url):
        raise ValueError("Invalid URL")
    try:
        parsed = urlsplit(url)
        port = parsed.port
    except (ValueError, UnicodeError):
        raise ValueError("Invalid URL") from None

    if (
        parsed.scheme not in _DEFAULT_PORTS
        or not parsed.hostname
        or parsed.netloc.rpartition("@")[2].endswith(":")
        or port == 0
    ):
        raise ValueError("Expected an HTTP(S) URL with a valid DNS host")
    host = _normalize_host(parsed.hostname)
    suffix = f":{port}" if port is not None and port != _DEFAULT_PORTS[parsed.scheme] else ""
    return f"{parsed.scheme}://{host}{suffix}"


@lru_cache(maxsize=1)
def _suffix_rules() -> tuple[set[str], set[str], set[str]]:
    exact, wildcard, exception = set(), set(), set()
    resource = files("account_privacy").joinpath("resources", "public_suffix_list.dat")
    for line in resource.read_text(encoding="utf-8").splitlines():
        rule = line.strip()
        if not rule or rule.startswith("//"):
            continue
        if rule.startswith("!"):
            exception.add(idna.encode(rule[1:], uts46=True).decode("ascii"))
        elif rule.startswith("*."):
            wildcard.add(idna.encode(rule[2:], uts46=True).decode("ascii"))
        else:
            exact.add(idna.encode(rule, uts46=True).decode("ascii"))
    return exact, wildcard, exception


@lru_cache(maxsize=4096)
def registrable_domain(host: str) -> str:
    """Return the eTLD+1 using the bundled ICANN and private suffix rules."""
    labels = _normalize_host(host).split(".")
    exact, wildcard, exception = _suffix_rules()
    suffix_length = 1
    for index in range(len(labels)):
        candidate = ".".join(labels[index:])
        length = len(labels) - index
        if candidate in exception:
            suffix_length = length - 1
            break
        if candidate in exact:
            suffix_length = max(suffix_length, length)
        if index and candidate in wildcard:
            suffix_length = max(suffix_length, length + 1)
    if len(labels) <= suffix_length:
        raise ValueError("The domain is a public suffix")
    return ".".join(labels[-suffix_length - 1:])


def service_domain(host: str, aliases: Mapping[str, str] | None = None) -> str:
    """Apply explicit catalog aliases keyed by normalized host or registrable domain."""
    host = _normalize_host(host)
    domain = registrable_domain(host)
    if not aliases:
        return domain
    return registrable_domain(aliases.get(host, aliases.get(domain, domain)))
