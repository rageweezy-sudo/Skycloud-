import json
from dataclasses import dataclass
from email.errors import HeaderParseError
from email.headerregistry import Address
from enum import StrEnum
from importlib.resources import files
from types import MappingProxyType
from urllib.parse import urlsplit

from account_privacy.core.domains import normalize_origin, registrable_domain


class ContactError(ValueError):
    pass


class ContactKind(StrEnum):
    EMAIL = "email"
    PORTAL = "portal"


def mail_address(value: str) -> str:
    try:
        if not value.isascii() or any(ord(char) < 33 or ord(char) == 127 for char in value):
            raise ValueError
        address = Address(addr_spec=value)
        if not address.username or not address.domain or address.addr_spec != value:
            raise ValueError
        registrable_domain(address.domain)
    except (ValueError, TypeError, IndexError, HeaderParseError):
        raise ContactError("Enter one email address") from None
    return value


@dataclass(frozen=True, slots=True)
class Contact:
    domain: str
    kind: ContactKind
    destination: str
    source: str

    def __post_init__(self):
        try:
            if registrable_domain(self.domain) != self.domain or not self.source.strip():
                raise ValueError
            if self.kind == ContactKind.EMAIL:
                mail_address(self.destination)
            elif self.kind == ContactKind.PORTAL:
                parsed = urlsplit(self.destination)
                if parsed.scheme != "https" or parsed.username is not None or parsed.fragment:
                    raise ValueError
                normalize_origin(self.destination)
            else:
                raise ValueError
        except (ValueError, TypeError, AttributeError):
            raise ContactError("The contact needs a canonical domain and a valid email address or HTTPS portal") from None

    @property
    def origin(self) -> str:
        return normalize_origin(self.destination)


@dataclass(frozen=True, slots=True)
class Catalog:
    version: int
    contacts: MappingProxyType
    aliases: MappingProxyType

    @classmethod
    def from_json(cls, content: str) -> "Catalog":
        try:
            document = json.loads(content)
            version = document["version"]
            if type(version) is not int or version < 1 or not isinstance(document["contacts"], list):
                raise ValueError
            contacts = {}
            for row in document["contacts"]:
                contact = Contact(row["domain"], ContactKind(row["kind"]), row["destination"], row["source"])
                if contact.domain in contacts:
                    raise ValueError
                contacts[contact.domain] = contact
            aliases = document.get("aliases", {})
            for host, domain in aliases.items():
                registrable_domain(host)
                if host != host.lower() or domain not in contacts or host in contacts:
                    raise ValueError
            return cls(version, MappingProxyType(contacts), MappingProxyType(aliases))
        except (KeyError, ValueError, TypeError, AttributeError):
            raise ContactError("Invalid privacy contacts catalog") from None

    @classmethod
    def bundled(cls) -> "Catalog":
        data = files("account_privacy").joinpath("resources", "privacy_contacts.json")
        return cls.from_json(data.read_text(encoding="utf-8"))
