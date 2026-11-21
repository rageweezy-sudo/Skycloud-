from collections.abc import Iterable
from dataclasses import dataclass
from enum import StrEnum

from .models import EvidenceCategory


class ConfidenceBand(StrEnum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


@dataclass(frozen=True, slots=True)
class Confidence:
    points: int
    band: ConfidenceBand
    categories: tuple[EvidenceCategory, ...]


_WEIGHTS = {
    EvidenceCategory.IMPORT: 80,
    EvidenceCategory.SIGNUP: 70,
    EvidenceCategory.RESET: 45,
    EvidenceCategory.RECEIPT: 35,
    EvidenceCategory.UNSUBSCRIBE: 15,
}


def score_evidence(
    categories: Iterable[EvidenceCategory], ambiguous: bool = False
) -> Confidence:
    unique = tuple(sorted(set(categories), key=_WEIGHTS.__getitem__, reverse=True))
    points = min(_WEIGHTS[unique[0]] + 10 * (len(unique) - 1), 44 if ambiguous else 100) if unique else 0
    band = ConfidenceBand.LOW
    if points >= 80:
        band = ConfidenceBand.HIGH
    elif points >= 45:
        band = ConfidenceBand.MEDIUM
    return Confidence(points, band, unique)
