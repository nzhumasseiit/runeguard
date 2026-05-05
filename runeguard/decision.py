from dataclasses import dataclass
from enum import Enum


class DecisionType(str, Enum):
    ALLOW = "ALLOW"
    BLOCK = "BLOCK"
    REQUIRE_APPROVAL = "REQUIRE_APPROVAL"


@dataclass(frozen=True)
class Decision:
    type: DecisionType
    reason: str
