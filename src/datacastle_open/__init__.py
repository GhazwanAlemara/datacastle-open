"""DataCastle Open: Self-Hosted EU Customs, Freight & EU AI Act Compliance Engine."""

from datacastle_open.engine import (
    classify_eu_ai_act,
    generate_tamper_evident_seal,
    reconcile_3way_freight,
    validate_taric_code,
)

__version__ = "1.0.0"
__all__ = [
    "__version__",
    "classify_eu_ai_act",
    "generate_tamper_evident_seal",
    "reconcile_3way_freight",
    "validate_taric_code",
]
