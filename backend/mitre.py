import json
from typing import Dict, Iterable, List

from .config import settings


def _load_mapping() -> Dict[str, List[str]]:
    path = settings.resolve_path(settings.mitre_mapping_path)
    if not path.exists():
        return {
            "ATTACK": ["T1046"],
            "ANOMALY": ["T1046"],
            "RULE_MATCH": ["T1046"],
            "PORT_SCAN": ["T1046"],
            "SUSPICIOUS_OUTBOUND_VOLUME": ["T1041"],
            "KNOWN_MALICIOUS_INDICATOR": ["T1071"],
        }
    with path.open("r", encoding="utf-8") as handle:
        data = json.load(handle)
    return {key.upper(): list(value) for key, value in data.items()}


MAPPING = _load_mapping()


def map_to_mitre(*classifications: str, rule_ids: Iterable[str] = ()) -> List[str]:
    techniques = set()
    for classification in classifications:
        techniques.update(MAPPING.get(str(classification).upper(), []))
    for rule_id in rule_ids:
        techniques.update(MAPPING.get(str(rule_id).upper(), []))
    return sorted(techniques)
