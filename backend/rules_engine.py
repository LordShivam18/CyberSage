import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional

from .config import settings
from .detection_types import DetectorResult
from .telemetry import NormalizedNetworkEvent


@dataclass
class Rule:
    id: str
    name: str
    description: str
    severity: str
    conditions: Dict[str, Any]
    mitre_techniques: List[str]
    investigation_actions: List[str]
    enabled: bool = True


SEVERITY_ORDER = {"informational": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


def _severity_max(values: List[str]) -> str:
    if not values:
        return "informational"
    return max(values, key=lambda value: SEVERITY_ORDER.get(value, 0))


class RuleEngine:
    def __init__(self, rules_path: Optional[Path] = None):
        self.rules_path = rules_path or settings.resolve_path(settings.rules_path)
        self.rules: List[Rule] = []
        self.error = None
        self.load()

    def load(self) -> None:
        try:
            with self.rules_path.open("r", encoding="utf-8") as handle:
                data = json.load(handle)
            self.rules = [self._parse_rule(item) for item in data.get("rules", [])]
            ids = [rule.id for rule in self.rules]
            if len(ids) != len(set(ids)):
                raise ValueError("Rule IDs must be unique")
        except Exception as exc:
            self.rules = []
            self.error = str(exc)

    def _parse_rule(self, item: Dict[str, Any]) -> Rule:
        required = {"id", "name", "description", "severity", "conditions"}
        missing = required - set(item)
        if missing:
            raise ValueError(f"Rule is missing required fields: {sorted(missing)}")
        severity = item["severity"]
        if severity not in SEVERITY_ORDER:
            raise ValueError(f"Unsupported severity '{severity}' for rule {item['id']}")
        return Rule(
            id=str(item["id"]),
            name=str(item["name"]),
            description=str(item["description"]),
            severity=severity,
            conditions=dict(item["conditions"]),
            mitre_techniques=list(item.get("mitre_techniques", [])),
            investigation_actions=list(item.get("investigation_actions", [])),
            enabled=bool(item.get("enabled", True)),
        )

    def status(self) -> Dict[str, Any]:
        return {"loaded": len(self.rules), "error": self.error, "rules": [rule.id for rule in self.rules]}

    def evaluate(
        self,
        event: NormalizedNetworkEvent,
        context: Optional[Dict[str, Any]] = None,
        threat_intel_hits: Optional[List[Dict[str, Any]]] = None,
    ) -> DetectorResult:
        context = context or {}
        threat_intel_hits = threat_intel_hits or []
        triggered: List[Dict[str, Any]] = []

        for rule in self.rules:
            if not rule.enabled:
                continue
            if self._matches(rule, event, context, threat_intel_hits):
                triggered.append(
                    {
                        "id": rule.id,
                        "name": rule.name,
                        "description": rule.description,
                        "severity": rule.severity,
                        "mitre_techniques": rule.mitre_techniques,
                        "investigation_actions": rule.investigation_actions,
                    }
                )

        severity = _severity_max([item["severity"] for item in triggered])
        return DetectorResult(
            source="rules",
            classification="RULE_MATCH" if triggered else "NO_RULE_MATCH",
            confidence=1.0 if triggered else 0.0,
            severity=severity,
            triggered_rules=triggered,
            mitre_techniques=sorted({tech for rule in triggered for tech in rule["mitre_techniques"]}),
            recommended_actions=sorted(
                {action for rule in triggered for action in rule["investigation_actions"]}
            ),
        )

    def _matches(
        self,
        rule: Rule,
        event: NormalizedNetworkEvent,
        context: Dict[str, Any],
        threat_intel_hits: List[Dict[str, Any]],
    ) -> bool:
        conditions = rule.conditions
        field = conditions.get("field")
        operator = conditions.get("operator")
        threshold = conditions.get("threshold")

        if operator == "threat_intel_match":
            min_confidence = float(conditions.get("min_confidence", 0.5))
            return any(float(hit.get("confidence", 0.0)) >= min_confidence for hit in threat_intel_hits)

        if operator == "context_gte":
            value = float(context.get(str(field), 0.0) or 0.0)
            return value >= float(threshold)

        value = self._event_value(event, str(field))
        if operator == "exists":
            return value not in (None, "", [])
        if value is None:
            return False
        if operator == "gte":
            return float(value) >= float(threshold)
        if operator == "lte":
            return float(value) <= float(threshold)
        if operator == "equals":
            return str(value).lower() == str(threshold).lower()
        if operator == "contains":
            return str(threshold).lower() in str(value).lower()
        return False

    def _event_value(self, event: NormalizedNetworkEvent, field: str):
        if hasattr(event, field):
            return getattr(event, field)
        return (event.raw_event or {}).get(field)


rule_engine = RuleEngine()
