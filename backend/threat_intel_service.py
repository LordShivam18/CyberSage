import json
import time
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional

from sqlalchemy.orm import Session

from .config import settings
from .models import ThreatIntelCache


class ThreatIntelProvider:
    name = "base"

    def lookup(self, indicator: str, indicator_type: str) -> Optional[Dict[str, Any]]:
        raise NotImplementedError


class LocalIndicatorProvider(ThreatIntelProvider):
    name = "local_indicators"

    def __init__(self):
        self.indicators: Dict[str, Dict[str, Any]] = {}
        self._load()

    def _load(self):
        path = settings.resolve_path(settings.local_indicator_path)
        if not path.exists():
            return
        with path.open("r", encoding="utf-8") as handle:
            data = json.load(handle)
        for item in data.get("indicators", []):
            value = str(item.get("value", "")).lower()
            if value:
                self.indicators[value] = item

    def lookup(self, indicator: str, indicator_type: str) -> Optional[Dict[str, Any]]:
        item = self.indicators.get(str(indicator).lower())
        if not item:
            return None
        confidence = float(item.get("confidence", 0.5))
        return {
            "indicator": indicator,
            "indicator_type": indicator_type,
            "source": item.get("source", self.name),
            "confidence": confidence,
            "verdict": "suspicious" if confidence < 0.85 else "malicious",
            "details": {
                "description": item.get("description", "Local indicator list match"),
                "tags": item.get("tags", []),
            },
        }


class DisabledExternalProvider(ThreatIntelProvider):
    def __init__(self, name: str):
        self.name = name

    def lookup(self, indicator: str, indicator_type: str) -> Optional[Dict[str, Any]]:
        return None


class ThreatIntelService:
    def __init__(self, providers: Optional[List[ThreatIntelProvider]] = None, timeout_seconds: Optional[float] = None):
        self.timeout_seconds = settings.threat_intel_timeout_seconds if timeout_seconds is None else timeout_seconds
        self.providers: List[ThreatIntelProvider] = providers if providers is not None else [LocalIndicatorProvider()]
        if settings.threat_intel_external_enabled:
            self.providers.extend(
                [
                    DisabledExternalProvider("alienvault_otx_placeholder"),
                    DisabledExternalProvider("virustotal_placeholder"),
                    DisabledExternalProvider("misp_placeholder"),
                ]
            )

    def lookup(self, indicator: str, indicator_type: str, db: Optional[Session] = None) -> List[Dict[str, Any]]:
        if not indicator:
            return []
        cached = self._lookup_cache(indicator, indicator_type, db)
        if cached:
            return cached
        hits = []
        for provider in self.providers:
            started = time.monotonic()
            result = provider.lookup(indicator, indicator_type)
            elapsed = time.monotonic() - started
            if elapsed > self.timeout_seconds:
                hits.append(
                    {
                        "indicator": indicator,
                        "indicator_type": indicator_type,
                        "source": provider.name,
                        "confidence": 0.0,
                        "verdict": "timeout",
                        "details": {"timeout_seconds": self.timeout_seconds, "elapsed_seconds": round(elapsed, 4)},
                    }
                )
                continue
            if result:
                hits.append(result)
                self._store_cache(result, db)
        return hits

    def lookup_event_indicators(self, event, db: Optional[Session] = None) -> List[Dict[str, Any]]:
        indicators = [
            (event.source_ip, "ip"),
            (event.destination_ip, "ip"),
            (event.host_id, "host"),
            (event.device_id, "device"),
        ]
        hits = []
        seen = set()
        for value, indicator_type in indicators:
            if not value or value in seen:
                continue
            seen.add(value)
            hits.extend(self.lookup(str(value), indicator_type, db=db))
        return hits

    def _lookup_cache(self, indicator: str, indicator_type: str, db: Optional[Session]) -> List[Dict[str, Any]]:
        if db is None:
            return []
        now = datetime.now(timezone.utc).replace(tzinfo=None)
        rows = (
            db.query(ThreatIntelCache)
            .filter(
                ThreatIntelCache.indicator == indicator,
                ThreatIntelCache.indicator_type == indicator_type,
                ThreatIntelCache.expires_at > now,
            )
            .all()
        )
        return [
            {
                "indicator": row.indicator,
                "indicator_type": row.indicator_type,
                "source": row.source,
                "confidence": row.confidence,
                "verdict": row.verdict,
                "details": row.details,
                "cached": True,
            }
            for row in rows
        ]

    def _store_cache(self, result: Dict[str, Any], db: Optional[Session]) -> None:
        if db is None:
            return
        expires_at = datetime.now(timezone.utc).replace(tzinfo=None) + timedelta(
            seconds=settings.threat_intel_cache_ttl_seconds
        )
        db.add(
            ThreatIntelCache(
                indicator=result["indicator"],
                indicator_type=result["indicator_type"],
                source=result["source"],
                confidence=float(result["confidence"]),
                verdict=result["verdict"],
                details=result.get("details", {}),
                expires_at=expires_at,
            )
        )
        db.flush()


threat_intel_service = ThreatIntelService()
