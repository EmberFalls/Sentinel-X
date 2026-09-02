"""Short-lived alert deduplication for streaming replay."""

from __future__ import annotations

from collections import OrderedDict
from datetime import timedelta

from sentinelx.core.schemas import AlertRecord


class AlertDeduplicator:
    def __init__(self, cooldown_seconds: int = 60, max_entries: int = 2000) -> None:
        self.cooldown = timedelta(seconds=cooldown_seconds)
        self.max_entries = max_entries
        self._seen = OrderedDict()

    def accept(self, alert: AlertRecord) -> bool:
        key = (
            alert.threat_class.value,
            str(alert.source.ip) if alert.source else "",
            str(alert.destination.ip) if alert.destination else "",
            alert.detector_id,
            alert.decision.value,
        )
        previous = self._seen.get(key)
        if previous and alert.timestamp - previous.timestamp < self.cooldown:
            return False
        self._seen[key] = alert
        self._seen.move_to_end(key)
        while len(self._seen) > self.max_entries:
            self._seen.popitem(last=False)
        return True

    def reset(self) -> None:
        self._seen.clear()
