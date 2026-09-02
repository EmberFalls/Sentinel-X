"""Validated alert creation, severity, and deduplication."""

from sentinelx.alerts.builder import build_alert
from sentinelx.alerts.dedupe import AlertDeduplicator

__all__ = ["AlertDeduplicator", "build_alert"]
