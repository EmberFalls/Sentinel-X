"""DNS lexical and behavioural features from visible passive DNS metadata."""

from __future__ import annotations

from collections import Counter

from sentinelx.core.enums import FeatureFamily
from sentinelx.core.ids import make_window_id
from sentinelx.core.schemas import CapabilityProfile, FeatureVector, PacketObservation
from sentinelx.features.schema import DNS_SCHEMA_VERSION, shannon_entropy, stable_bucket
from sentinelx.state.windows import TemporalSnapshot


def _query(packet: PacketObservation) -> dict | None:
    if not packet.dns_metadata:
        return None
    for query in packet.dns_metadata.get("queries", []):
        if isinstance(query, dict):
            return query
    return None


class DNSFeatureExtractor:
    """Create DNS features while explicitly marking hidden query text unavailable."""

    NGRAM_BUCKETS = 8

    def extract(
        self,
        packet: PacketObservation,
        state: TemporalSnapshot,
        capabilities: CapabilityProfile,
    ) -> FeatureVector:
        query = _query(packet)
        domain = query.get("name") if query else None
        domain = domain.lower() if isinstance(domain, str) and domain else None
        labels = domain.split(".") if domain else []
        characters = list(domain.replace(".", "")) if domain else []
        counts = Counter(characters)
        values: dict[str, int | float | None] = {
            "domain_length": len(domain) if domain else None,
            "subdomain_count": max(len(labels) - 2, 0) if domain else None,
            "mean_label_length": (sum(len(label) for label in labels) / len(labels))
            if labels
            else None,
            "character_entropy": shannon_entropy(characters) if domain else None,
            "digit_ratio": (sum(character.isdigit() for character in characters) / len(characters))
            if characters
            else None,
            "letter_ratio": (sum(character.isalpha() for character in characters) / len(characters))
            if characters
            else None,
            "hyphen_ratio": (characters.count("-") / len(characters)) if characters else None,
            "repeated_character_ratio": (
                sum(count for count in counts.values() if count > 1) / len(characters)
            )
            if characters
            else None,
            "query_type": int(query["type"]) if query and query.get("type") is not None else None,
            "query_frequency": state.recent_domains.count(domain) if domain else None,
            "unique_domain_ratio": len(set(state.recent_domains))
            / max(len(state.recent_domains), 1)
            if state.recent_domains
            else None,
        }
        for bucket in range(self.NGRAM_BUCKETS):
            values[f"bigram_bucket_{bucket}"] = None if not domain else 0
        if domain:
            for first, second in zip(domain, domain[1:], strict=False):
                bucket = stable_bucket(first + second, self.NGRAM_BUCKETS)
                key = f"bigram_bucket_{bucket}"
                values[key] = int(values[key] or 0) + 1
        availability = {
            key: capabilities.has_dns_query_name
            if key != "query_type"
            else capabilities.has_dns_query_type
            for key in values
        }
        for key, is_available in availability.items():
            if not is_available:
                values[key] = None
        return FeatureVector(
            family=FeatureFamily.DNS,
            schema_version=DNS_SCHEMA_VERSION,
            entity_id=f"dns:{packet.src_ip}",
            window_id=make_window_id(str(packet.src_ip), state.observed_at, state.window_seconds),
            values=values,
            availability=availability,
        )
