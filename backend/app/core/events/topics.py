"""Bus topics. One constant per published event so producers and consumers cannot drift."""

from __future__ import annotations

# Normalised, validated events awaiting indexing (ingestion API -> indexer worker).
EVENTS_NORMALIZED = "events.normalized"

# Incidents gained links (correlation -> enrichment worker). Payload: {"indicators": ["ip:…", "domain:…"]}.
INCIDENTS_CHANGED = "incidents.changed"
