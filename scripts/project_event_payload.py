#!/usr/bin/env python3
"""Computes the exact byte size of TriggerRecall's RecallAlert event JSON
for the real N=10/100/1,000 benchmark batches, using the same encoding
Go's encoding/json performs (alphabetically sorted map keys, no inserted
whitespace) and the real token IDs / transaction IDs already committed
for those batches.

This is not an estimate: scripts/measure_event_payload.sh confirms this
exact reconstruction method reproduces a live-captured event byte-for-byte
(see evidence/event_payload_measurement.log). Re-triggering the original
N=10/100/1,000 batches directly was not possible, since TriggerRecall on
an already-recalled batch returns affectedCount:0 with an empty
recalledTokens array rather than the original event.
"""
import json

BATCHES = [
    (10, "", "BENCH-10", "599154021ebfac90b36620157972962a97bae138085744b4dc669cb17c8a7dae"),
    (100, "", "BENCH-100", "bbc26235d4a06e9c5e0e79e5af036612a70e65d3317c159401a5489518f4ecb8"),
    (1000, "B", "BENCH-1000B", "86df1f35792f32d5ea417e635ea17ccb9513989daeed1f8dd8d67fd4128df8e0"),
]

for n, suffix, batch, txid in BATCHES:
    tokens = sorted(f"BCOMP-{n}{suffix}-{i}" for i in range(1, n + 1))
    obj = {
        "affectedCount": n,
        "batchId": batch,
        "notifiedOwners": ["Tier2Supplier"],
        "recalledTokens": tokens,
        "skippedOverlap": [],
        "txId": txid,
    }
    encoded = json.dumps(obj, separators=(",", ":"))
    print(f"N={n}: {len(encoded)} bytes")
