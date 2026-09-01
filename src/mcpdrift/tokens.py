"""Token accounting for tool definitions.

What is being counted is the tool definition as it reaches the model: name,
title, description and schemas. The exact wire format differs slightly per
client, so this is an estimate of a real quantity rather than an exact count of
a specific one - and the report says so, because a precise-looking number nobody
can reproduce is worse than an honest range.

tiktoken is used when importable and a character-ratio approximation otherwise.
The method is recorded per server so a mixed run stays interpretable, and it is
never installed on the user's behalf: the zero-dependency claim is load-bearing
for the collection kit's auditability.
"""

from __future__ import annotations

import json
from typing import Any, Dict, List, Optional, Tuple

METHOD_TIKTOKEN = "tiktoken"
METHOD_APPROXIMATION = "approximation"

# Calibrated, not guessed. Measured against 91 real tool definitions from 11
# servers on 2026-08-31: 122,645 characters to 26,961 cl100k_base tokens.
#
# The intuition that JSON is denser than prose - more punctuation, so fewer
# characters per token - is wrong here and cost 26% of aggregate accuracy when
# this constant was set to 3.6 by reasoning rather than measurement. Tool schemas
# are dominated by a small repeated vocabulary ("type", "string", "properties",
# "description") that tokenises very efficiently, which makes them *less* dense
# than English prose, not more.
#
# Re-measure rather than re-reason if this needs changing.
CHARS_PER_TOKEN = 4.55
APPROXIMATION_ERROR = "median 4%, p95 9% per tool; ~0% aggregate"
CALIBRATION_BASIS = "91 tools / 11 servers, 2026-08-31"

# Fields the model actually receives. outputSchema and annotations are included
# because they are part of what is sent, not merely metadata about it.
COUNTED_FIELDS = ("name", "title", "description", "inputSchema", "outputSchema", "annotations")

_encoder = None
_encoder_tried = False


def _get_encoder():
    global _encoder, _encoder_tried
    if _encoder_tried:
        return _encoder
    _encoder_tried = True
    try:
        import tiktoken  # noqa: F401  (optional extra)

        _encoder = tiktoken.get_encoding("cl100k_base")
    except Exception:
        _encoder = None
    return _encoder


def available_method() -> str:
    return METHOD_TIKTOKEN if _get_encoder() is not None else METHOD_APPROXIMATION


def count_text(text: str) -> Tuple[int, str]:
    encoder = _get_encoder()
    if encoder is not None:
        return len(encoder.encode(text)), METHOD_TIKTOKEN
    return int(round(len(text) / CHARS_PER_TOKEN)), METHOD_APPROXIMATION


def serialise_tool(tool: Dict[str, Any]) -> str:
    """The payload a tool contributes to context, as closely as we can model it."""
    subset = {k: tool[k] for k in COUNTED_FIELDS if k in tool and tool[k] is not None}
    return json.dumps(subset, ensure_ascii=False, separators=(",", ":"), sort_keys=True)


def count_tools(tools: List[Dict[str, Any]]) -> Tuple[Dict[str, int], int, str]:
    """Return (per-tool counts, total, method)."""
    per_tool: Dict[str, int] = {}
    total = 0
    method = available_method()
    for tool in tools:
        name = tool.get("name")
        if not isinstance(name, str):
            continue
        count, method = count_text(serialise_tool(tool))
        per_tool[name] = count
        total += count
    return per_tool, total, method


def describe_method(method: Optional[str]) -> str:
    if method == METHOD_TIKTOKEN:
        return "tiktoken cl100k_base (approximates Claude tokenisation)"
    if method == METHOD_APPROXIMATION:
        return "character ratio {} chars/token ({}); error {}".format(
            CHARS_PER_TOKEN, CALIBRATION_BASIS, APPROXIMATION_ERROR)
    return "not counted"
