"""Canonicalisation and hashing. This decides whether drift detection works.

The pipeline, per spec section 7:

    strip transport noise -> drop null-valued optional keys -> sort known-unordered
    arrays -> RFC 8785 (JCS) -> SHA-256

**Normalise structure, never content.** This is the rule the whole file exists to
protect. Unicode normalisation is NOT applied to string values and must never be
added: NFKC collapses homoglyphs and strips zero-width characters, which is
exactly the payload of an invisible-character attack. `transfer` and `transfеr`
(Cyrillic е) MUST hash differently, so a description mutated into a lookalike is
caught rather than normalised away. Suspicious characters are found by a separate
lexical check (see lexical.py), not by folding them out of the hash.

Hashes are per component, not one blob, because the rug-pull signature is
`description_hash` changed while `schema_hash` is unchanged: an attacker
injecting instructions has to preserve the schema or the tool stops working. That
correlation is only visible if the components are hashed separately.
"""

from __future__ import annotations

import hashlib
import re
from typing import Any, Dict, List, Optional, Tuple

# Transport-layer keys that vary per response and say nothing about the tool.
# ttlMs and cacheScope became REQUIRED on tools/list results in 2026-07-28, so
# without this strip every single scan would report drift.
NOISE_KEYS = ("_meta", "ttlMs", "cacheScope")
NOISE_PREFIXES = ("io.modelcontextprotocol/",)

# Arrays whose order carries no meaning, so a server reordering them is not a
# change. anyOf/oneOf/allOf are deliberately absent: their order affects which
# error a validator reports, so reordering them IS a change.
UNORDERED_ARRAY_KEYS = ("required", "enum")

MAX_REF_DEPTH = 16

RESOLVED = "resolved"
UNRESOLVED_EXTERNAL = "unresolved_external"
CYCLE = "cycle"
TOO_DEEP = "too_deep"


# --------------------------------------------------------------------------
# RFC 8785 JSON Canonicalisation Scheme
# --------------------------------------------------------------------------

_ESCAPES = {
    '"': '\\"', "\\": "\\\\", "\b": "\\b", "\f": "\\f",
    "\n": "\\n", "\r": "\\r", "\t": "\\t",
}


def _escape(value: str) -> str:
    out = []
    for char in value:
        if char in _ESCAPES:
            out.append(_ESCAPES[char])
        elif char < "\x20":
            out.append("\\u{:04x}".format(ord(char)))
        else:
            # Everything else is emitted literally, including zero-width and
            # bidi characters. Escaping or removing them here would hide the
            # attack this tool is meant to surface.
            out.append(char)
    return '"' + "".join(out) + '"'


def _number(value: Any) -> str:
    """ECMAScript Number::toString, which JCS defers to."""
    if isinstance(value, bool):  # bool is a subclass of int; check it first
        return "true" if value else "false"
    if isinstance(value, int):
        return str(value)
    if value != value or value in (float("inf"), float("-inf")):
        raise ValueError("JCS cannot serialise non-finite numbers")
    if value == int(value) and abs(value) < 1e21:
        return str(int(value))
    text = repr(value)
    # Python writes 1e+21; ECMAScript writes 1e+21 too, but pads exponents
    # differently in some builds. Normalise the exponent form.
    return re.sub(r"e([+-])0*(\d)", r"e\1\2", text)


def _sort_key(key: str) -> Tuple[int, ...]:
    """JCS sorts object keys by UTF-16 code unit, not by code point.

    These differ above the BMP: an astral character is one code point but two
    surrogate code units, and surrogates sort below U+E000-U+FFFF. Sorting by
    code point would order such keys differently from every conforming
    implementation, and two canonicalisers that disagree are worse than none.
    """
    return tuple(key.encode("utf-16-be").hex(" ").split())  # type: ignore[return-value]


def jcs(value: Any) -> str:
    """Serialise to the RFC 8785 canonical form."""
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (int, float)):
        return _number(value)
    if isinstance(value, str):
        return _escape(value)
    if isinstance(value, (list, tuple)):
        return "[" + ",".join(jcs(item) for item in value) + "]"
    if isinstance(value, dict):
        items = sorted(value.items(), key=lambda kv: _sort_key(str(kv[0])))
        return "{" + ",".join(_escape(str(k)) + ":" + jcs(v) for k, v in items) + "}"
    raise TypeError("cannot canonicalise {!r}".format(type(value).__name__))


def sha256_of(value: Any) -> str:
    return hashlib.sha256(jcs(value).encode("utf-8")).hexdigest()


# --------------------------------------------------------------------------
# Structural normalisation
# --------------------------------------------------------------------------

def strip_noise(value: Any) -> Any:
    """Remove transport-layer keys wherever they appear."""
    if isinstance(value, dict):
        return {
            k: strip_noise(v) for k, v in value.items()
            if k not in NOISE_KEYS and not any(k.startswith(p) for p in NOISE_PREFIXES)
        }
    if isinstance(value, list):
        return [strip_noise(item) for item in value]
    return value


def drop_nulls(value: Any) -> Any:
    """Drop null-valued keys. An absent optional key and an explicitly null one
    describe the same tool, and servers differ on which they send."""
    if isinstance(value, dict):
        return {k: drop_nulls(v) for k, v in value.items() if v is not None}
    if isinstance(value, list):
        return [drop_nulls(item) for item in value]
    return value


def sort_unordered(value: Any, key: Optional[str] = None) -> Any:
    """Sort arrays whose order is not semantic. Never composition keywords."""
    if isinstance(value, dict):
        return {k: sort_unordered(v, k) for k, v in value.items()}
    if isinstance(value, list):
        items = [sort_unordered(item) for item in value]
        # "type" may be a string or an array of strings; the array form is a set.
        if key in UNORDERED_ARRAY_KEYS or (key == "type" and all(isinstance(i, str) for i in items)):
            try:
                return sorted(items, key=lambda i: jcs(i))
            except TypeError:
                return items
        return items
    return value


def resolve_refs(schema: Any) -> Tuple[Any, str]:
    """Inline same-document $ref before hashing. Returns (schema, status).

    SEP-2106 loosened inputSchema to any JSON Schema 2020-12 keywords, including
    $ref. The same logical schema can now be written inline or as a reference
    into $defs, so a server refactoring its schema generator changes the hash
    with no semantic change - the false positive that gets a tool `--fail-on
    none`'d. External refs are never fetched: this runs offline, and following a
    URL from a server being assessed would be its own vulnerability.
    """
    if not isinstance(schema, dict):
        return schema, RESOLVED

    root = schema
    status = [RESOLVED]

    def pointer(ref: str) -> Any:
        if not ref.startswith("#"):
            status[0] = UNRESOLVED_EXTERNAL
            return None
        node: Any = root
        for part in [p for p in ref.lstrip("#").split("/") if p]:
            part = part.replace("~1", "/").replace("~0", "~")
            if isinstance(node, dict) and part in node:
                node = node[part]
            elif isinstance(node, list) and part.isdigit() and int(part) < len(node):
                node = node[int(part)]
            else:
                status[0] = UNRESOLVED_EXTERNAL
                return None
        return node

    def walk(node: Any, depth: int, seen: Tuple[str, ...]) -> Any:
        if depth > MAX_REF_DEPTH:
            status[0] = TOO_DEEP
            return node
        if isinstance(node, dict):
            ref = node.get("$ref")
            if isinstance(ref, str):
                if ref in seen:
                    status[0] = CYCLE
                    return {"$ref": ref}
                target = pointer(ref)
                if target is None:
                    return {"$ref": ref}
                merged = walk(target, depth + 1, seen + (ref,))
                extra = {k: walk(v, depth + 1, seen) for k, v in node.items() if k != "$ref"}
                if isinstance(merged, dict):
                    combined = dict(merged)
                    combined.update(extra)
                    return combined
                return merged
            return {k: walk(v, depth + 1, seen) for k, v in node.items()}
        if isinstance(node, list):
            return [walk(item, depth + 1, seen) for item in node]
        return node

    resolved = walk(schema, 0, ())
    if isinstance(resolved, dict):
        # $defs exists only to be referenced; once inlined it is not part of the
        # contract, and leaving it in would make pruning an unused definition
        # look like a change.
        resolved = {k: v for k, v in resolved.items() if k not in ("$defs", "definitions")}
    return resolved, status[0]


def canonicalise(value: Any, resolve: bool = False) -> Tuple[Any, str]:
    """The full structural pipeline. Returns (normalised value, ref status)."""
    status = RESOLVED
    if resolve:
        value, status = resolve_refs(value)
    return sort_unordered(drop_nulls(strip_noise(value))), status


# --------------------------------------------------------------------------
# Component hashes
# --------------------------------------------------------------------------

def hash_tool(tool: Dict[str, Any]) -> Dict[str, Any]:
    """Component hashes for one tool definition.

    Split rather than one blob: `description_hash` changed while `schema_hash`
    is unchanged is the rug-pull signature, and only component hashes show it.
    """
    description, _ = canonicalise({
        "description": tool.get("description"), "title": tool.get("title")})
    input_schema, input_status = canonicalise(tool.get("inputSchema"), resolve=True)
    output_schema, output_status = canonicalise(tool.get("outputSchema"), resolve=True)
    annotations, _ = canonicalise({"annotations": tool.get("annotations")})

    schema_status = input_status if input_status != RESOLVED else output_status
    hashes = {
        "description_hash": sha256_of(description),
        "schema_hash": sha256_of({"inputSchema": input_schema, "outputSchema": output_schema}),
        "annotations_hash": sha256_of(annotations),
        "schema_resolution": schema_status,
    }
    hashes["composite_hash"] = sha256_of({
        "name": tool.get("name"),
        "description_hash": hashes["description_hash"],
        "schema_hash": hashes["schema_hash"],
        "annotations_hash": hashes["annotations_hash"],
    })
    return hashes


def hash_server(tools: List[Dict[str, Any]], instructions: Optional[str] = None) -> Dict[str, str]:
    """Per-server hashes: the instruction string, and the toolset as a whole."""
    pairs = sorted(
        (t.get("name"), hash_tool(t)["composite_hash"])
        for t in tools if isinstance(t.get("name"), str)
    )
    return {
        "instructions_hash": sha256_of({"instructions": instructions}),
        "toolset_hash": sha256_of(pairs),
    }
