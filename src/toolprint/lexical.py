"""Lexical checks for characters that hide meaning from a human reader.

These are deliberately separate from hashing. Canonicalisation must never fold
these characters out - a homoglyph or an invisible character has to change the
hash so drift catches it - so the hash preserves them and this module reports
them. Folding and detecting are opposite jobs and must not share code.

What this looks for is text that reads one way to a reviewer and another way to a
model: zero-width characters splitting words, bidi controls reordering a line,
Cyrillic letters standing in for Latin ones, ANSI escapes that vanish in a
terminal, and tag characters that most editors render as nothing at all.
"""

from __future__ import annotations

import re
import unicodedata
from typing import Any, Dict, Iterable, List, Optional, Tuple

ZERO_WIDTH = {
    0x200B: "zero-width space", 0x200C: "zero-width non-joiner",
    0x200D: "zero-width joiner", 0x2060: "word joiner",
    0xFEFF: "zero-width no-break space", 0x180E: "Mongolian vowel separator",
    0x00AD: "soft hyphen",
}
BIDI = {
    0x200E: "left-to-right mark", 0x200F: "right-to-left mark",
    0x202A: "left-to-right embedding", 0x202B: "right-to-left embedding",
    0x202C: "pop directional formatting", 0x202D: "left-to-right override",
    0x202E: "right-to-left override", 0x2066: "left-to-right isolate",
    0x2067: "right-to-left isolate", 0x2068: "first strong isolate",
    0x2069: "pop directional isolate",
}
ANSI_ESCAPE = re.compile(r"\x1b\[[0-9;?]*[ -/]*[@-~]|\x1b[@-Z\\-_]")
# Tag characters (U+E0000-E007F) render as nothing almost everywhere and can
# carry a full ASCII message invisibly.
TAG_RANGE = (0xE0000, 0xE007F)
PRIVATE_USE = ((0xE000, 0xF8FF), (0xF0000, 0xFFFFD), (0x100000, 0x10FFFD))

# Scripts whose letters are routinely confused with Latin. Range-based because
# the standard library exposes no script property.
SCRIPT_RANGES: Tuple[Tuple[str, int, int], ...] = (
    ("Latin", 0x0041, 0x005A), ("Latin", 0x0061, 0x007A),
    ("Latin", 0x00C0, 0x024F), ("Latin", 0x1E00, 0x1EFF),
    ("Greek", 0x0370, 0x03FF), ("Greek", 0x1F00, 0x1FFF),
    ("Cyrillic", 0x0400, 0x04FF), ("Cyrillic", 0x0500, 0x052F),
    ("Armenian", 0x0530, 0x058F),
    ("Hebrew", 0x0590, 0x05FF),
    ("Arabic", 0x0600, 0x06FF),
    ("Cherokee", 0x13A0, 0x13FF),
)

WORD = re.compile(r"[^\W\d_]{2,}", re.UNICODE)

# Severity is decided by the finding engine; these are the categories.
ZERO_WIDTH_FOUND = "zero_width"
BIDI_FOUND = "bidi_control"
ANSI_FOUND = "ansi_escape"
TAG_FOUND = "tag_characters"
PRIVATE_FOUND = "private_use"
MIXED_SCRIPT = "mixed_script"


def script_of(char: str) -> Optional[str]:
    point = ord(char)
    for name, low, high in SCRIPT_RANGES:
        if low <= point <= high:
            return name
    return None


def _in_ranges(point: int, ranges: Iterable[Tuple[int, int]]) -> bool:
    return any(low <= point <= high for low, high in ranges)


def _describe(char: str) -> str:
    try:
        name = unicodedata.name(char)
    except ValueError:
        name = "unnamed"
    return "U+{:04X} {}".format(ord(char), name)


def inspect(text: Optional[str]) -> List[Dict[str, Any]]:
    """Return one finding per suspicious construct. Never returns the raw text.

    Positions are reported so a reviewer can locate the character without the
    report having to reproduce an attack payload verbatim.
    """
    if not isinstance(text, str) or not text:
        return []
    found: List[Dict[str, Any]] = []

    for index, char in enumerate(text):
        point = ord(char)
        if point in ZERO_WIDTH:
            found.append({"kind": ZERO_WIDTH_FOUND, "at": index,
                          "detail": "{} ({})".format(_describe(char), ZERO_WIDTH[point])})
        elif point in BIDI:
            found.append({"kind": BIDI_FOUND, "at": index,
                          "detail": "{} ({})".format(_describe(char), BIDI[point])})
        elif TAG_RANGE[0] <= point <= TAG_RANGE[1]:
            found.append({"kind": TAG_FOUND, "at": index, "detail": _describe(char)})
        elif _in_ranges(point, PRIVATE_USE):
            found.append({"kind": PRIVATE_FOUND, "at": index, "detail": _describe(char)})

    for match in ANSI_ESCAPE.finditer(text):
        found.append({"kind": ANSI_FOUND, "at": match.start(),
                      "detail": "terminal escape sequence, {} bytes".format(len(match.group(0)))})

    for match in WORD.finditer(text):
        word = match.group(0)
        scripts = {script_of(c) for c in word}
        scripts.discard(None)
        if len(scripts) > 1:
            # The classic homoglyph: one Cyrillic letter inside a Latin word.
            odd = [(_describe(c), script_of(c)) for c in word
                   if script_of(c) and script_of(c) != "Latin"]
            found.append({
                "kind": MIXED_SCRIPT, "at": match.start(),
                "detail": "word mixes {}: {}".format(
                    ", ".join(sorted(scripts)),
                    "; ".join("{} [{}]".format(d, s) for d, s in odd[:3])),
            })

    found.sort(key=lambda f: (f["at"], f["kind"]))
    return found


def inspect_tool(tool: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Check every free-text field a model reads."""
    out: List[Dict[str, Any]] = []
    for field in ("name", "title", "description"):
        for item in inspect(tool.get(field)):
            out.append(dict(item, field=field))
    schema = tool.get("inputSchema")
    if isinstance(schema, dict):
        properties = schema.get("properties")
        if isinstance(properties, dict):
            for prop in sorted(properties):
                value = properties[prop]
                if isinstance(value, dict):
                    for item in inspect(value.get("description")):
                        out.append(dict(item, field="inputSchema.properties.{}".format(prop)))
    return out


def is_distinctive(name: str) -> bool:
    """Is this tool name specific enough that seeing it in prose means something?

    Structure only: a separator or a camelCase boundary, as in `contact_delete`,
    `issues.create` or `createIssue`. A bare single word is never distinctive,
    however long.

    Length was tried as a second clause and had to be removed. At six characters
    it matched `search`, `delete` and `create`; raised to twelve it still matched
    `documentation`, which is an Azure tool name and also a word that appears in
    seven other servers' descriptions - every one of them a false shadowing
    report, and every one of them blocking a baseline from being written.
    `configuration` and `authentication` would do the same.

    The trade is deliberate. Missing a reference to an unusual single-word tool
    name costs one detection path, and the mutation rules still cover the tool.
    A false positive here refuses to write a baseline, which is how a security
    tool teaches people to pass --force by reflex.
    """
    if any(sep in name for sep in ("_", ".", "-", "/", ":")):
        return True
    return bool(re.search(r"[a-z0-9][A-Z]", name))


def shadowing(tools_by_server: Dict[str, List[Dict[str, Any]]]) -> List[Dict[str, Any]]:
    """Descriptions that name another server's tools.

    Cross-server shadowing: a description telling the model how to use, or when
    to prefer, a tool belonging to a different server. Legitimate rarely, and a
    hijack the rest of the time.
    """
    owners: Dict[str, str] = {}
    own_names: Dict[str, set] = {}
    for server, tools in tools_by_server.items():
        own_names[server] = set()
        for tool in tools:
            name = tool.get("name")
            if not isinstance(name, str):
                continue
            own_names[server].add(name)
            if is_distinctive(name) and name not in owners:
                owners[name] = server

    found: List[Dict[str, Any]] = []
    for server in sorted(tools_by_server):
        for tool in tools_by_server[server]:
            text = " ".join(str(tool.get(f) or "") for f in ("description", "title"))
            if not text.strip():
                continue
            for other_name in sorted(owners):
                if owners[other_name] == server or other_name == tool.get("name"):
                    continue
                # A server describing a tool it also implements is not reaching
                # across a boundary. Tool names recur legitimately - Sentry and
                # GitHub both ship `search_issues` - and ownership here is just
                # "whichever server was seen first", so without this the second
                # one is accused of shadowing the first for describing its own
                # feature.
                if other_name in own_names.get(server, ()):
                    continue
                if re.search(r"\b{}\b".format(re.escape(other_name)), text):
                    found.append({
                        "server": server, "tool": tool.get("name"),
                        "references": other_name, "owned_by": owners[other_name],
                    })
    return found
