"""Emit a self-contained HTML report by inlining findings.json into the viewer.

The viewer template is a complete, working file on its own: opened directly it
offers a dropzone. `--html` produces the same file with the data already embedded,
so what circulates is one artefact with no companion file to lose.

Why this exists at all: the person who runs the scan is rarely the person who can
authorise a change. Terminal output dies in the terminal. A page that opens
offline, prints cleanly, and states its own inability to phone home is a thing
that gets forwarded.
"""

from __future__ import annotations

import json
import os
from typing import Any, Dict

# The template ships with a null placeholder so it works unmodified.
PLACEHOLDER = '<script type="application/json" id="findings-data">null</script>'
TEMPLATE_NAME = "report.html"


def template_path() -> str:
    return os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                        "viewer", TEMPLATE_NAME)


def read_template() -> str:
    with open(template_path(), "r", encoding="utf-8") as handle:
        return handle.read()


def embed(document: Dict[str, Any], template: str = None) -> str:
    """Inline a findings document into the viewer template."""
    html = read_template() if template is None else template
    if PLACEHOLDER not in html:
        raise ValueError("viewer template is missing its data placeholder")

    payload = json.dumps(document, ensure_ascii=False, separators=(",", ":"))
    # A tool description containing "</script>" would otherwise close the block
    # early and drop the rest of the report into the document as markup. These
    # three escapes are valid JSON and make that impossible. The content being
    # escaped comes from MCP servers - the untrusted party this tool assesses -
    # so this is the one place the report's own data could attack its reader.
    payload = (payload.replace("<", "\\u003c")
                      .replace(">", "\\u003e")
                      .replace("&", "\\u0026")
                      .replace(" ", "\\u2028")
                      .replace(" ", "\\u2029"))

    block = '<script type="application/json" id="findings-data">{}</script>'.format(payload)
    return html.replace(PLACEHOLDER, block, 1)
