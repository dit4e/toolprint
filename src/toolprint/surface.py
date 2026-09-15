"""What a tool's schema says about its own surface.

Some servers advertise routers rather than operations: one tool that takes an
operation name and a free-form object of arguments, with the real sub-commands
discovered at call time. Azure routes 64 of its 70 tools this way, sentry
collapsed 15 tools behind one executor in September 2026, and a generic kubectl
passthrough is the same shape.

The shape matters to two separate parts of this tool, which is why the test
lives here rather than in either of them: effect classification reads names and
schemas, and a router's say nothing; and drift compares the advertised surface,
which a router deliberately keeps small.
"""

from __future__ import annotations

import re
from typing import Any, Dict, Optional

# Names that select an operation rather than describe one. Deliberately short.
# "endpoint" was in an earlier draft and matched firecrawl_feedback, where it is
# a URL beside an unrelated metadata bag - a false positive of exactly the kind
# that makes a report stop being read. "name" is excluded for the same reason,
# despite sentry using it: it is the single most common parameter there is.
DISPATCH_NAMES = frozenset({"command", "operation", "action", "method", "subcommand"})

# ...so sentry is caught by the tool's own name instead. Measured across the 496
# tools of the public watch corpus, this pattern matches exactly one tool, and
# that tool is execute_sentry_tool.
EXECUTOR_NAME = re.compile(r"(^|_)(execute|exec|run|invoke|call|dispatch|perform)(_|$)", re.I)


def _constrains_values(schema: Any) -> bool:
    """Whether `additionalProperties` actually restricts what may be passed.

    An empty schema restricts nothing: `additionalProperties: {}` is how sentry
    declares "any arguments at all", and reading a bare {} as a constraint made
    the executor look like a well-specified object.
    """
    extra = schema.get("additionalProperties")
    return isinstance(extra, dict) and bool(extra)


def is_freeform_object(schema: Any) -> bool:
    """An object parameter that declares nothing about what goes inside it."""
    if not isinstance(schema, dict) or schema.get("type") != "object":
        return False
    properties = schema.get("properties")
    if isinstance(properties, dict) and properties:
        return False
    return not _constrains_values(schema)


# Where a tool's real operations are defined, and therefore what it takes to see
# them. Level 4 - behaviour that changes while the definition does not - is
# deliberately not here: it is invisible from the surface by definition, so it
# is a standing caveat, never a per-tool tag.
LEVEL_DECLARED = 1        # the tool list is the surface; read it and you are done
LEVEL_PACKAGE = 2         # a router whose operations ship inside the package
LEVEL_ENVIRONMENT = 3     # operations defined by a runtime environment, not the package

# Signals that a tool's operations come from a runtime environment outside the
# package. A starter set, cited, extended the way the prober's catalogue is: by
# adding a case with the evidence for it.
_ENV_DESCRIPTION = re.compile(
    r"registered by the page|page-provided|provided by the (?:page|site|website)", re.I)


def environment_source(tool: Dict[str, Any]) -> Optional[str]:
    """Name the runtime environment a tool's operations come from, or None.

    A router that matches nothing here is treated as package-defined (level 2),
    the conservative default: when it is unclear whether the operations ship
    with the package, assume they do, because that is the case a package probe
    can actually enumerate. Being wrong in this direction over-probes a level-3
    tool once; being wrong the other way would silently drop a package router
    from analysis.
    """
    if not isinstance(tool, dict):
        return None
    name = tool.get("name")
    name = name.lower() if isinstance(name, str) else ""
    description = tool.get("description")
    description = description if isinstance(description, str) else ""
    # @playwright/mcp 1.64.0-alpha browser_webmcp_call / browser_webmcp_list:
    # tools registered at runtime by the open web page, across frames.
    if "webmcp" in name or _ENV_DESCRIPTION.search(description):
        return "the open web page (per page, changes as pages load)"
    # mcp-server-kubernetes kubectl_generic: a command and args passed to
    # kubectl, whose surface is the cluster's API and the credential's RBAC.
    if name == "kubectl_generic":
        return "the cluster's API and the credential's permissions"
    return None


def capability_level(tool: Dict[str, Any]) -> int:
    """Where this tool's real operations are defined, from the surface alone.

    Environment first: a WebMCP list tool is not itself a router, but its
    capability is still the page's, so it must not be read as declared.
    """
    if environment_source(tool):
        return LEVEL_ENVIRONMENT
    if is_dispatch_router(tool):
        return LEVEL_PACKAGE
    return LEVEL_DECLARED


def is_dispatch_router(tool: Dict[str, Any]) -> bool:
    """A tool whose arguments are "which operation" plus "anything at all".

    Both halves are required. A free-form object on its own is a common and
    harmless way to pass options - firecrawl has four - and an operation
    selector on its own is usually an enum. Only together do they describe a
    tool whose real surface is somewhere other than its schema.
    """
    if not isinstance(tool, dict):
        return False
    schema = tool.get("inputSchema")
    if not isinstance(schema, dict):
        return False
    properties = schema.get("properties")
    if not isinstance(properties, dict):
        return False
    if not any(is_freeform_object(spec) for spec in properties.values()):
        return False

    selects = any(
        name.lower().replace("-", "").replace("_", "") in DISPATCH_NAMES
        and isinstance(spec, dict) and spec.get("type") == "string"
        for name, spec in properties.items())
    name = tool.get("name")
    return selects or bool(isinstance(name, str) and EXECUTOR_NAME.search(name))
