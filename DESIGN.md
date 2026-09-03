# Design notes

Why toolprint reports what it reports. These are the decisions most likely to
surprise you, and the reasoning behind each — mostly because getting them wrong
produces a tool people learn to ignore.

---

## Cost is per context, not per machine

A conversation loads exactly one client in one project. That pairing is the only
unit in which "what do my tools cost per conversation" has an answer.

All three multi-scope clients resolve the same way: the more specific scope
wins, the **whole** entry from that scope is used, and there is no field
merging.

| Client | Order (first wins) |
|---|---|
| Claude Code | local → project → user |
| Cursor | project → user |
| VS Code | workspace → user |

So 19 configured entries can resolve to 11 distinct servers, of which one
context loads 8. The machine-wide union is not a conservative overestimate — it
describes no state the system is ever in. Entries that lose are reported as
**shadowed**, because editing one has no effect and produces no warning.

Shadowing is per context, not global: an entry can lose in one project and win
in another.

## Annotations give a floor and a ceiling, and only a ceiling can be contradicted

A tool's declared annotations make two different kinds of claim, and conflating
them produces false accusations.

| Annotation | Means | Contradictable |
|---|---|---|
| `readOnlyHint: true` | ceiling = `read` | yes |
| `destructiveHint: false` | ceiling = `external` | yes |
| `readOnlyHint: false` | floor = `write` | no |
| `destructiveHint: true` | floor = `irreversible` | no |

`readOnlyHint: false` is equally true of a write, an outbound call and a delete.
The annotation vocabulary has no way to say "external", so a tool declaring
not-read-only and inferring as `external` is being as precise as the schema
allows — not contradicting itself. Treating that as a mislabel produced three
false accusations against one correctly-annotated server.

Annotations raise a classification and never lower it. A server asserting
read-only on a tool called `delete_account` is making a claim, not providing
evidence.

## `AUTH-001` applies only to remote transports

"No authentication" means something completely different for a local stdio
subprocess than for a remote endpoint. A filesystem server started on your own
machine has no credential because it needs none; a remote server with no
credential is reachable by anything that can reach the URL.

Flagging every local server as critically unauthenticated is the alert fatigue
that ends with everyone passing `--fail-on none`.

## Canonicalisation normalises structure and never content

Hashes are computed over an RFC 8785 canonical form after stripping transport
noise (`_meta`, `ttlMs`, `cacheScope`), dropping null optionals and sorting
arrays whose order carries no meaning.

**Unicode normalisation is deliberately absent and must not be added.** NFKC
collapses homoglyphs and strips zero-width characters, which is exactly the
payload of an invisible-character attack. `transfer` and `transfеr` (Cyrillic е)
hash **differently on purpose**, so the substitution is caught rather than
normalised away. Suspicious characters are found by a separate lexical pass;
folding and detecting are opposite jobs and do not share code.

`anyOf`, `oneOf` and `allOf` are never sorted — their order affects which error
a validator reports, so reordering them is a real change.

Same-document `$ref` is inlined before hashing. Schemas may now use any JSON
Schema 2020-12 keywords, so the same logical schema has two spellings, and a
server refactoring its generator would otherwise look like drift. External refs
are never fetched: following a URL supplied by the server under assessment would
be its own vulnerability.

## Hashes are per component, not one blob

`description_hash`, `schema_hash` and `annotations_hash` are separate because
the rug-pull signature is **description changed while schema did not**. An
attacker rewriting a tool's instructions has to leave the schema alone or the
tool stops working. Only component hashes show that correlation.

## Drift rules: specific before general

Ten rules, first match wins. The specific checks run before the general one:
text carrying a bidi override has, by definition, also changed its description,
so a general "description changed" rule would always claim it first and the
specific explanation would never print. All are the same severity, so nothing is
under-reported — the reader gets "invisible characters appeared" instead of "the
text changed", which is the difference between a finding and a diff.

## Baselines record the platform they were taken on

Some servers describe themselves differently depending on where they run.
`desktop-commander`'s `start_process` embeds *"Running on macOS. Default shell:
zsh."* and a block of OS-specific advice. Baseline that on a laptop, check it in
Linux CI, and the description hash differs forever — firing `DRIFT-003`, the
rug-pull rule, which is the worst one to cry wolf on.

The baseline records `sys.platform`, and a check from a different one says so.
The finding is **annotated, not suppressed**: a description rewritten on another
platform could still be a real attack, and hiding it would trade one failure
mode for a worse one.

The practical advice is simpler: baseline in the environment you check from.

## Exceptions require a reason and an expiry

A suppression that cannot lapse becomes permanent by neglect, and then nobody
reads the report. Expired exceptions stop suppressing and say so in the output.

Baselines also refuse to bless a suspicious state: trust-on-first-use means a
baseline approves whatever is in front of it, so `baseline` checks for invisible
characters, homoglyphs and cross-server shadowing first and will not write a
clean baseline over any of them without `--force`.

## Token counts are calibrated, not reasoned

Without `tiktoken`, counts use 4.55 characters per token — measured against 91
real tool definitions, not derived from the usual ~4.0 figure for English. The
intuition that JSON is denser than prose is wrong here and cost 26% of aggregate
accuracy when the constant was set by reasoning: tool schemas are dominated by a
small repeated vocabulary (`type`, `string`, `properties`, `description`) that
tokenises very efficiently. Re-measure rather than re-reason if it changes.

The method used is recorded per server, so a mixed run stays interpretable.

## Heuristics are versioned

Changing the effect-class verb lists reclassifies tools, which is otherwise
indistinguishable from real drift. `heuristics_version` is recorded in every
baseline, and a mismatch is a re-approval event rather than a finding.

## Nothing renders from raw collected data

`findings.json` is the contract. The CLI, the HTML viewer and any hand-written
report all render from it. That is also why the viewer is entirely client-side:
the file contains your tool names, descriptions and schemas, and is as sensitive
as the deployment it describes.
