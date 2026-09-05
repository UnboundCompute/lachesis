"""Candidate census for graph-temporal lifecycle patterns.

Temporal candidates are deliberately not findings.  They are the semantic
operation sites that a graph matcher must relate across compatible paths.  The
pattern identity and required event vocabulary come from Atropos; this module
only turns observable graph facts into the common candidate capsule shape.
"""
from __future__ import annotations

import hashlib

from ..flow import atropos


def merge_semantic_nodes(target, semantic_graph, language):
    """Merge one language's semantic nodes without losing language identity.

    Semantic node IDs are generated from function names and can collide when a
    multi-language project contains equally named functions.  Candidate census
    consumes nodes, not graph edges, so namespace only collisions while keeping
    the original ID in the node metadata.  Stamp language on each node because
    the graph-level language is lost when several graphs are combined.
    """
    payload = semantic_graph.to_dict()
    for raw_id, raw_node in (payload.get("nodes") or {}).items():
        node_id = str(raw_id)
        if node_id in target:
            node_id = f"{language}:{node_id}"
            suffix = 2
            while node_id in target:
                node_id = f"{language}:{raw_id}:{suffix}"
                suffix += 1
        node = dict(raw_node)
        metadata = dict(node.get("metadata") or {})
        metadata.setdefault("language", language)
        node["metadata"] = metadata
        target[node_id] = node
    return target


def _event_kind(node):
    props = node.get("properties") or {}
    event = node.get("event") or {}
    return str(props.get("event_kind") or event.get("kind") or
               node.get("kind") or "").lower().replace("eventkind.", "")


def _object_id(node):
    props = node.get("properties") or {}
    event = node.get("event") or {}
    for source in (props, event):
        for key in ("object_id", "target_id", "value_id", "obj", "base"):
            if source.get(key):
                return source[key]
    return None


class TemporalLifecycle:
    metadata = {}
    trigger = ()

    def __init__(self, graph, bind_summary=None):
        self.graph = graph
        self.bind_summary = bind_summary or {}
        raw_nodes = graph.get("nodes", ())
        if isinstance(raw_nodes, dict):
            self.nodes = [{"id": node_id, **(node or {})}
                          for node_id, node in raw_nodes.items()]
        else:
            self.nodes = list(raw_nodes)
        # Some callers attach the materialized semantic graph under this key;
        # accepting it keeps the registry useful before and after graph
        # publication without coupling it to the C frontend.
        semantic = graph.get("semantic_graph") or {}
        self.language = graph.get("language")
        if (isinstance(semantic, dict) and semantic.get("native_sidecar")
                and not semantic.get("nodes")):
            # Native Pass 2 persists the Rust protobuf sidecar by reference.
            # Expand it only when a temporal constructor is actually queried;
            # ``enrich`` itself must not parse a 300MB semantic graph merely to
            # build an unused registry.
            from ..nav.semantic_query import load_semantic_sidecar
            native = load_semantic_sidecar(
                semantic["native_sidecar"], self.language or "mixed")
            if native is not None:
                semantic = {
                    "nodes": native.to_dict().get("nodes", {}),
                    "coverage": semantic.get("coverage") or native.coverage,
                }
        self.coverage = {}
        if isinstance(semantic, dict):
            self.language = self.language or semantic.get("language")
            self.coverage = dict(semantic.get("coverage") or {})
            semantic_nodes = semantic.get("nodes", ())
            if isinstance(semantic_nodes, dict):
                self.nodes.extend([{"id": node_id, **(node or {})}
                                   for node_id, node in semantic_nodes.items()])
            else:
                self.nodes.extend(semantic_nodes)
        # When the native matcher has run its findings are authoritative for this
        # family: it has already related the temporal events across a reachable
        # path on one object, which the per-node inventory below cannot do.  Route
        # its findings to the right family by matcher pattern -- the same string
        # the Atropos declaration carries as ``matcher_pattern`` -- and let
        # ``enumerate`` surface those confirmed relations while suppressing the
        # pre-matcher inventory, so the census stops emitting one not-queried row
        # per dereference.  The key is present only on the converged native bind;
        # its absence (the fast structural path) keeps the inventory fallback.
        self.native_ran = "native_temporal" in graph
        pattern = self.metadata.get("matcher_pattern")
        self.native_findings = [
            (function.get("id"), finding)
            for function in graph.get("native_temporal", {}).get("functions", ())
            for finding in function.get("findings", ())
            if finding.get("pattern") == pattern
        ]
        # Declaration id -> {file, line}, resolved from the Pass-1 store at bind
        # time (the census graph dict has no function decl nodes). Lets a
        # matcher-confirmed lead report its file:line instead of ``file: None``.
        self.native_locations = dict(
            graph.get("native_temporal", {}).get("locations") or {})

    def _language(self, node):
        props = node.get("properties") or {}
        path = props.get("absolute_file") or props.get("file") or node.get("file") or ""
        metadata = node.get("metadata") or {}
        return (atropos.lang_of(path) if path else
                node.get("language") or metadata.get("language") or
                self.language or "c")

    def _candidate(self, node):
        props = node.get("properties") or {}
        metadata = node.get("metadata") or {}
        event = node.get("event") or {}
        site = node.get("id", "")
        pattern_id = self.metadata["id"]
        raw = f"{pattern_id}\0{site}"
        return {
            "candidate_id": "temporal_" + hashlib.sha256(raw.encode()).hexdigest()[:20],
            "constructor": pattern_id,
            "domain": "lifecycle",
            "language": self._language(node),
            "obligation": self.metadata["obligation"],
            "handles": {
                "site_node_id": site,
                "enclosing_function_id": (props.get("owner_function_id") or
                                            metadata.get("owner_function_id") or
                                            node.get("fragment")),
                "obligation_value_ids": ([obj] if (obj := _object_id(node)) else []),
            },
            "observations": {
                "site": node.get("label"),
                "event_kind": _event_kind(node),
                "object_id": _object_id(node),
                "file": (props.get("absolute_file") or props.get("file") or
                         node.get("file")),
                "line": (props.get("start_line") or props.get("line") or
                         event.get("line")),
                "pattern": self.metadata["matcher_pattern"],
                "requires": list(self.metadata["requires"]),
            },
            "inferences": {
                "path_relation": "not-queried",
                "same_object": "not-queried",
                "same_generation": "not-queried",
            },
            "rank": None,
            "rank_reasons": [],
            "completeness": "PARTIAL",
            "next_op": {"tool": "skeleton", "why": "inspect compatible temporal context"},
        }

    def _native_candidate(self, function_id, finding):
        """Render one matcher-confirmed temporal finding as a resolved candidate.

        The blanket per-node candidate leaves the temporal relation ``not-queried``;
        here the native matcher has proven it, so the relation facts are resolved
        (same object, same generation, reachable path).  This is still a lead for
        the judge to adjudicate, not a safety verdict: it reports what the matcher
        computed, and points at ``skeleton`` for the guards it does not weigh.
        """
        pattern_id = self.metadata["id"]
        node_id = finding.get("node") or ""
        line = finding.get("line")
        obj = finding.get("path") or None
        # The finding names its enclosing declaration directly; the wrapper
        # ``function_id`` is only the synthetic skeleton entry. Prefer the real
        # declaration so the handle points at the function and its file resolves.
        decl_id = finding.get("function") or function_id
        location = self.native_locations.get(decl_id) or {}
        # The native matcher is C-only: its findings can name only C declarations.
        # But semantic decl ids are generated from function names and collide when
        # a multi-language project holds equally named functions (see
        # ``merge_semantic_nodes``), so ``decl_id`` can resolve through the store to
        # a *non-C* declaration -- yielding a C-memory-model verdict (double-free,
        # use-after-free) stamped onto a Python/JS file that has no such semantics.
        # A resolved location whose file is not C is therefore a proven cross-language
        # id collision, not a real site; drop the finding rather than surface an
        # unreviewable false positive. (A ``None`` file is merely unresolved, not
        # mis-resolved, so it is left to the normal path.)
        loc_file = location.get("file")
        if loc_file and atropos.lang_of(loc_file) != "c":
            return None
        site = f"native:{function_id}:{node_id}:{line}"
        raw = f"{pattern_id}\0{site}"
        # An unvalidated family (``confirmable`` is false in its Atropos declaration
        # -- its native detector raises nothing on its own positive control) may
        # over-fire on real code: its soundness is unproven.  Surface its findings as
        # PARTIAL triage leads with the temporal relation left un-asserted, so an
        # unproven detector never lands a COMPLETE row a reviewer would trust as a
        # verdict.  When the detector earns confirmation (its control flips to
        # ``detected``), dropping the flag restores COMPLETE with no engine change.
        if not self.metadata.get("confirmable", True):
            return {
                "candidate_id": "temporal_" + hashlib.sha256(raw.encode()).hexdigest()[:20],
                "constructor": pattern_id,
                "domain": "lifecycle",
                "language": self.language or "c",
                "obligation": self.metadata["obligation"],
                "handles": {
                    "site_node_id": node_id,
                    "enclosing_function_id": decl_id,
                    "obligation_value_ids": [obj] if obj else [],
                },
                "observations": {
                    "site": node_id,
                    "event_kind": None,
                    "object_id": obj,
                    "file": location.get("file"),
                    "line": line if line is not None else location.get("line"),
                    "pattern": self.metadata["matcher_pattern"],
                    "requires": list(self.metadata["requires"]),
                    "native_path": obj,
                },
                "inferences": {
                    "path_relation": "reachable",
                    "same_object": "same",
                    "same_generation": "not-queried",
                },
                "rank": 0.4,
                "rank_reasons": [{
                    "term": "unvalidated-detector",
                    "why": ("this family's native detector raises nothing on its own "
                            "positive control, so its matches are unproven triage "
                            "leads a reviewer must confirm, not standalone verdicts"),
                }],
                "completeness": "PARTIAL",
                "next_op": {"tool": "skeleton",
                            "why": "confirm the temporal relation the unvalidated "
                                   "detector could not prove"},
            }
        # A lead pattern records an ownership shape (a field alias from an
        # aggregate copy), not a temporal violation: the matcher has related no
        # release/use pair, only observed the copy.  Surface it as a PARTIAL lead
        # for the judge -- so a benign `struct b = a` is never a COMPLETE verdict
        # -- while the downstream double-free/UAF that composes through the alias
        # remains the COMPLETE finding on its own row.
        if self.metadata.get("lead"):
            return {
                "candidate_id": "temporal_" + hashlib.sha256(raw.encode()).hexdigest()[:20],
                "constructor": pattern_id,
                "domain": "lifecycle",
                "language": self.language or "c",
                "obligation": self.metadata["obligation"],
                "handles": {
                    "site_node_id": node_id,
                    "enclosing_function_id": decl_id,
                    "obligation_value_ids": [obj] if obj else [],
                },
                "observations": {
                    "site": node_id,
                    "event_kind": None,
                    "object_id": obj,
                    "file": location.get("file"),
                    "line": line if line is not None else location.get("line"),
                    "pattern": self.metadata["matcher_pattern"],
                    "requires": list(self.metadata["requires"]),
                    "native_path": obj,
                },
                "inferences": {
                    "path_relation": "reachable",
                    "same_object": "same",
                    "same_generation": "not-queried",
                },
                "rank": 0.4,
                "rank_reasons": [{
                    "term": "ownership-shape-lead",
                    "why": ("the native matcher recorded a field alias from an "
                            f"{self.metadata['matcher_pattern']}; this is a lead a "
                            "downstream release/use pattern must confirm, not a "
                            "standalone verdict"),
                }],
                "completeness": "PARTIAL",
                "next_op": {"tool": "skeleton",
                            "why": "look for a downstream double-free/UAF that "
                                   "composes through this alias"},
            }
        return {
            "candidate_id": "temporal_" + hashlib.sha256(raw.encode()).hexdigest()[:20],
            "constructor": pattern_id,
            "domain": "lifecycle",
            "language": self.language or "c",
            "obligation": self.metadata["obligation"],
            "handles": {
                "site_node_id": node_id,
                "enclosing_function_id": decl_id,
                "obligation_value_ids": [obj] if obj else [],
            },
            "observations": {
                "site": node_id,
                "event_kind": None,
                "object_id": obj,
                "file": location.get("file"),
                "line": line if line is not None else location.get("line"),
                "pattern": self.metadata["matcher_pattern"],
                "requires": list(self.metadata["requires"]),
                "native_path": obj,
            },
            "inferences": {
                "path_relation": "reachable",
                "same_object": "same",
                "same_generation": "same",
            },
            "rank": 1.0,
            "rank_reasons": [{
                "term": "native-matcher",
                "why": ("the native temporal matcher related the "
                        f"{self.metadata['matcher_pattern']} events across a "
                        "reachable path on one object"),
            }],
            "completeness": "COMPLETE",
            "next_op": {"tool": "skeleton",
                        "why": "inspect the confirmed temporal context and its guards"},
        }

    def enumerate(self):
        if self.native_ran:
            # The matcher is authoritative: emit its confirmed findings (possibly
            # none) and suppress the pre-matcher inventory rather than drown the
            # confirmed relation in one not-queried row per dereference.
            # ``_native_candidate`` returns None for a finding whose decl id
            # collided onto a non-C declaration (a cross-language id clash); those
            # are dropped here so a C-memory verdict never lands on a non-C file.
            rows = [row for fid, finding in self.native_findings
                    if (row := self._native_candidate(fid, finding)) is not None]
        else:
            rows = [self._candidate(node) for node in self.nodes
                    if _event_kind(node) in self.trigger]
        rows.sort(key=lambda row: (row["observations"].get("file") or "",
                                   row["observations"].get("line") or 0,
                                   row["handles"]["site_node_id"]))
        uncovered = (len(self.coverage.get("uncovered_states", ()))
                     + len(self.coverage.get("uncovered_contexts", ())))
        by_status: dict[str, int] = {}
        for row in rows:
            status = row["inferences"].get("path_relation", "not-queried")
            by_status[status] = by_status.get(status, 0) + 1
        return {
            "constructor": self.metadata["id"],
            "domain": "lifecycle",
            "metadata": dict(self.metadata),
            "candidates": rows,
            "census": {"enumerated": len(rows), "by_status": by_status},
            "frontiers": {"unresolved_calls": uncovered, "unbound_models": 0,
                           "unbound_sinks": [], "truncated_walks": 0,
                           "missing_optional_capabilities": [],
                           "unselected_configs": []},
            "complete_for_observable_graph": bool(self.coverage.get("converged", True)),
        }


def temporal_constructor(spec):
    """Build a constructor directly from one Atropos candidate declaration."""
    entry = next((item for item in atropos.pattern_catalog()
                  if item.get("id") == spec["id"]), {})
    matcher = entry.get("matcher") or {}
    pattern = matcher.get("pattern") or spec.get("matcher_pattern")
    # The Atropos pattern declaration owns the event vocabulary.  Keeping this
    # routing data beside the public obligation means a new lifecycle pattern can
    # enter candidate_census without an engine-side family list or a new
    # constructor.  Candidate rows remain observations, never findings: the
    # semantic matcher must still prove the temporal relation.
    triggers = tuple(matcher.get("event_kinds") or ())
    return type("Temporal_" + spec["family"].replace("-", "_"),
                (TemporalLifecycle,), {
                    "trigger": triggers,
                    "metadata": {
                        "id": spec["id"], "domain": "lifecycle",
                        "family": spec["family"], "languages": spec["languages"],
                        "required_capabilities": ("semantic-events",),
                        "optional_capabilities": ("value-flow", "calls"),
                        "obligation": spec["obligation"],
                        "matcher_pattern": pattern,
                        "requires": spec.get("requires", ()),
                        # A `lead` pattern (e.g. aggregate-copy-alias) records an
                        # ownership shape the downstream typestate verdicts compose
                        # through; it is never a COMPLETE verdict on its own.  Keep
                        # its rows PARTIAL so a benign struct copy is a triage lead,
                        # not a confirmed bug.
                        "lead": bool(entry.get("lead")),
                        # A family whose native detector raises nothing on its own
                        # positive control is unvalidated: it may over-fire on real
                        # code (its soundness is unproven), so its findings are
                        # surfaced as PARTIAL triage leads, never COMPLETE verdicts,
                        # until the detector earns confirmation.  Absence defaults to
                        # confirmable so validated families are unaffected.
                        "confirmable": entry.get("confirmable", True),
                    },
                })
