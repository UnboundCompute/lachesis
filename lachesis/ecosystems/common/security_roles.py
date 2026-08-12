"""Portable entry-parameter and sensitive-call security role policies."""
from __future__ import annotations

import re

from ...core.composition import GraphDelta
from ...core.identities import stable_id
from ...core.query import GraphIndex


# An exported parameter is an external taint source only when it looks like
# externally-derived input. Grading by name/type (and by whether its owner is a
# request boundary) both DE-NOISES (a config scalar like `secret`/`botAppId` is no
# longer tagged as tainted as a raw body) AND collapses the taint-BFS source count
# — the single biggest amplifier of the super-linear build.
NAME_REQUEST_RE = re.compile(
    r"url|uri|href|endpoint|request|\breq\b|body|payload|\binput\b|param|\bquery\b"
    r"|\bevent\b|header|cookie|\bform\b|upload|webhook|\bdata\b|content|message|\bmsg\b",
    re.IGNORECASE,
)
TYPE_REQUEST_RE = re.compile(
    r"\b(URL|URI|Request|Response|IncomingMessage|ServerRequest|Readable|Buffer"
    r"|Stream|FormData|Headers|Uint8Array|ArrayBuffer|Blob|Socket)\b",
)
BOUNDARY_FUNCTION_RE = re.compile(
    r"handle|webhook|route|controller|middleware|endpoint|\bserve\b|listen"
    r"|subscribe|consume|dispatch|resolver",
    re.IGNORECASE,
)
# Resource identifiers are the classic IDOR / broken-object-level-authorization
# external input: a caller-supplied handle (documentId, invoiceId, uuid, slug)
# that addresses a stored record and flows to an unscoped data-access sink. These
# are NOT request-named or boundary-owned, so without this class the IDOR surface
# (the whole point of a resource-handler param) would be silently dropped by the
# de-noising gate. Targeted to identifier shapes — not "every param" — so a config
# scalar (secret, botAppId... note: botAppId ends in Id, see NON_IDENTIFIER_RE).
IDENTIFIER_RE = re.compile(
    r"(^|_)(id|ids|uuid|guid|slug|ref|handle)$|(?<![A-Z])Id$|(?<![A-Z])Ids$"
    r"|Uuid$|Guid$|Slug$",
)
# Identifier-shaped names that are really credentials/config, not object handles.
NON_IDENTIFIER_RE = re.compile(
    r"secret|token|apikey|appid|clientid|tenantid|sessionid|requestid|traceid|nonce",
    re.IGNORECASE,
)


SENSITIVE_CALLS = {
    "eval": "dynamic-code",
    "Function": "dynamic-code",
    "fetch": "network",
    "exec": "process",
    "execFile": "process",
    "spawn": "process",
    "writeFile": "filesystem-write",
    "writeFileSync": "filesystem-write",
    "query": "database",
    "execute": "database",
    "rename": "filesystem-write",
    "findById": "database",
    "findOne": "database",
    "send": "response",
    "json": "response",
    "redirect": "response",
}


# Beyond the exact high-signal names above, recognise sensitive operations by
# targeted name families so real codebases (whose sink calls are rarely one of the
# 15 exact names) still materialize sinks. Deliberately targeted — no ultra-common
# verbs (get/map/parse) — so the graph doesn't drown. Graded confidence; the strict
# judge adjudicates. First match wins; exact SENSITIVE_CALLS takes precedence.
#
# A family alternative has to stay a *substring of an operation name*, not of any
# name that contains the verb. `execute` and `rename` unanchored matched
# `executeArchiveRoom` and `renameRoom`, which are application functions that
# delegate: the real query is inside them and is already a sink of its own, so each
# match manufactured a duplicate sink whose "operation" was a function call. Both
# verbs keep an exact entry above, which is what covers `fs.rename(...)` and a bare
# `execute(...)`, so the tightening costs no real sink.
SINK_FAMILIES = [
    (re.compile(r"\beval\b|^Function$|runInContext|runInNewContext|createFunction"), "dynamic-code", "high"),
    (re.compile(r"^exec$|execSync|execFile|spawn(Sync)?|\bfork\b|execa"), "process", "high"),
    (re.compile(r"writeFile|appendFile|createWriteStream|unlink|rmdir|^rm$|mkdir|rename(Sync|File|Dir|Path)|copyFile|chmod|symlink"), "filesystem-write", "medium"),
    (re.compile(r"\bfetch\b|axios|\bgot\b|https?Request|createConnection|sendBeacon|XMLHttpRequest|\bky\b"), "network", "medium"),
    (re.compile(r"findOne|findById|findMany|\bfindAll\b|\bquery\b|execute(Query|Sql|SQL|Statement|Raw|Batch)|rawQuery|\.raw\b|aggregate|deleteMany|updateMany|insertMany|createQueryBuilder"), "database", "medium"),
    (re.compile(r"readFile|createReadStream|readdir|realpath"), "filesystem-read", "low"),
    (re.compile(r"deserialize|unserialize|parseXml|loadYaml|fromJSON"), "deserialize", "low"),
]


def _classify_sink(name: str) -> tuple[str, str] | None:
    """Return (sink_kind, confidence) for a call name, or None if not sensitive."""
    subtype = SENSITIVE_CALLS.get(name)
    if subtype:
        return subtype, "high"
    for pattern, subtype, confidence in SINK_FAMILIES:
        if pattern.search(name):
            return subtype, confidence
    return None


def _last_name(value: str) -> str:
    normalized = value.split("?.")[-1]
    if "." in normalized:
        normalized = normalized.rsplit(".", 1)[-1]
    if "[" in normalized:
        normalized = normalized.rsplit("[", 1)[-1]
    return normalized.strip("'\"`] ")


class GenericSecurityRoleModel:
    """Tag public inputs and mechanically named sensitive operations."""

    model_id = "generic-security-roles"
    supported_languages = (
        "typescript", "javascript", "python", "java", "go", "csharp",
        "ruby", "c", "cpp",
    )
    required_capabilities = ("calls", "direct_data_flow")

    def applies(self, graph: dict, package_inventory: frozenset[str]) -> bool:
        del package_inventory
        return any(
            node.get("kind") in {"function", "method", "call", "construct"}
            for node in graph.get("nodes", [])
        )

    def enrich(self, graph: dict) -> GraphDelta:
        index = GraphIndex(graph)
        nodes = []
        edges = []
        exported = {
            edge["target"] for edge in index.edges_of_kind("EXPORTS")
            if index.nodes.get(edge["target"], {}).get("kind")
                in {"function", "method", "constructor"}
        }
        route_targets = {
            edge["target"]
            for kind in ("ROUTE_HANDLED_BY", "WIRES_TO")
            for edge in index.edges_of_kind(kind)
        }
        for parameter in index.nodes_of_kind("parameter"):
            properties = parameter.get("properties", {})
            owner_id = properties.get("owner_function_id")
            if owner_id not in exported:
                continue
            provenance = properties.get("provenance")
            if provenance and provenance != "application":
                continue  # never tag standard-library / dependency parameters
            name = str(parameter.get("label", ""))
            type_text = str(properties.get("type", ""))
            owner_name = str(index.nodes.get(owner_id, {}).get("label", ""))
            is_request = bool(
                NAME_REQUEST_RE.search(name) or TYPE_REQUEST_RE.search(type_text)
            )
            is_identifier = bool(
                IDENTIFIER_RE.search(name) and not NON_IDENTIFIER_RE.search(name)
            )
            is_boundary = bool(
                owner_id in route_targets or BOUNDARY_FUNCTION_RE.search(owner_name)
            )
            if is_request:
                source_kind, confidence = "request-input", "high"
            elif is_identifier:
                # Caller-supplied object handle → IDOR / BOLA surface.
                source_kind, confidence = "resource-identifier", "medium"
            elif is_boundary:
                source_kind, confidence = "boundary-parameter", "medium"
            else:
                continue  # generic exported scalar/config param: not an external source
            source_id = stable_id(
                "runtime-model", self.model_id, "source", parameter["id"],
            )
            evidence = [owner_id, parameter["id"]]
            fact = {
                "fact_origin": "runtime-model",
                "confidence": confidence,
                "evidence_ids": evidence,
            }
            nodes.append({
                "id": source_id,
                "kind": "source",
                "label": f"public parameter:{parameter.get('label', parameter['id'])}",
                "properties": {
                    **fact,
                    "model_id": self.model_id,
                    "value_id": parameter["id"],
                    "source_kind": source_kind,
                    "function_id": owner_id,
                },
            })
            edges.append({
                "kind": "TAINT_SOURCE", "source": source_id,
                "target": parameter["id"], "properties": fact,
            })

        for call in index.nodes_of_kind("call", "construct"):
            properties = call.get("properties", {})
            name = properties.get("method_name") or _last_name(
                str(properties.get("callee") or call.get("label", ""))
            )
            classified = _classify_sink(name)
            if not classified:
                continue
            subtype, confidence = classified
            value_id = properties.get("value_id") or call["id"]
            if value_id not in index.nodes:
                value_id = call["id"]
            sink_id = stable_id(
                "runtime-model", self.model_id, "sink", call["id"], subtype,
            )
            evidence = [call["id"], value_id]
            fact = {
                "fact_origin": "runtime-model",
                "confidence": confidence,
                "evidence_ids": list(dict.fromkeys(evidence)),
            }
            nodes.append({
                "id": sink_id,
                "kind": "sink",
                "label": f"{subtype}:{call.get('label', name)}",
                "properties": {
                    **fact,
                    "model_id": self.model_id,
                    "value_id": value_id,
                    "sink_kind": subtype,
                    "callsite_id": call["id"],
                },
            })
            edges.append({
                "kind": "TAINT_SINK", "source": sink_id,
                "target": value_id, "properties": fact,
            })

        return GraphDelta(self.model_id, nodes, edges)

