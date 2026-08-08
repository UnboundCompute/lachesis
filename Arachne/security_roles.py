"""Security-role derivation and guard detection over the built Arachne graph.

This is a *read-only projection* helper for the layered security graph. It never
mutates the input graph — it consumes the flat ``{nodes, edges}`` graph (indexed)
plus the per-file records and returns, keyed by existing node id:

  * ``derive_roles`` -> role annotations (EntryPoint / Source / Sink / Boundary /
    Middleware / State) attached to the nodes that carry them.
  * ``detect_guards`` -> per-(handler, sink) GUARDED_BY / UNGUARDED verdicts with
    the differential (a guarded sibling on the same sink), plus witnesses.

The Guard signal is the novel piece: it must come from the operation/branch layer,
NOT from taint. The guard on ``findById`` is applied *post-fetch* on the returned
record (``if (rec.tenantId !== currentTenant(ctx)) return 403``), so the taint that
flows into ``findById(id)`` is byte-identical for the guarded and the unguarded
handler. We therefore key GUARDED_BY on a *comparison operation whose operands are a
property-access on the fetched record and a call to an authorization/identity
accessor*, which is exactly what separates ``getInvoice`` from ``getDocument``.
"""
from collections import defaultdict

# --- role vocabulary --------------------------------------------------------
ROLE_ENTRYPOINT = "EntryPoint"
ROLE_SOURCE = "Source"
ROLE_SINK = "Sink"
ROLE_GUARD = "Guard"
ROLE_BOUNDARY = "Boundary"
ROLE_MIDDLEWARE = "Middleware"
ROLE_STATE = "State"

# Authorization / identity accessors whose result gates a sink. Extensible; would
# also be fed by `authz-decision` sink models once those are added to runtime_models.
AUTHZ_ACCESSORS = {
    "currentTenant", "verifyInbound", "principalKey", "currentUser",
    "requireUser", "currentSession", "authorize", "checkPermission", "can",
}

# Data-access sinks that have no runtime-model today; matched by name (evidence
# "name-only"). db-read is the default subtype for these.
SINK_NAME_HINTS = {
    "findById": "db-read", "findOne": "db-read", "findMany": "db-read",
    "query": "db-read", "execute": "db-read",
}

# runtime-model behavior -> Sink subtype.
BEHAVIOR_SINK_SUBTYPE = {
    "network-request": "net",
    "filesystem-read": "fs",
    "filesystem-write": "fs",
    "process-execution": "exec",
    "worker-spawn": "exec",
    "parse": "deserialize",
    "message-send": "net",
    "message-publish": "net",
    "emits-event": "net",
    "worker-message": "net",
}

# wiring_kind -> role.
WIRING_ROLE = {
    "route": ROLE_ENTRYPOINT,
    "event-subscriber": ROLE_ENTRYPOINT,
    "tool-registration": ROLE_ENTRYPOINT,
    "controller": ROLE_BOUNDARY,
    "middleware": ROLE_MIDDLEWARE,
    "orm-model": ROLE_BOUNDARY,
    "dependency-injection": ROLE_BOUNDARY,
    "config-dispatch": ROLE_BOUNDARY,
    "module-registration": ROLE_BOUNDARY,
    "decorator": ROLE_BOUNDARY,
}

STATE_KINDS = {
    "singleton", "module-state", "static-initializer", "module-initializer",
    "import-cycle",
}


def _annotate(role_of, node_id, role, subtype=None, confidence="high", witnesses=None):
    """Attach a role to a node id (a node may carry several roles)."""
    if node_id is None:
        return
    entry = {
        "role": role, "subtype": subtype, "confidence": confidence,
        "witnesses": sorted(set(witnesses or [])),
    }
    role_of[node_id].append(entry)


# --- sink classification ----------------------------------------------------

def classify_sinks(index):
    """Return {call_node_id: {"callee", "subtype", "evidence"}} for sink calls.

    Union of three signals: runtime-model behaviors (call-site subtype),
    flow-confirmed tainted-calls, and name hints for un-modeled data sinks.
    """
    sinks = {}

    # runtime-model-application nodes carry call_id + behaviors.
    for node in index.nodes.values():
        if node["kind"] != "runtime-model-application":
            continue
        call_id = node["properties"].get("call_id")
        if not call_id:
            continue
        subtype = None
        for behavior in node["properties"].get("behaviors", []):
            if behavior in BEHAVIOR_SINK_SUBTYPE:
                subtype = BEHAVIOR_SINK_SUBTYPE[behavior]
                break
        if subtype:
            call = index.nodes.get(call_id)
            sinks[call_id] = {
                "callee": call["label"] if call else "?",
                "subtype": subtype, "evidence": "runtime-model",
            }

    # flow-confirmed tainted-call nodes.
    for node in index.nodes.values():
        if node["kind"] != "tainted-call":
            continue
        call_id = node["properties"].get("call_id")
        if not call_id:
            continue
        call = index.nodes.get(call_id)
        callee = call["label"] if call else "?"
        existing = sinks.get(call_id)
        if existing:
            existing["evidence"] = "taint-flow+" + existing["evidence"]
        else:
            sinks[call_id] = {
                "callee": callee,
                "subtype": SINK_NAME_HINTS.get(callee, "unclassified"),
                "evidence": "taint-flow",
            }

    # name-hinted data sinks (findById & friends) even without a taint flow.
    for node in index.nodes.values():
        if node["kind"] != "call":
            continue
        callee = node["label"]
        if callee in SINK_NAME_HINTS and node["id"] not in sinks:
            sinks[node["id"]] = {
                "callee": callee, "subtype": SINK_NAME_HINTS[callee],
                "evidence": "name-only",
            }
    return sinks


# --- role derivation --------------------------------------------------------

def derive_roles(index, files):
    """Derive security roles for every node that carries one.

    Returns {node_id: [role_annotation, ...]}.
    """
    role_of = defaultdict(list)

    # Source: every taint-source node.
    for node in index.nodes.values():
        if node["kind"] == "taint-source":
            _annotate(
                role_of, node["id"], ROLE_SOURCE,
                subtype=node["properties"].get("source_kind"),
                confidence=node["properties"].get("confidence", "high"),
                witnesses=[node["properties"].get("value_id")],
            )

    # Sink: classified call nodes.
    sinks = classify_sinks(index)
    for call_id, info in sinks.items():
        confidence = "high" if info["evidence"].startswith("taint-flow") else "medium"
        _annotate(
            role_of, call_id, ROLE_SINK, subtype=info["subtype"],
            confidence=confidence, witnesses=[info["evidence"]],
        )

    # EntryPoint / Boundary / Middleware: wiring-boundary nodes (+ wired targets).
    wires_to = defaultdict(list)  # boundary_id -> [function_id]
    for edge in index.by_kind.get("WIRES_TO", []):
        wires_to[edge["source"]].append(edge["target"])
    for node in index.nodes.values():
        if node["kind"] != "wiring-boundary":
            continue
        wiring_kind = node["properties"].get("wiring_kind")
        role = WIRING_ROLE.get(wiring_kind, ROLE_BOUNDARY)
        _annotate(
            role_of, node["id"], role, subtype=wiring_kind,
            confidence=node["properties"].get("confidence", "medium"),
            witnesses=[node["properties"].get("mechanism")],
        )
        # Promote the wired handler function to EntryPoint for ingress kinds.
        if role == ROLE_ENTRYPOINT:
            for function_id in wires_to.get(node["id"], []):
                _annotate(
                    role_of, function_id, ROLE_ENTRYPOINT, subtype=wiring_kind,
                    confidence="high", witnesses=[node["id"]],
                )

    # EntryPoint: functions that own a boundary taint-source (request handlers).
    for node in index.nodes.values():
        if node["kind"] == "taint-source":
            function_id = node["properties"].get("function_id")
            if function_id:
                _annotate(
                    role_of, function_id, ROLE_ENTRYPOINT, subtype="request-handler",
                    confidence="medium", witnesses=[node["id"]],
                )

    # Boundary: dynamic-behavior dispatch surfaces.
    for node in index.nodes.values():
        if node["kind"] == "dynamic-behavior":
            _annotate(
                role_of, node["id"], ROLE_BOUNDARY,
                subtype=node["properties"].get("behavior_kind"),
                confidence="medium",
            )

    # State: singletons / module-state / static + module initializers / cycles.
    for node in index.nodes.values():
        if node["kind"] in STATE_KINDS:
            _annotate(
                role_of, node["id"], ROLE_STATE, subtype=node["kind"],
                confidence="high",
            )

    return role_of, sinks


# --- guard detection --------------------------------------------------------

def _calls_in_function(index):
    """function_id -> [call_node_id] via CONTAINS_CALL."""
    result = defaultdict(list)
    for edge in index.by_kind.get("CONTAINS_CALL", []):
        result[edge["source"]].append(edge["target"])
    return result


def _operations_by_function(files):
    result = defaultdict(list)
    for info in files:
        for operation in info["operations"]:
            if operation.get("function_id"):
                result[operation["function_id"]].append(operation)
    return result


def _returns_by_function(files):
    result = defaultdict(list)
    for info in files:
        for statement in info["statements"]:
            if statement.get("function_id") and statement.get("kind") == "return":
                result[statement["function_id"]].append(statement)
    return result


def _comparison_is_authz_guard(index, comparison, function_call_labels):
    """Does this comparison operation compare a fetched property against an authz
    accessor? Returns (is_guard, witnesses) where witnesses are the operand ids.

    Structured check first (OPERATION_INPUT operands -> PERFORMS_CALL -> authz call
    + a property-access operand); text fallback if operand edges are sparse.
    """
    comparison_id = comparison["id"]
    operand_edges = [
        edge for edge in index.inn.get(comparison_id, [])
        if edge["kind"] == "OPERATION_INPUT"
    ]
    has_authz_call = False
    has_property_access = False
    witnesses = [comparison_id]
    for edge in operand_edges:
        operand_id = edge["source"]
        operand = index.nodes.get(operand_id)
        if not operand:
            continue
        if operand.get("kind") == "operation":
            op_kind = operand["properties"].get("operation_kind")
            if op_kind == "property-access":
                has_property_access = True
                witnesses.append(operand_id)
            if op_kind == "call":
                for performs in index.out.get(operand_id, []):
                    if performs["kind"] == "PERFORMS_CALL":
                        call = index.nodes.get(performs["target"])
                        if call and call["label"] in AUTHZ_ACCESSORS:
                            has_authz_call = True
                            witnesses.append(performs["target"])
    if has_authz_call and has_property_access:
        return True, witnesses

    # Text fallback: the comparison text names an authz accessor and a property.
    text = comparison.get("text", "")
    if "." in text and any(name in text for name in AUTHZ_ACCESSORS):
        # confirm the accessor is actually invoked inside this function
        if any(label in AUTHZ_ACCESSORS for label in function_call_labels):
            return True, [comparison_id]
    return False, []


def detect_guards(index, files, sinks):
    """Per-(handler, sink) GUARDED_BY / UNGUARDED verdicts.

    A handler is any function that contains a sink call. v1 = name-based guard
    (a contained call to an authz accessor). v2 = operation-level guard (a
    comparison of a fetched property against an authz accessor). v2 wins.
    The differential flags an UNGUARDED handler that has a GUARDED sibling on the
    same sink callee.
    """
    calls_in_fn = _calls_in_function(index)
    ops_by_fn = _operations_by_function(files)
    returns_by_fn = _returns_by_function(files)
    sink_call_ids = set(sinks)

    # For each function: its sink call sites (by callee name) + callee label set.
    verdicts = []
    fn_sink_names = {}  # function_id -> set of sink callee names
    fn_status = {}      # function_id -> "GUARDED" | "UNGUARDED"

    for function_id, call_ids in calls_in_fn.items():
        sink_sites = [cid for cid in call_ids if cid in sink_call_ids]
        if not sink_sites:
            continue
        function = index.nodes.get(function_id)
        if not function:
            continue
        call_labels = {
            index.nodes[cid]["label"]
            for cid in call_ids if cid in index.nodes
        }
        sink_names = {sinks[cid]["callee"] for cid in sink_sites}
        fn_sink_names[function_id] = sink_names

        # v1: name-based guard.
        v1_guards = call_labels & AUTHZ_ACCESSORS

        # v2: operation-level authz guard.
        v2_guard = False
        v2_witnesses = []
        for operation in ops_by_fn.get(function_id, []):
            if operation.get("kind") != "comparison":
                continue
            is_guard, witnesses = _comparison_is_authz_guard(
                index, operation, call_labels
            )
            if is_guard:
                v2_guard = True
                v2_witnesses = witnesses
                break

        if v2_guard:
            status, signal, confidence = "GUARDED", "operation-cfg-v2", "high"
            witnesses = list(v2_witnesses)
        elif v1_guards:
            status, signal, confidence = "GUARDED", "name-v1", "medium"
            witnesses = sorted(
                cid for cid in call_ids
                if index.nodes.get(cid, {}).get("label") in AUTHZ_ACCESSORS
            )
        else:
            status, signal, confidence = "UNGUARDED", None, "medium"
            witnesses = []

        # deny-return witness (early forbidden/throw) if present.
        for statement in returns_by_fn.get(function_id, []):
            text = (statement.get("text") or "").lower()
            if any(token in text for token in ("403", "401", "forbidden", "unauthor", "throw")):
                witnesses.append(statement["id"])

        fn_status[function_id] = status
        verdicts.append({
            "handler_id": function_id,
            "handler_label": function["label"],
            "file": function["properties"].get("file"),
            "line": function["properties"].get("start_line"),
            "sink_names": sorted(sink_names),
            "sink_call_ids": sorted(sink_sites),
            "status": status,
            "guard_signal": signal,
            "confidence": confidence,
            "witnesses": sorted(set(w for w in witnesses if w)),
        })

    # Differential: an UNGUARDED handler with a GUARDED sibling on the same sink.
    for verdict in verdicts:
        if verdict["status"] != "UNGUARDED":
            verdict["differential_siblings"] = []
            continue
        my_sinks = set(verdict["sink_names"])
        siblings = [
            index.nodes[other]["label"]
            for other, names in fn_sink_names.items()
            if other != verdict["handler_id"]
            and (names & my_sinks)
            and fn_status.get(other) == "GUARDED"
        ]
        verdict["differential_siblings"] = sorted(siblings)

    return verdicts
