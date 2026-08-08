"""Attacker-source tagging and context-sensitive transitive taint closure."""
import hashlib
import re
from collections import defaultdict, deque
from typing import Dict, Iterable, List, Optional, Set, Tuple


BOUNDARY_FUNCTION_RE = re.compile(
    r"^(?:handle|handler|webhook|route|endpoint|middleware|loader|action|"
    r"GET|POST|PUT|PATCH|DELETE|OPTIONS|HEAD)(?:$|[A-Z_$])",
    re.IGNORECASE,
)
REQUEST_TYPE_RE = re.compile(
    r"(?:^|\W)(?:InboundRequest|Request|NextRequest|NextApiRequest|"
    r"IncomingMessage|APIGateway\w*Event|HttpRequest)(?:\W|$)",
    re.IGNORECASE,
)
REQUEST_NAME_RE = re.compile(r"^(?:req|request|event|httpRequest)$", re.IGNORECASE)
UNTRUSTED_REQUEST_PATHS = {
    "body", "query", "params", "parameter", "path", "headers", "cookies",
    "rawBody", "url", "method", "form", "files", "data", "payload",
}
MAX_CONTEXT_DEPTH = 12


def stable_id(kind: str, *parts) -> str:
    raw = ":".join(str(part) for part in parts)
    digest = hashlib.sha256(f"{kind}:{raw}".encode("utf-8")).hexdigest()[:16]
    return f"{kind}:{digest}"


def _boundary_function(function: dict, exported_names: Set[str]) -> bool:
    return (
        function["name"] in exported_names
        and bool(BOUNDARY_FUNCTION_RE.search(function["name"]))
    )


def analyze_taint(files: Iterable[dict]) -> None:
    """Tag inbound sources and materialize context-aware transitive taint."""
    file_list = list(files)
    value_owner: Dict[str, dict] = {}
    records: Dict[str, dict] = {}
    symbols: Dict[str, dict] = {}
    definitions_by_symbol: Dict[str, List[dict]] = defaultdict(list)
    calls: Dict[str, Tuple[dict, dict]] = {}

    for info in file_list:
        info["taint_sources"] = []
        info["taint_flows"] = []
        info["taint_reaches"] = []
        info["tainted_calls"] = []
        for symbol in info["symbols"]:
            symbols[symbol["id"]] = symbol
        for collection in (
            "definitions", "reads", "arguments", "returns", "phi_nodes",
            "heap_locations", "heap_accesses",
        ):
            for record in info[collection]:
                value_owner[record["id"]] = info
                records[record["id"]] = record
        for definition in info["definitions"]:
            definitions_by_symbol[definition["symbol_id"]].append(definition)
        for call in info["function_calls"]:
            calls[call["id"]] = (info, call)
            value_owner[call["id"]] = info
            value_owner[call["return_value_id"]] = info
            records[call["return_value_id"]] = call
        for context in info["call_contexts"]:
            value_owner[context["return_value_id"]] = info
            records[context["return_value_id"]] = context
            for binding in context["parameter_bindings"]:
                value_owner[binding["id"]] = info
                records[binding["id"]] = binding

    sources = []

    def add_source(
        info: dict, value_id: str, kind: str, label: str,
        function_id: str, line: int, confidence: str = "high",
        parent_source_id: Optional[str] = None,
    ) -> dict:
        source = {
            "id": stable_id("taint-source", value_id, kind),
            "value_id": value_id, "kind": kind, "label": label,
            "function_id": function_id, "line": line,
            "confidence": confidence, "parent_source_id": parent_source_id,
        }
        if not any(existing["id"] == source["id"] for existing in sources):
            sources.append(source)
            info["taint_sources"].append(source)
        return source

    # Boundary status is intentionally narrow: an exported request handler is
    # an ingress, while an ordinary helper accepting Request is not a second,
    # artificial source when reached from that handler.
    boundary_parameter_sources = {}
    for info in file_list:
        exported_names = set(info["exports"])
        functions = {function["id"]: function for function in info["functions"]}
        for symbol in info["symbols"]:
            if symbol["kind"] != "parameter":
                continue
            function = functions.get(symbol.get("owner_function_id"))
            if not function or not _boundary_function(function, exported_names):
                continue
            declared_type = symbol.get("declared_type") or ""
            if not (
                REQUEST_TYPE_RE.search(declared_type)
                or REQUEST_NAME_RE.fullmatch(symbol["name"])
            ):
                continue
            definitions = definitions_by_symbol.get(symbol["id"], [])
            if not definitions:
                continue
            definition = min(definitions, key=lambda item: item["offset"])
            source = add_source(
                info, definition["id"], "request-parameter",
                f"{function['name']} parameter {symbol['name']}",
                function["id"], definition["line"],
            )
            boundary_parameter_sources[symbol["id"]] = source

        properties = {item["id"]: item for item in info["properties"]}
        for definition in info["definitions"]:
            if definition.get("origin") != "property-read":
                continue
            property_info = properties.get(definition["symbol_id"])
            if not property_info:
                continue
            parent_source = boundary_parameter_sources.get(
                property_info["base_symbol_id"]
            )
            first_path = property_info["path"].split(".", 1)[0]
            if not parent_source or first_path not in UNTRUSTED_REQUEST_PATHS:
                continue
            symbol = symbols[property_info["base_symbol_id"]]
            add_source(
                info, definition["id"], "request-property",
                f"{symbol['name']}.{property_info['path']}",
                parent_source["function_id"], definition["line"],
                parent_source_id=parent_source["id"],
            )

    direct = []
    direct_keys = set()

    def add_flow(
        kind: str, source: Optional[str], target: Optional[str],
        transition: str = "local", context_id: Optional[str] = None,
        **properties,
    ) -> None:
        if not source or not target or source == target:
            return
        key = (kind, source, target, transition, context_id)
        if key in direct_keys:
            return
        direct_keys.add(key)
        direct.append({
            "kind": kind, "source": source, "target": target,
            "transition": transition, "context_id": context_id,
            "properties": properties,
        })

    # Branch-aware reads are the base of all local evaluation flow.
    for info in file_list:
        for read in info["reads"]:
            for definition_id in read.get(
                "reaching_definition_ids", [read["definition_id"]]
            ):
                add_flow("TAINT_READ", definition_id, read["id"])

        reads = info["reads"]
        calls_in_file = info["function_calls"]
        for collection, kind in (
            (info["definitions"], "TAINT_ASSIGN"),
            (info["arguments"], "TAINT_ARGUMENT_VALUE"),
            (info["returns"], "TAINT_RETURN_VALUE"),
        ):
            for target in collection:
                start = target.get("expression_start", target.get("start_offset"))
                end = target.get("expression_end", target.get("end_offset"))
                if start is None or end is None:
                    continue
                for read in reads:
                    if start <= read["offset"] and read.get("end_offset", read["offset"] + 1) <= end:
                        add_flow(kind, read["id"], target["id"])
                for call in calls_in_file:
                    if start <= call["start_offset"] and call["end_offset"] + 1 <= end:
                        add_flow(
                            "TAINT_CALL_RESULT_VALUE", call["return_value_id"],
                            target["id"],
                        )

        for flow in info["data_flows"]:
            if flow["kind"] == "PROPERTY_READ":
                add_flow("TAINT_PROPERTY_READ", flow["source"], flow["target"])
        for flow in info["branch_flows"]:
            if flow["kind"] == "PHI_INPUT":
                add_flow("TAINT_PHI_INPUT", flow["source"], flow["target"])

        arguments_by_call = defaultdict(list)
        for argument in info["arguments"]:
            arguments_by_call[argument["call_id"]].append(argument)
            add_flow(
                "TAINT_CALL_INPUT", argument["id"], argument["call_id"],
                position=argument["position"], terminal=True,
            )

        contexts = {context["call_id"]: context for context in info["call_contexts"]}
        runtime_models = {
            model["call_id"]: model for model in info.get("runtime_models", [])
        }
        for call in calls_in_file:
            context = contexts.get(call["id"])
            context_targets = (
                context.get("callee_function_ids", []) if context else []
            ) or ([context.get("callee_function_id")] if context and context.get("callee_function_id") else [])
            if context and context_targets:
                for binding in context["parameter_bindings"]:
                    add_flow(
                        "TAINT_CONTEXT_BINDING", binding["argument_id"], binding["id"],
                        context_id=context["id"], position=binding["position"],
                    )
                    add_flow(
                        "TAINT_PARAMETER_ENTER", binding["id"],
                        binding.get("parameter_definition_id"),
                        transition="push", context_id=context["id"],
                    )
                target_returns = [
                    returned
                    for target_info in file_list
                    for returned in target_info["returns"]
                    if returned.get("function_id") in context_targets
                ]
                for returned in target_returns:
                    add_flow(
                        "TAINT_RETURN_EXIT", returned["id"],
                        context["return_value_id"], transition="pop",
                        context_id=context["id"],
                    )
                add_flow(
                    "TAINT_CONTEXT_RESULT", context["return_value_id"],
                    call["return_value_id"], context_id=context["id"],
                )
            else:
                model = runtime_models.get(call["id"], {})
                derived_positions = model.get("derives_return_from", [])
                for argument in arguments_by_call.get(call["id"], []):
                    if argument["position"] not in derived_positions:
                        continue
                    add_flow(
                        "TAINT_RUNTIME_RESULT", argument["id"],
                        call["return_value_id"], position=argument["position"],
                    )

            receiver = call.get("receiver") or {}
            model = runtime_models.get(call["id"], {})
            if model.get("derives_return_from_receiver"):
                add_flow(
                    "TAINT_RECEIVER_RESULT", receiver.get("definition_id"),
                    call["return_value_id"],
                )

        # Heap writes and reads meet at a stable object/location identity.
        for access in info["heap_accesses"]:
            if access["kind"] in {"write", "initialize", "collection-write"}:
                for source_id in access.get("value_source_ids", []):
                    add_flow("TAINT_HEAP_WRITE", source_id, access["location_id"])
            elif access["kind"] in {"read", "collection-read"}:
                add_flow(
                    "TAINT_HEAP_READ", access["location_id"], access["entity_id"]
                )

    # Store direct flow records with the file owning their target (or source).
    for flow in direct:
        owner = value_owner.get(flow["target"]) or value_owner.get(flow["source"])
        if owner:
            owner["taint_flows"].append(flow)

    adjacency = defaultdict(list)
    for flow in direct:
        adjacency[flow["source"]].append(flow)

    tainted_call_keys = set()
    for source in sources:
        source_id = source["id"]
        start_state = (source["value_id"], tuple())
        queue = deque([start_state])
        predecessor = {start_state: None}
        incoming_flow = {}
        distance = {start_state: 0}
        while queue:
            node_id, context_stack = queue.popleft()
            for flow in adjacency.get(node_id, []):
                next_stack = context_stack
                if flow["transition"] == "push":
                    if len(context_stack) >= MAX_CONTEXT_DEPTH:
                        continue
                    next_stack = context_stack + (flow["context_id"],)
                elif flow["transition"] == "pop":
                    if not context_stack or context_stack[-1] != flow["context_id"]:
                        continue
                    next_stack = context_stack[:-1]
                next_state = (flow["target"], next_stack)
                if next_state in predecessor:
                    continue
                predecessor[next_state] = (node_id, context_stack)
                incoming_flow[next_state] = flow
                distance[next_state] = distance[(node_id, context_stack)] + 1
                queue.append(next_state)

        for state, previous_state in predecessor.items():
            value_id, context_stack = state
            if previous_state is None:
                via = "TAINT_SOURCE"
                predecessor_id = source_id
                predecessor_context_stack = []
            else:
                via = incoming_flow[state]["kind"]
                predecessor_id = previous_state[0]
                predecessor_context_stack = list(previous_state[1])
            reach = {
                "id": stable_id(
                    "taint-reach", source_id, value_id, "/".join(context_stack)
                ),
                "source_id": source_id, "value_id": value_id,
                "hop_count": distance[state], "predecessor_id": predecessor_id,
                "predecessor_context_stack": predecessor_context_stack,
                "via": via, "context_stack": list(context_stack),
            }
            owner = value_owner.get(value_id) or value_owner.get(source["value_id"])
            if owner:
                owner["taint_reaches"].append(reach)
            record = records.get(value_id)
            if record is not None:
                record.setdefault("taint_source_ids", [])
                if source_id not in record["taint_source_ids"]:
                    record["taint_source_ids"].append(source_id)
            call_pair = calls.get(value_id)
            if call_pair and previous_state is not None and via == "TAINT_CALL_INPUT":
                call_info, call = call_pair
                key = (call["id"], source_id, context_stack)
                if key not in tainted_call_keys:
                    tainted_call_keys.add(key)
                    call_info["tainted_calls"].append({
                        "id": stable_id(
                            "tainted-call", call["id"], source_id,
                            "/".join(context_stack),
                        ),
                        "call_id": call["id"], "source_id": source_id,
                        "line": call["line"], "callee": call["callee"],
                        "argument_id": previous_state[0],
                        "context_stack": list(context_stack),
                        "hop_count": distance[state],
                    })


def taint_path(files: Iterable[dict], source_id: str, value_id: str) -> List[str]:
    """Return one shortest materialized source-to-value path."""
    reaches = [
        reach for info in files for reach in info.get("taint_reaches", [])
        if reach["source_id"] == source_id and reach["value_id"] == value_id
    ]
    if not reaches:
        return []
    current = min(reaches, key=lambda item: item["hop_count"])
    path = [current["value_id"]]
    all_reaches = [
        reach for info in files for reach in info.get("taint_reaches", [])
        if reach["source_id"] == source_id
    ]
    while current["predecessor_id"] != source_id:
        predecessor_id = current["predecessor_id"]
        path.append(predecessor_id)
        candidates = [
            reach for reach in all_reaches
            if reach["value_id"] == predecessor_id
            and reach["hop_count"] == current["hop_count"] - 1
            and reach["context_stack"] == current["predecessor_context_stack"]
        ]
        if not candidates:
            break
        current = candidates[0]
    path.append(source_id)
    return list(reversed(path))
