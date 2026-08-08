"""Framework and dependency wiring — relationships that are not plain calls.

A handler is reached because a route table, a decorator, a DI container, an event
name, or a tool registry connects a string key to an implementation at runtime.
Statically these look like a literal passed to a library method, or a name that is
never "called" — so a naive call graph drops the handler as unreferenced. This
pass recovers those connections as explicit *wiring boundaries* so the edge is
marked dynamic rather than silently unresolved:

  - route -> handler        (`app.get('/x', h)`, `@Get('/x')`)
  - middleware ordering     (`app.use(mw)` in sequence)
  - dependency injection    (`@Injectable`, `container.get(T)`, constructor params)
  - decorators              (any `@Decorator(...)` on a declaration)
  - controller registration (`@Controller`, `.register(...)`)
  - ORM model -> table      (`@Entity`, `sequelize.define('t', ...)`)
  - event name -> subscriber(`.on('e', h)`, `@OnEvent('e')`)
  - tool name -> impl       (registry object / dispatch `switch`)
  - configuration dispatch  (`switch(action)` -> per-case handler)

Each boundary carries the key (route/event/tool name), the resolved target
function when findable, and a `static_resolution` tag.
"""
import hashlib
import re
from collections import defaultdict
from typing import Iterable, List, Optional, Tuple

from .function_analysis import mask_non_code


def stable_id(kind: str, *parts) -> str:
    raw = ":".join(str(part) for part in parts)
    return f"{kind}:{hashlib.sha256((kind + ':' + raw).encode()).hexdigest()[:16]}"


ROUTE_METHODS = {"get", "post", "put", "delete", "patch", "options", "head", "all"}
EVENT_METHODS = {"on", "once", "addlistener", "addeventlistener", "subscribe"}
REGISTER_METHODS = {"register", "provide", "define", "set", "bind", "component", "service"}

DECORATOR_KINDS = {
    "get": "route", "post": "route", "put": "route", "delete": "route",
    "patch": "route", "options": "route", "head": "route", "all": "route",
    "controller": "controller", "restcontroller": "controller",
    "injectable": "dependency-injection", "inject": "dependency-injection",
    "service": "dependency-injection", "component": "dependency-injection",
    "entity": "orm-model", "table": "orm-model", "column": "orm-model",
    "primarygeneratedcolumn": "orm-model", "primarycolumn": "orm-model",
    "manytoone": "orm-model", "onetomany": "orm-model", "manytomany": "orm-model",
    "onevent": "event-subscriber", "subscribe": "event-subscriber",
    "eventpattern": "event-subscriber", "messagepattern": "event-subscriber",
    "module": "module-registration",
}

FUNCTIONISH_RE = re.compile(r"^(?:async\s+)?(?:function\b|\([^)]*\)\s*=>|[A-Za-z_$][\w$]*\s*=>)")
STRING_LITERAL_RE = re.compile(r"^['\"`]([^'\"`]*)['\"`]$")
FIRST_STRING_RE = re.compile(r"^\s*['\"`]([^'\"`]*)['\"`]")


def analyze_wiring(files: Iterable[dict]) -> None:
    file_list = list(files)
    functions_by_name = defaultdict(list)
    for info in file_list:
        for function in info["functions"]:
            functions_by_name[function["name"]].append((info, function))

    for info in file_list:
        path_hash = info["path_hash"]
        text, masked = info["text"], mask_non_code(info["text"])
        boundaries = []
        arguments_by_call = defaultdict(list)
        for argument in info["arguments"]:
            arguments_by_call[argument["call_id"]].append(argument)

        def owner_function(offset: int) -> Optional[str]:
            function = min(
                (
                    item for item in info["functions"]
                    if item["start_offset"] <= offset <= item["end_offset"]
                ),
                key=lambda item: item["end_offset"] - item["start_offset"],
                default=None,
            )
            return function["id"] if function else None

        def resolve_target(expression: str, span: Optional[Tuple[int, int]] = None) -> Tuple[Optional[str], str]:
            """Resolve a handler expression to a function id (inline / named / import)."""
            value = expression.strip()
            if span:
                inline = [
                    function for function in info["functions"]
                    if span[0] <= function["start_offset"] and function["end_offset"] <= span[1]
                ]
                if inline:
                    smallest = min(inline, key=lambda f: f["end_offset"] - f["start_offset"])
                    return smallest["id"], "inline"
            name = value.split("(")[0].strip()
            if name in functions_by_name:
                local = [pair for pair in functions_by_name[name] if pair[0] is info]
                chosen = (local or functions_by_name[name])[0][1]
                return chosen["id"], "local" if local else "cross-file"
            if any(name == binding["local"]
                   for imported in info["imports"] for binding in imported["bindings"]):
                return None, "imported"
            return None, "unresolved"

        def add(kind: str, mechanism: str, offset: int, **fields) -> None:
            record = {
                "id": stable_id("wiring", path_hash, kind, mechanism, offset),
                "kind": kind, "mechanism": mechanism,
                "line": text.count("\n", 0, offset) + 1, "offset": offset,
                "function_id": owner_function(offset),
                "key": fields.get("key"),
                "key_expression": fields.get("key_expression"),
                "target_function_id": fields.get("target_function_id"),
                "target_expression": fields.get("target_expression"),
                "confidence": fields.get("confidence", "medium"),
                "static_resolution": fields.get("static_resolution", "runtime"),
                "call_id": fields.get("call_id"),
                "declaration": fields.get("declaration"),
            }
            if not any(item["id"] == record["id"] for item in boundaries):
                boundaries.append(record)

        # ---- Decorators: `@Name(args)` before a declaration. -----------------
        for match in re.finditer(r"@([A-Za-z_$][\w$]*)\s*(\([^)]*\))?", masked):
            name = match.group(1)
            kind = DECORATOR_KINDS.get(name.lower(), "decorator")
            args = text[match.start(2):match.end(2)] if match.group(2) else ""
            key_match = FIRST_STRING_RE.match(args[1:]) if args else None
            # The decorated declaration is the next function/class after the decorator.
            following = min(
                (
                    function for function in info["functions"]
                    if function["start_offset"] >= match.end()
                ),
                key=lambda f: f["start_offset"],
                default=None,
            )
            following_type = min(
                (
                    declared for declared in info["types"]
                    if declared["start_offset"] >= match.end()
                ),
                key=lambda d: d["start_offset"],
                default=None,
            )
            target_id = None
            target_expr = name
            if following and (not following_type or following["start_offset"] <= following_type["start_offset"]):
                target_id, target_expr = following["id"], following["name"]
            elif following_type:
                target_expr = following_type["name"]
            add(
                kind, "decorator", match.start(),
                key=key_match.group(1) if key_match else None,
                key_expression=args.strip("()") or None,
                target_function_id=target_id, target_expression=target_expr,
                decoration=name, confidence="high", static_resolution="decorator",
                declaration=target_expr,
            )

        # ---- Framework method calls: routing / middleware / events / DI. -----
        for call in info["function_calls"]:
            method = (call.get("method_name") or "").lower()
            receiver = (call.get("receiver") or {}).get("expression", "")
            arguments = sorted(arguments_by_call.get(call["id"], []), key=lambda a: a["position"])
            if not method:
                continue

            def handler_argument():
                for argument in reversed(arguments):
                    expression = argument["expression"].strip()
                    if FUNCTIONISH_RE.match(expression) or expression.split("(")[0].strip() in functions_by_name:
                        return argument
                return arguments[-1] if arguments else None

            first_literal = None
            if arguments:
                literal = STRING_LITERAL_RE.match(arguments[0]["expression"].strip())
                first_literal = literal.group(1) if literal else None

            if method in ROUTE_METHODS and first_literal is not None:
                handler = handler_argument()
                target_id, resolution = (
                    resolve_target(handler["expression"], (handler["start_offset"], handler["end_offset"]))
                    if handler else (None, "unresolved")
                )
                add(
                    "route", f"{receiver or 'app'}.{method}", call["start_offset"],
                    key=first_literal, key_expression=arguments[0]["expression"],
                    target_function_id=target_id,
                    target_expression=handler["expression"] if handler else None,
                    call_id=call["id"], confidence="high",
                    static_resolution="literal-route",
                )
            elif method == "use":
                handler = handler_argument()
                if handler:
                    target_id, _ = resolve_target(
                        handler["expression"], (handler["start_offset"], handler["end_offset"])
                    )
                    add(
                        "middleware", f"{receiver or 'app'}.use", call["start_offset"],
                        target_function_id=target_id,
                        target_expression=handler["expression"], call_id=call["id"],
                        confidence="medium", static_resolution="ordered",
                    )
            elif method in EVENT_METHODS and arguments:
                handler = handler_argument()
                target_id, _ = (
                    resolve_target(handler["expression"], (handler["start_offset"], handler["end_offset"]))
                    if handler else (None, "unresolved")
                )
                add(
                    "event-subscriber", f"{receiver or 'emitter'}.{method}", call["start_offset"],
                    key=first_literal, key_expression=arguments[0]["expression"] if arguments else None,
                    target_function_id=target_id,
                    target_expression=handler["expression"] if handler else None,
                    call_id=call["id"], confidence="medium",
                    static_resolution="literal-event" if first_literal else "runtime",
                )
            elif method == "define" and receiver in {"sequelize", "db"} and first_literal:
                add(
                    "orm-model", f"{receiver}.define", call["start_offset"],
                    key=first_literal, key_expression=arguments[0]["expression"],
                    call_id=call["id"], confidence="high", static_resolution="literal",
                )
            elif method == "model" and first_literal:
                add(
                    "orm-model", f"{receiver or 'orm'}.model", call["start_offset"],
                    key=first_literal, key_expression=arguments[0]["expression"],
                    call_id=call["id"], confidence="medium", static_resolution="literal",
                )
            elif method == "get" and receiver in {"container", "injector", "app"} and arguments:
                add(
                    "dependency-injection", f"{receiver}.get", call["start_offset"],
                    key=first_literal, key_expression=arguments[0]["expression"],
                    target_expression=arguments[0]["expression"], call_id=call["id"],
                    confidence="medium", static_resolution="token",
                )
            elif method in REGISTER_METHODS and first_literal:
                handler = handler_argument()
                target_id, _ = (
                    resolve_target(handler["expression"], (handler["start_offset"], handler["end_offset"]))
                    if handler and handler is not arguments[0] else (None, "unresolved")
                )
                add(
                    "tool-registration", f"{receiver or 'registry'}.{method}", call["start_offset"],
                    key=first_literal, key_expression=arguments[0]["expression"],
                    target_function_id=target_id,
                    target_expression=handler["expression"] if handler else None,
                    call_id=call["id"], confidence="medium", static_resolution="literal-key",
                )

        # ---- Dispatch `switch(key)` -> per-case handler. ---------------------
        # A switch statement's own offset span covers only its header line; its
        # cases live inside the sibling `switch` scope, so locate that scope by
        # containment and read the cases (and their bodies) from within it.
        statements = sorted(info["statements"], key=lambda s: s["start_offset"])
        calls_sorted = sorted(info["function_calls"], key=lambda c: c["start_offset"])
        switch_scopes = [scope for scope in info["scopes"] if scope["kind"] == "switch"]
        for switch_stmt in statements:
            if switch_stmt["kind"] != "switch-statement":
                continue
            discriminant = ""
            head = text[switch_stmt["start_offset"]:switch_stmt["start_offset"] + 120]
            disc_match = re.search(r"switch\s*\(([^)]*)\)", head)
            if disc_match:
                discriminant = disc_match.group(1).strip()
            body_scope = min(
                (
                    scope for scope in switch_scopes
                    if scope.get("start_offset", -1) >= switch_stmt["start_offset"]
                ),
                key=lambda scope: scope["start_offset"],
                default=None,
            )
            if not body_scope:
                continue
            scope_end = body_scope["end_offset"]
            cases = sorted(
                (
                    statement for statement in statements
                    if statement["kind"] in {"case-statement", "default-statement"}
                    and body_scope["start_offset"] <= statement["start_offset"] <= scope_end
                ),
                key=lambda s: s["start_offset"],
            )
            for index, case in enumerate(cases):
                segment_end = (
                    cases[index + 1]["start_offset"] if index + 1 < len(cases)
                    else scope_end
                )
                label_match = re.search(r"case\s+(.+?):", " ".join(case["text"].split()))
                key_expression = label_match.group(1).strip() if label_match else "default"
                literal = STRING_LITERAL_RE.match(key_expression)
                segment_calls = [
                    call for call in calls_sorted
                    if case["end_offset"] <= call["start_offset"] < segment_end
                    and call.get("caller_function_id") == switch_stmt["function_id"]
                ]
                target_call = segment_calls[0] if segment_calls else None
                add(
                    "config-dispatch", "switch-case", case["start_offset"],
                    key=literal.group(1) if literal else None,
                    key_expression=f"{discriminant} == {key_expression}",
                    target_function_id=(target_call or {}).get("declaration_symbol_id"),
                    target_expression=(target_call or {}).get("callee"),
                    confidence="high" if target_call else "low",
                    static_resolution="switch-key",
                )

        # ---- Registry object literals: `const tools = { name: impl }`. -------
        for symbol in info["symbols"]:
            if symbol.get("owner_function_id") is not None or symbol["kind"] not in {"const", "let", "var"}:
                continue
            if not re.search(r"tool|handler|route|registr|dispatch|command|action|resolver|map", symbol["name"], re.I):
                continue
            definition = next(
                (
                    d for d in info["definitions"]
                    if d["symbol_id"] == symbol["id"] and d.get("expression_start") is not None
                ),
                None,
            )
            if not definition:
                continue
            rhs = text[definition["expression_start"]:definition["expression_end"]]
            if not rhs.strip().startswith("{"):
                continue
            for prop_match in re.finditer(
                r"([A-Za-z_$][\w$]*|['\"][^'\"]+['\"])\s*:\s*([A-Za-z_$][\w$]*)\b", rhs
            ):
                value_name = prop_match.group(2)
                if value_name not in functions_by_name:
                    continue
                key_raw = prop_match.group(1).strip("'\"")
                target_id, _ = resolve_target(value_name)
                add(
                    "tool-registration", f"registry:{symbol['name']}",
                    definition["expression_start"] + prop_match.start(),
                    key=key_raw, key_expression=prop_match.group(1),
                    target_function_id=target_id, target_expression=value_name,
                    confidence="medium", static_resolution="registry-literal",
                )

        info["wiring_boundaries"] = boundaries
