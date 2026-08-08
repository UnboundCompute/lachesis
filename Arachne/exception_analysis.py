"""Exception flow: throws, may-throw calls, catch binding, finally, rejections.

Layers a semantic exception model on top of the structured CFG. The CFG already
carries CFG_THROW / CFG_EXCEPTION / CFG_FINALLY edges; this pass turns those raw
transfers into first-class records a security query can read directly:

  - explicit `throw` sites and whether they are caught or escape the function,
  - calls that may throw (runtime models that raise + interprocedural: a callee
    whose own body can throw), resolved to their handler or marked escaping,
  - catch-variable binding (the error value a handler receives),
  - `finally` blocks and the completions that run them,
  - re-thrown errors (a throw inside a catch), and
  - rejected promises (an async function whose body can throw, `Promise.reject`,
    and `.catch` rejection handlers).

The throw/reject reachability is computed to a fixpoint across files so
`callee may throw` propagates to every caller that does not wrap the call.
"""
import hashlib
from collections import defaultdict
from typing import Iterable, List, Optional, Tuple


def stable_id(kind: str, *parts) -> str:
    raw = ":".join(str(part) for part in parts)
    return f"{kind}:{hashlib.sha256((kind + ':' + raw).encode()).hexdigest()[:16]}"


# Built-in / library callees whose normal completion can raise. Kept small and
# high-signal; interprocedural throwing is discovered from function bodies.
THROWING_RUNTIME = {
    "JSON.parse": "invalid-json",
    "decodeURIComponent": "malformed-uri",
    "decodeURI": "malformed-uri",
    "BigInt": "invalid-bigint",
    "structuredClone": "uncloneable",
}
# Constructors (form == "constructor") that can throw on bad input.
THROWING_CONSTRUCTORS = {"URL": "invalid-url"}
# Runtime models whose promise settles rejected (async throw channel).
REJECTING_RUNTIME = {"fetch": "network-failure"}


def _catch_of_try(try_stmt: dict, siblings: List[dict]) -> Tuple[Optional[dict], Optional[dict]]:
    """The catch / finally statements that pair with a try, by sibling adjacency."""
    catch_stmt = finally_stmt = None
    order = sorted(siblings, key=lambda item: item["start_offset"])
    index = next((i for i, item in enumerate(order) if item["id"] == try_stmt["id"]), None)
    if index is None:
        return None, None
    cursor = index + 1
    if cursor < len(order) and order[cursor]["kind"] == "catch-statement":
        catch_stmt = order[cursor]
        cursor += 1
    if cursor < len(order) and order[cursor]["kind"] == "finally-statement":
        finally_stmt = order[cursor]
    return catch_stmt, finally_stmt


def analyze_exceptions(files: Iterable[dict]) -> None:
    file_list = list(files)

    # ---- Per-function try/catch/finally structure (offset ranges). -----------
    # groups[function_id] = list of {try_range, catch_id, catch_range, finally_id}
    groups = defaultdict(list)
    catch_scope_of = {}       # catch statement id -> its scope record
    for info in file_list:
        scopes = {scope["id"]: scope for scope in info["scopes"]}
        statements = info["statements"]
        by_parent_scope = defaultdict(list)
        for statement in statements:
            by_parent_scope[(statement["function_id"], statement.get("scope_id"))].append(statement)

        def controlled(statement: dict, kind: str) -> Optional[dict]:
            candidates = [
                scope for scope in scopes.values()
                if scope["kind"] == kind
                and statement["start_offset"] <= scope.get("start_offset", -1)
                and scope.get("end_offset", 1 << 62) <= statement["end_offset"] + 2
            ]
            return min(candidates, key=lambda s: s["start_offset"], default=None)

        for statement in statements:
            if statement["kind"] != "try-statement":
                continue
            siblings = by_parent_scope[(statement["function_id"], statement.get("scope_id"))]
            catch_stmt, finally_stmt = _catch_of_try(statement, siblings)
            try_scope = controlled(statement, "try")
            catch_scope = controlled(catch_stmt, "catch") if catch_stmt else None
            if catch_scope and catch_stmt:
                catch_scope_of[catch_stmt["id"]] = catch_scope
            finally_scope = controlled(finally_stmt, "finally") if finally_stmt else None
            groups[statement["function_id"]].append({
                "try_range": (
                    (try_scope["start_offset"], try_scope["end_offset"]) if try_scope
                    else (statement["start_offset"], statement["end_offset"])
                ),
                "catch_id": catch_stmt["id"] if catch_stmt else None,
                "catch_range": (
                    (catch_scope["start_offset"], catch_scope["end_offset"])
                    if catch_scope else None
                ),
                "finally_id": finally_stmt["id"] if finally_stmt else None,
                "finally_range": (
                    (finally_scope["start_offset"], finally_scope["end_offset"])
                    if finally_scope else None
                ),
            })

    def guarding(function_id: str, offset: int) -> Tuple[Optional[str], List[str], bool]:
        """Handler catch id (or None), ordered finally ids, and whether it escapes."""
        handler = None
        finally_ids: List[str] = []
        escapes = True
        ordered = sorted(
            groups.get(function_id, []),
            key=lambda g: g["try_range"][1] - g["try_range"][0],
        )
        for group in ordered:
            in_try = group["try_range"][0] <= offset <= group["try_range"][1]
            catch_range = group["catch_range"]
            in_catch = bool(catch_range) and catch_range[0] <= offset <= catch_range[1]
            if in_try:
                if group["finally_id"]:
                    finally_ids.append(group["finally_id"])
                if group["catch_id"]:
                    handler = group["catch_id"]
                    escapes = False
                    break
                # finally-only try: run finally, keep propagating outward.
            elif in_catch:
                # A throw inside a catch is not handled by that try's own catch;
                # its finally still runs, then it propagates to any outer try.
                if group["finally_id"]:
                    finally_ids.append(group["finally_id"])
        return handler, finally_ids, escapes

    # ---- Function -> resolved callee ids (for interprocedural throwing). ------
    functions_by_id = {}
    for info in file_list:
        for function in info["functions"]:
            functions_by_id[function["id"]] = (info, function)

    def callee_ids(call: dict) -> List[str]:
        targets = call.get("dispatch_target_ids") or []
        if call.get("declaration_symbol_id"):
            targets = [*targets, call["declaration_symbol_id"]]
        return [target for target in targets if target in functions_by_id]

    def call_throw_reason(call: dict) -> Optional[str]:
        normalized = call["callee"].replace("?.", ".")
        if call.get("form") == "constructor" and normalized in THROWING_CONSTRUCTORS:
            return f"runtime:{THROWING_CONSTRUCTORS[normalized]}"
        if normalized in THROWING_RUNTIME:
            return f"runtime:{THROWING_RUNTIME[normalized]}"
        return None

    def call_reject_reason(call: dict) -> Optional[str]:
        normalized = call["callee"].replace("?.", ".")
        if normalized in REJECTING_RUNTIME:
            return f"runtime:{REJECTING_RUNTIME[normalized]}"
        if normalized in {"Promise.reject"}:
            return "explicit-reject"
        return None

    # ---- Explicit throw statements, grouped per function. --------------------
    throws_by_function = defaultdict(list)
    for info in file_list:
        for statement in info["statements"]:
            if statement["kind"] == "throw":
                throws_by_function[statement["function_id"]].append(statement)

    def statement_of_offset(info: dict, offset: int) -> Optional[dict]:
        return min(
            (
                item for item in info["statements"]
                if item["start_offset"] <= offset <= item["end_offset"]
            ),
            key=lambda item: item["end_offset"] - item["start_offset"],
            default=None,
        )

    # ---- Fixpoint: which functions can raise past their own boundary. --------
    may_throw = set()
    changed = True
    while changed:
        changed = False
        for info in file_list:
            for function in info["functions"]:
                if function["id"] in may_throw:
                    continue
                raises = any(
                    guarding(function["id"], statement["start_offset"])[2]
                    for statement in throws_by_function.get(function["id"], [])
                )
                if not raises:
                    for call in info["function_calls"]:
                        if call.get("caller_function_id") != function["id"]:
                            continue
                        throws = call_throw_reason(call) is not None or any(
                            target in may_throw for target in callee_ids(call)
                        )
                        if throws and guarding(function["id"], call["start_offset"])[2]:
                            raises = True
                            break
                if raises:
                    may_throw.add(function["id"])
                    changed = True

    # ---- Emit records. -------------------------------------------------------
    for info in file_list:
        exception_sites = []
        catch_handlers = []
        finally_blocks = []
        promise_rejections = []
        path_hash = info["path_hash"]
        reads_by_offset = info["reads"]

        catch_params = {
            symbol["scope_id"]: symbol
            for symbol in info["symbols"]
            if symbol["kind"] == "catch-parameter"
        }

        # Catch handlers + finally blocks.
        for statement in info["statements"]:
            if statement["kind"] == "catch-statement":
                catch_scope = catch_scope_of.get(statement["id"])
                param = catch_params.get(catch_scope["id"]) if catch_scope else None
                rethrows = bool(catch_scope) and any(
                    other["kind"] == "throw"
                    and catch_scope["start_offset"] <= other["start_offset"] <= catch_scope["end_offset"]
                    for other in info["statements"]
                )
                catch_handlers.append({
                    "id": stable_id("catch-handler", path_hash, statement["id"]),
                    "statement_id": statement["id"],
                    "function_id": statement["function_id"],
                    "line": statement["start_line"],
                    "scope_id": catch_scope["id"] if catch_scope else None,
                    "parameter_symbol_id": param["id"] if param else None,
                    "parameter_name": param["name"] if param else None,
                    "rethrows": rethrows,
                })
            elif statement["kind"] == "finally-statement":
                finally_blocks.append({
                    "id": stable_id("finally-block", path_hash, statement["id"]),
                    "statement_id": statement["id"],
                    "function_id": statement["function_id"],
                    "line": statement["start_line"],
                })

        handler_id_of = {
            handler["statement_id"]: handler["id"] for handler in catch_handlers
        }
        finally_id_of = {
            block["statement_id"]: block["id"] for block in finally_blocks
        }

        # Explicit throws (and re-throws).
        for statement in info["statements"]:
            if statement["kind"] != "throw":
                continue
            handler_stmt, finally_stmts, escapes = guarding(
                statement["function_id"], statement["start_offset"]
            )
            enclosing_catch = next(
                (
                    handler for handler in catch_handlers
                    if handler["scope_id"]
                    and statement["function_id"] == handler["function_id"]
                    and statement["start_offset"] >= statement["start_offset"]
                    and handler_id_of.get(handler["statement_id"])
                    and catch_scope_of.get(handler["statement_id"])
                    and catch_scope_of[handler["statement_id"]]["start_offset"]
                    <= statement["start_offset"]
                    <= catch_scope_of[handler["statement_id"]]["end_offset"]
                ),
                None,
            )
            is_rethrow = enclosing_catch is not None
            thrown_text = " ".join(statement["text"].split())
            exception_sites.append({
                "id": stable_id("exception-site", path_hash, statement["id"]),
                "kind": "rethrow" if is_rethrow else "throw",
                "function_id": statement["function_id"],
                "statement_id": statement["id"],
                "call_id": None,
                "line": statement["start_line"],
                "expression": thrown_text,
                "handler_catch_id": handler_id_of.get(handler_stmt),
                "finally_ids": [finally_id_of[f] for f in finally_stmts if f in finally_id_of],
                "escapes": escapes,
                "rethrown_from_catch_id": enclosing_catch["id"] if enclosing_catch else None,
            })

        # Calls that may throw / reject.
        for call in info["function_calls"]:
            function_id = call.get("caller_function_id")
            if not function_id:
                continue
            throw_reason = call_throw_reason(call)
            interproc = [t for t in callee_ids(call) if t in may_throw]
            reject_reason = call_reject_reason(call)
            if throw_reason or interproc:
                handler_stmt, finally_stmts, escapes = guarding(
                    function_id, call["start_offset"]
                )
                statement = statement_of_offset(info, call["start_offset"])
                exception_sites.append({
                    "id": stable_id("exception-site", path_hash, "call", call["id"]),
                    "kind": "may-throw-call",
                    "function_id": function_id,
                    "statement_id": statement["id"] if statement else None,
                    "call_id": call["id"],
                    "line": call["line"],
                    "expression": call["callee"],
                    "reason": throw_reason or "callee-throws",
                    "callee_target_ids": interproc,
                    "handler_catch_id": handler_id_of.get(handler_stmt),
                    "finally_ids": [finally_id_of[f] for f in finally_stmts if f in finally_id_of],
                    "escapes": escapes,
                })
            if reject_reason:
                promise_rejections.append({
                    "id": stable_id("promise-rejection", path_hash, "call", call["id"]),
                    "kind": "reject-call",
                    "function_id": function_id,
                    "call_id": call["id"],
                    "line": call["line"],
                    "reason": reject_reason,
                    "handler_target_id": None,
                })

        # Async functions whose body can raise reject their returned promise.
        for function in info["functions"]:
            is_async = function.get("form", "").startswith("async")
            if is_async and function["id"] in may_throw:
                promise_rejections.append({
                    "id": stable_id("promise-rejection", path_hash, "async", function["id"]),
                    "kind": "async-rejection",
                    "function_id": function["id"],
                    "call_id": None,
                    "line": function["start_line"],
                    "reason": "async-body-throws",
                    "handler_target_id": None,
                })

        info["exception_sites"] = exception_sites
        info["catch_handlers"] = catch_handlers
        info["finally_blocks"] = finally_blocks
        info["promise_rejections"] = promise_rejections
