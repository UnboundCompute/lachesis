"""Turn expression structure into explicit value-producing operations."""
import hashlib


def stable_id(kind: str, *parts) -> str:
    raw = ":".join(str(part) for part in parts)
    digest = hashlib.sha256(f"{kind}:{raw}".encode("utf-8")).hexdigest()[:16]
    return f"{kind}:{digest}"


def operation_kind(expression: dict) -> str:
    kind = expression["kind"]
    operator = expression.get("operator")
    if kind == "binary":
        if operator in {"&&", "||", "??"}:
            return "logical"
        if operator in {"===", "!==", "==", "!=", "<", ">", "<=", ">=", "in", "instanceof"}:
            return "comparison"
        if operator in {"&", "|", "^", "<<", ">>", ">>>"}:
            return "bitwise"
        return "arithmetic"
    return {
        "unary": "await" if operator == "await" else "unary",
        "conditional": "conditional",
        "cast": "cast",
        "constructor": "object-construction",
        "object-literal": "object-construction",
        "array-literal": "array-construction",
        "template-literal": "template-construction",
        "member-access": "property-access",
        "call": "call",
    }.get(kind, "")


def analyze_operations(info: dict) -> None:
    expressions = {expression["id"]: expression for expression in info["expressions"]}
    operations = []
    operations_by_expression = {}
    for expression in info["expressions"]:
        kind = operation_kind(expression)
        if not kind:
            continue
        operation = {
            "id": stable_id("operation", expression["id"]),
            "kind": kind, "operator": expression.get("operator"),
            "expression_id": expression["id"],
            "start_offset": expression["start_offset"],
            "end_offset": expression["end_offset"],
            "line": expression["start_line"],
            "text": expression["text"],
            "cast_type": expression.get("cast_type"),
            "function_id": expression.get("function_id"),
        }
        operations.append(operation)
        operations_by_expression[expression["id"]] = operation

    operation_inputs = []
    for link in info["expression_links"]:
        parent = operations_by_expression.get(link["parent"])
        if not parent:
            continue
        child_operation = operations_by_expression.get(link["child"])
        operation_inputs.append({
            "source": (
                child_operation["id"] if child_operation else link["child"]
            ),
            "target": parent["id"], "role": link["role"],
            "position": link.get("position"),
        })

    operation_attachments = []
    for attachment in info["body_attachments"]:
        operation = operations_by_expression.get(attachment.get("expression_id"))
        if operation:
            operation_attachments.append({
                "operation_id": operation["id"],
                "entity_id": attachment["entity_id"],
                "entity_kind": attachment["entity_kind"],
            })

    # Reads/calls nested beneath a leaf feed the closest containing operation.
    for attachment in info["body_attachments"]:
        if attachment["entity_kind"] not in {"READ", "CALL"}:
            continue
        expression = expressions.get(attachment.get("expression_id"))
        if not expression:
            continue
        candidates = [
            operation for operation in operations
            if operation["start_offset"] <= expression["start_offset"]
            and expression["end_offset"] <= operation["end_offset"]
        ]
        operation = min(
            candidates,
            key=lambda item: item["end_offset"] - item["start_offset"],
            default=None,
        )
        if operation and not any(
            item["operation_id"] == operation["id"]
            and item["entity_id"] == attachment["entity_id"]
            for item in operation_attachments
        ):
            operation_attachments.append({
                "operation_id": operation["id"],
                "entity_id": attachment["entity_id"],
                "entity_kind": attachment["entity_kind"],
            })

    info["operations"] = operations
    info["operation_inputs"] = operation_inputs
    info["operation_attachments"] = operation_attachments
