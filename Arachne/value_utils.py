"""Small language-neutral helpers for normalized receiver/access expressions."""
import re
from typing import List, Tuple


def access_parts(token: str) -> Tuple[str, str, List[str]]:
    normalized = re.sub(r"\s+", "", token).replace("?.", ".")
    root_match = re.match(r"[A-Za-z_$][\w$]*", normalized)
    if not root_match:
        return normalized, "", []
    root = root_match.group(0)
    suffix = normalized[root_match.end():]
    path_parts = []
    dynamic_parts = []
    for match in re.finditer(r"\.([A-Za-z_$][\w$]*)|\[([^\]]+)\]", suffix):
        if match.group(1):
            path_parts.append(match.group(1))
        else:
            inner = match.group(2)
            if re.fullmatch(r"['\"][^'\"]+['\"]", inner):
                path_parts.append(inner[1:-1])
            else:
                path_parts.append(f"[{inner}]")
                dynamic_parts.append(inner)
    path = ""
    for part in path_parts:
        path += part if part.startswith("[") else ("." if path else "") + part
    return root, path, dynamic_parts
