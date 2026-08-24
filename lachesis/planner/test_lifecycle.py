from lachesis.flow.skeleton import _typestate_skel
from lachesis.planner.registry import default_candidate_registry


def _fixture(extension, callee, receiver=False):
    props = {
        "callee": callee, "start_line": 2,
        "absolute_file": "fixture" + extension, "owner_function_id": "f",
    }
    if receiver:
        props["receiver_value_id"] = "resource"
    else:
        props["argument_value_ids"] = ["resource"]
    use_kind = "expression" if extension == ".c" else "read"
    use_properties = {"target_id": "resource", "definition_id": "resource",
                      "start_line": 3, "absolute_file": "fixture" + extension,
                      "owner_function_id": "f"}
    if extension == ".c":
        use_properties["syntax_kind"] = "UnaryOperator"
    return {"nodes": [
        {"id": "release", "kind": "call", "label": callee, "properties": props},
        {"id": "use", "kind": use_kind,
         "label": "*resource" if extension == ".c" else "resource.field",
         "properties": use_properties},
    ], "edges": []}


def test_lifecycle_release_and_use_census_all_supported_languages():
    cases = [
        (".c", "free", False),
        (".py", "close", True),
        (".js", "dispose", True),
        (".ts", "dispose", True),
    ]
    for extension, callee, receiver in cases:
        registry = default_candidate_registry(_fixture(extension, callee, receiver))
        release = registry.census("lifecycle.release")["constructors"][0]
        use = registry.census("lifecycle.use")["constructors"][0]
        assert release["census"]["enumerated"] == 1
        assert use["census"]["enumerated"] == 1


def test_lifecycle_use_excludes_bare_reads_and_acquire_is_catalogued():
    graph = _fixture(".py", "open", False)
    graph["nodes"].append({
        "id": "bare", "kind": "read", "label": "resource",
        "properties": {"target_id": "resource", "definition_id": "resource",
                        "start_line": 4, "absolute_file": "fixture.py",
                        "owner_function_id": "f"},
    })
    registry = default_candidate_registry(graph)
    assert registry.census("lifecycle.acquire")["constructors"][0]["census"]["enumerated"] == 1
    assert registry.census("lifecycle.use")["constructors"][0]["census"]["enumerated"] == 1


def test_lifecycle_skeleton_families_preserve_c_specializations():
    c = _typestate_skel("f", "p", [
        {"kind": "alloc"}, {"kind": "free"}, {"kind": "use"},
    ], 0, "c")
    assert [token["family"] for token in c[1:-1]] == [
        "memory.alloc", "memory.free", "memory.deref",
    ]
    managed = _typestate_skel("f", "p", [
        {"kind": "alloc"}, {"kind": "free"}, {"kind": "use"},
    ], 0, "typescript")
    assert [token["family"] for token in managed[1:-1]] == [
        "lifecycle.acquire", "lifecycle.release", "lifecycle.use",
    ]
