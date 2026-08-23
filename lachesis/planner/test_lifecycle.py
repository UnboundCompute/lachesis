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
    return {"nodes": [
        {"id": "release", "kind": "call", "label": callee, "properties": props},
        {"id": "use", "kind": "read", "label": "resource.field",
         "properties": {"target_id": "resource", "definition_id": "resource",
                         "start_line": 3, "absolute_file": "fixture" + extension,
                         "owner_function_id": "f"}},
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
