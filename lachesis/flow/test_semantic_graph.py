import unittest

from .emit import _cfg_guard_proofs
from . import atropos
from .semantic_graph import (Edge, Event, EventKind, GuardProof, ObjRef,
                              SkeletonGraph, _requested_patterns, match_graph)


class SemanticGraphTests(unittest.TestCase):
    def test_ownerless_roots_are_declaration_qualified(self):
        from .emit import _readable_root

        class Index:
            @staticmethod
            def nodes_of_kind(*_kinds):
                return [
                    {"id": "global-id", "label": "state", "properties": {}},
                    {"id": "local-id", "label": "state", "properties":
                     {"owner_function_id": "worker"}},
                ]

        class Sub:
            idx = Index()

            @staticmethod
            def label(node_id):
                return {"global-id": "state", "local-id": "state"}[node_id]

            @staticmethod
            def props(node_id):
                return {"global-id": {},
                        "local-id": {"owner_function_id": "worker"}}[node_id]

        sub = Sub()
        self.assertEqual(_readable_root(sub, "decl:global-id"), "state@global-id")
        self.assertEqual(_readable_root(sub, "decl:local-id"), "state")

    def test_default_pattern_registry_covers_every_atropos_matcher(self):
        from lachesis.flow.patterns import EVALUATORS
        from lachesis.flow.semantic_graph import FROZEN_PATTERNS

        for entry in atropos.pattern_catalog():
            matcher = entry.get("matcher") or {}
            pattern = matcher.get("pattern")
            self.assertTrue(
                pattern in FROZEN_PATTERNS or pattern in EVALUATORS,
                entry.get("id"),
            )

    def test_default_matcher_registry_imports_atropos_matcher_names(self):
        declared = {
            (entry.get("matcher") or {}).get("pattern")
            for entry in atropos.pattern_catalog()
        }
        declared.discard(None)
        self.assertTrue(declared <= _requested_patterns(None))

    def test_atropos_sink_catalog_exposes_unique_argument_positions(self):
        from . import atropos

        for language in ("c", "python", "typescript"):
            for entry in atropos.sink_catalog(language).values():
                positions = entry.get("sink_args", ())
                self.assertEqual(len(positions), len(set(positions)), language)
            for entry in atropos.source_catalog(language).values():
                positions = entry.get("args", ())
                self.assertEqual(len(positions), len(set(positions)), language)
            for entry in atropos.sanitizer_catalog(language).values():
                positions = entry.get("ins", ())
                self.assertEqual(len(positions), len(set(positions)), language)
            for pairs in atropos.summary_catalog(language).values():
                self.assertEqual(len(pairs), len(set(pairs)), language)

    def test_frontend_ir_fallback_preserves_pushdown_lifecycle_order(self):
        from .emit import build_semantic_graph

        functions = {
            "main": {
                "is_source": True,
                "source_reachable": True,
                "events": [
                    {"kind": "alloc", "var": "p", "line": 1},
                    {"kind": "use", "var": "p", "line": 3},
                ],
                "calls": [{"callee": "release_helper", "line": 2,
                           "args": [{"pos": 0, "root": "p"}]}],
                "params": [],
            },
            "release_helper": {
                "events": [{"kind": "free", "var": "p", "line": 2}],
                "calls": [],
                "params": ["p"],
            },
        }
        graph = build_semantic_graph(object(), functions,
                                     {"main": ["release_helper"],
                                      "release_helper": []},
                                     lang="python", graph={})
        hits = match_graph(graph)
        self.assertTrue(any(hit["pattern"] == "uaf.deref" for hit in hits))
        self.assertTrue(all(hit["witness_complete"] for hit in hits))

    def test_frontend_ir_pending_cone_preserves_selected_call_return_seam(self):
        from .emit import build_semantic_graph

        functions = {
            "main": {
                "is_source": True, "source_reachable": True,
                "events": [{"kind": "alloc", "var": "p", "line": 1},
                           {"kind": "use", "var": "p", "line": 3}],
                "calls": [{"callee": "release_helper", "line": 2,
                           "args": [{"pos": 0, "root": "p"}]}],
            },
            "release_helper": {
                "events": [{"kind": "free", "var": "p", "line": 2}],
                "calls": [], "params": ["p"],
            },
            "unselected": {
                "events": [{"kind": "alloc", "var": "other", "line": 9}],
                "calls": [],
            },
        }
        graph = build_semantic_graph(
            object(), functions,
            {"main": ["release_helper"], "release_helper": [], "unselected": []},
            lang="python", graph={},
            work_functions={"main", "release_helper"},
        )
        self.assertNotIn("unselected", graph.fragments)
        self.assertTrue(any(edge.kind == "call"
                            for edges in graph.edges.values() for edge in edges))
        self.assertTrue(any(hit["pattern"] == "uaf.deref"
                            for hit in match_graph(graph)))

    def test_frontend_ir_callback_formal_is_stitched_to_function_target(self):
        from .emit import build_semantic_graph

        functions = {
            "main": {
                "is_source": True, "source_reachable": True,
                "events": [{"kind": "alloc", "var": "p", "line": 1},
                           {"kind": "use", "var": "p", "line": 4}],
                "calls": [{"callee": "dispatch", "line": 2,
                           "args": [{"pos": 0, "root": "handler"},
                                    {"pos": 1, "root": "p"}]}],
            },
            "dispatch": {
                "params": ["callback", "value"],
                "events": [],
                "calls": [{"callee": "callback", "line": 3,
                           "args": [{"pos": 0, "root": "value"}]}],
            },
            "handler": {
                "params": ["p"],
                "events": [{"kind": "free", "var": "p", "line": 3}],
                "calls": [],
            },
        }
        graph = build_semantic_graph(
            object(), functions,
            {"main": ["dispatch"], "dispatch": [], "handler": []},
            lang="python", graph={},
        )
        self.assertTrue(any(edge.kind == "call" and edge.target.startswith("handler:")
                            for edges in graph.edges.values() for edge in edges))
        self.assertTrue(any(hit["pattern"] == "uaf.deref"
                            for hit in match_graph(graph)))

    def test_frontend_ir_lifecycle_calls_use_atropos_roles(self):
        from .emit import build_semantic_graph

        functions = {
            "main": {
                "is_source": True,
                "source_reachable": True,
                "events": [],
                "calls": [
                    {"callee": "open", "assigned": "handle", "line": 1,
                     "args": []},
                    {"callee": "close", "line": 2,
                     "args": [{"pos": 0, "root": "handle"}]},
                ],
            },
        }
        graph = build_semantic_graph(object(), functions, {"main": []},
                                     lang="python", graph={})
        kinds = [node.event.kind for node in graph.nodes.values()
                 if node.event is not None]
        self.assertEqual(kinds.count(EventKind.ORIGIN), 1)
        self.assertEqual(kinds.count(EventKind.RELEASE), 1)
        self.assertNotIn("leak", {hit["pattern"] for hit in match_graph(graph)})

    def test_frontend_ir_lifecycle_receiver_release_uses_atropos_roles(self):
        from .emit import build_semantic_graph

        functions = {
            "main": {"is_source": True, "source_reachable": True,
                     "events": [], "calls": [
                         {"callee": "open", "assigned": "handle", "line": 1,
                          "args": []},
                         {"callee": "close", "receiver": "handle", "line": 2,
                          "args": []},
                     ]},
        }
        graph = build_semantic_graph(object(), functions, {"main": []},
                                     lang="python", graph={})
        kinds = [node.event.kind for node in graph.nodes.values()
                 if node.event is not None]
        self.assertEqual(kinds.count(EventKind.ORIGIN), 1)
        self.assertEqual(kinds.count(EventKind.RELEASE), 1)
        self.assertNotIn("leak", {hit["pattern"] for hit in match_graph(graph)})

    def test_managed_language_lifecycle_roles_cover_javascript_and_typescript(self):
        from .emit import build_semantic_graph

        functions = {
            "main": {"is_source": True, "source_reachable": True,
                     "events": [], "calls": [
                         {"callee": "fs.open", "assigned": "handle", "line": 1,
                          "args": []},
                         {"callee": "close", "receiver": "handle", "line": 2,
                          "args": []},
                     ]},
        }
        for language in ("javascript", "typescript"):
            graph = build_semantic_graph(object(), functions, {"main": []},
                                         lang=language, graph={})
            kinds = [node.event.kind for node in graph.nodes.values()
                     if node.event is not None]
            self.assertEqual(kinds.count(EventKind.ORIGIN), 1, language)
            self.assertEqual(kinds.count(EventKind.RELEASE), 1, language)

    def test_frontend_ir_source_calls_become_external_launch_nodes(self):
        from .emit import build_semantic_graph

        functions = {
            "main": {
                "source_reachable": True,
                "source_calls": [{"node": "read_site", "callee": "read",
                                  "line": 4}],
                "calls": [{"node": "read_site", "callee": "read", "line": 4,
                           "assigned": "value", "args": []}],
                "events": [{"kind": "use", "var": "value", "line": 5}],
            },
        }
        graph = build_semantic_graph(object(), functions, {"main": []},
                                     lang="python", graph={})
        launches = [graph.nodes[node_id] for node_id in graph.source_reachable]
        self.assertEqual(len(launches), 1)
        self.assertEqual(launches[0].metadata["source_site"], "read_site")

    def test_cfg_ir_source_calls_replace_entry_launch(self):
        from .emit import build_semantic_graph

        functions = {
            "main": {
                "source_reachable": True,
                "source_calls": [{"node": "source", "callee": "read",
                                  "line": 2}],
                "calls": [{"node": "source", "callee": "read", "line": 2,
                           "args": []}],
                "cfg": {
                    "nodes": ("entry", "source", "exit"),
                    "entry": "entry",
                    "succ": {
                        "entry": ({"target": "source"},),
                        "source": ({"target": "exit"},),
                        "exit": (),
                    },
                },
            },
        }
        graph = build_semantic_graph(object(), functions, {"main": []},
                                     lang="python", graph={})
        launches = [graph.nodes[node_id] for node_id in graph.source_reachable]
        self.assertEqual(len(launches), 1)
        self.assertEqual(launches[0].metadata["source_site"], "source")

    def test_frontend_ir_fallback_routes_sink_facts_through_atropos(self):
        from unittest.mock import patch
        from .emit import build_semantic_graph

        functions = {
            "entry": {
                "is_source": True,
                "source_reachable": True,
                "events": [],
                "calls": [{"callee": "copy_like", "line": 8,
                           "is_sink": True,
                           "args": [{"pos": 0, "root": "input",
                                     "provenance": "param"}],
                           "guards": [], "guard_status": "none-observed",
                           "guard_predicates": (), "control": [],
                           "size_expr": "length", "dst": "buffer"}],
                "params": ["input"],
            },
        }
        catalog = {"copy_like": {"sink_args": (0,),
                                  "kinds": {0: "buffer-write"}}}
        with patch("lachesis.flow.emit.atropos.sink_catalog",
                   return_value=catalog):
            graph = build_semantic_graph(object(), functions, {"entry": []},
                                         lang="python", graph={})
        hits = match_graph(graph)
        self.assertTrue(any(hit["pattern"] == "relational" for hit in hits))

    def test_frontend_ir_deduplicates_catalog_sink_arguments_and_call_ordinals(self):
        from unittest.mock import patch
        from .emit import build_semantic_graph

        functions = {
            "entry": {
                "is_source": True,
                "source_reachable": True,
                "events": [],
                "calls": [
                    {"callee": "execute", "line": 1,
                     "args": [{"pos": 0, "root": "cursor"}]},
                    {"callee": "execute", "line": 2,
                     "args": [{"pos": 0, "root": "cursor"}]},
                ],
            },
        }
        # A catalog merger may contribute the same argument position through
        # multiple declarations.  The graph must still contain one event per
        # call, with distinct stable node IDs.
        catalog = {"execute": {"sink_args": (0, 0),
                                "kinds": {0: "sql-injection"}}}
        with patch("lachesis.flow.emit.atropos.sink_catalog",
                   return_value=catalog):
            graph = build_semantic_graph(object(), functions, {"entry": []},
                                         lang="python", graph={})
        sinks = [node_id for node_id, node in graph.nodes.items()
                 if node.event is not None and node.event.kind == EventKind.SINK]
        self.assertEqual(len(sinks), 2)
        self.assertEqual(len(set(sinks)), 2)

    def test_frontend_ir_fallback_binds_returned_allocations(self):
        from .emit import build_semantic_graph

        functions = {
            "main": {
                "is_source": True,
                "source_reachable": True,
                "events": [
                    {"kind": "free", "var": "q", "line": 3},
                    {"kind": "use", "var": "q", "line": 4},
                ],
                "calls": [{"callee": "make", "line": 2, "assigned": "q",
                           "args": []}],
                "returns": [], "params": [],
            },
            "make": {
                "events": [{"kind": "alloc", "var": "tmp", "line": 1}],
                "calls": [], "returns": [{"kind": "var", "var": "tmp"}],
                "params": [],
            },
        }
        graph = build_semantic_graph(object(), functions,
                                     {"main": ["make"], "make": []},
                                     lang="python", graph={})
        self.assertTrue(any(hit["pattern"] == "uaf.deref"
                            for hit in match_graph(graph)))

    def test_frontend_ir_preserves_persistent_alias_across_helper_seams(self):
        from .emit import build_semantic_graph

        functions = {
            "main": {
                "is_source": True, "source_reachable": True, "params": [],
                "events": [
                    {"kind": "alloc", "var": "p", "line": 1},
                    {"kind": "use", "var": "cached", "line": 4},
                ],
                "calls": [
                    {"callee": "cache", "line": 2,
                     "args": [{"pos": 0, "root": "p"}]},
                    {"callee": "destroy", "line": 3,
                     "args": [{"pos": 0, "root": "p"}]},
                ],
            },
            "cache": {
                "params": ["value"],
                "events": [{"kind": "derive", "var": "cached",
                            "value": "value", "line": 2}],
                "calls": [],
            },
            "destroy": {
                "params": ["value"],
                "events": [{"kind": "free", "var": "value", "line": 3}],
                "calls": [],
            },
        }
        graph = build_semantic_graph(
            object(), functions, {"main": ["cache", "destroy"],
                                  "cache": [], "destroy": []},
            lang="python", graph={})
        hits = [hit for hit in match_graph(graph) if hit["pattern"] == "uaf.deref"]
        self.assertTrue(any(hit["line"] == 4 for hit in hits))

    def test_frontend_ir_fallback_keeps_sibling_cfg_arms_separate(self):
        from .emit import build_semantic_graph

        cfg = {
            "nodes": ("entry", "condition", "free_arm", "live_arm", "merge", "exit"),
            "entry": "entry",
            "succ": {
                "entry": ({"target": "condition", "kind": "CFG_NEXT"},),
                "condition": ({"target": "free_arm", "kind": "TRUE_BRANCH"},
                              {"target": "live_arm", "kind": "FALSE_BRANCH"}),
                "free_arm": ({"target": "merge", "kind": "CFG_NEXT"},),
                "live_arm": ({"target": "merge", "kind": "CFG_NEXT"},),
                "merge": ({"target": "exit", "kind": "CFG_NEXT"},),
            },
        }
        functions = {
            "entry_fn": {
                "is_source": True, "source_reachable": True, "params": [],
                "calls": [], "cfg": cfg,
                "events": [
                    {"kind": "alloc", "var": "p", "node": "entry", "line": 1},
                    {"kind": "free", "var": "p", "node": "free_arm", "line": 2},
                    {"kind": "use", "var": "p", "node": "live_arm", "line": 3},
                    {"kind": "use", "var": "p", "node": "merge", "line": 4},
                ],
            },
        }
        graph = build_semantic_graph(object(), functions, {"entry_fn": []},
                                     lang="python", graph={})
        hits = [hit for hit in match_graph(graph) if hit["pattern"] == "uaf.deref"]
        self.assertTrue(any(hit["line"] == 4 for hit in hits))
        self.assertFalse(any(hit["line"] == 3 for hit in hits))

    def test_frontend_ir_cfg_keeps_call_seam_inside_branch(self):
        from .emit import build_semantic_graph

        main_cfg = {
            "nodes": ("entry", "condition", "free_arm", "live_arm", "merge", "exit"),
            "entry": "entry",
            "succ": {
                "entry": ({"target": "condition", "kind": "CFG_NEXT"},),
                "condition": ({"target": "free_arm", "kind": "TRUE_BRANCH"},
                              {"target": "live_arm", "kind": "FALSE_BRANCH"}),
                "free_arm": ({"target": "merge", "kind": "CFG_NEXT"},),
                "live_arm": ({"target": "merge", "kind": "CFG_NEXT"},),
                "merge": ({"target": "exit", "kind": "CFG_NEXT"},),
            },
        }
        helper_cfg = {"nodes": ("hentry", "hexit"), "entry": "hentry",
                      "succ": {"hentry": ({"target": "hexit", "kind": "CFG_NEXT"},)}}
        functions = {
            "main": {"is_source": True, "source_reachable": True, "params": [],
                     "cfg": main_cfg,
                     "events": [{"kind": "alloc", "var": "p", "node": "entry", "line": 1},
                                {"kind": "use", "var": "p", "node": "live_arm", "line": 3},
                                {"kind": "use", "var": "p", "node": "merge", "line": 4}],
                     "calls": [{"callee": "release_helper", "node": "free_arm", "line": 2,
                                "args": [{"pos": 0, "root": "p"}]}]},
            "release_helper": {"params": ["p"], "cfg": helper_cfg,
                               "events": [{"kind": "free", "var": "p", "node": "hentry", "line": 2}],
                               "calls": [], "returns": []},
        }
        graph = build_semantic_graph(object(), functions,
                                     {"main": ["release_helper"], "release_helper": []},
                                     lang="python", graph={})
        hits = [hit for hit in match_graph(graph) if hit["pattern"] == "uaf.deref"]
        self.assertTrue(any(hit["line"] == 4 for hit in hits))
        self.assertFalse(any(hit["line"] == 3 for hit in hits))

    def test_frontend_ir_call_guards_use_typed_null_proofs(self):
        from .emit import _ir_guard_proofs

        proofs = _ir_guard_proofs({"guards": [
            {"var": "p", "canon": "p != NULL"},
            {"var": "q", "canon": "q == NULL"},
        ]})
        self.assertEqual([(proof.kind, proof.value) for proof in proofs], [
            ("NONNULL", "p#g0"), ("ISNULL", "q#g0")])

    def _graph(self, events, edges):
        g = SkeletonGraph()
        for node, event in events:
            g.add_node(node, event)
        for source, target, *kind in edges:
            g.add_edge(source, target, kind=kind[0] if kind else "normal")
        g.add_fragment("main", events[0][0], [events[-1][0]])
        g.validate()
        return g

    def test_atropos_public_ids_cover_generic_lifetime_and_write_findings(self):
        self.assertEqual(atropos.flow_pattern_id("leak"), "mem.lifetime.leak")
        self.assertEqual(atropos.flow_pattern_id("use.dangling"),
                         "mem.lifetime.dangling-use")
        self.assertEqual(atropos.flow_pattern_evaluator("uaf.deref"), "typestate")
        self.assertEqual(atropos.flow_pattern_evaluator("double-free"), "typestate")
        self.assertEqual(atropos.flow_pattern_id("relational", "buffer-write"),
                         "mem.write.tainted-unbounded")
        self.assertEqual(atropos.flow_pattern_id("missing-guard", "alloc-size"),
                         "mem.alloc.missing-guard")

    def test_matcher_honors_atropos_event_evaluator_routing(self):
        from unittest.mock import patch

        obj = ObjRef("p", generation="g0")
        graph = self._graph([
            ("origin", Event.origin(obj)),
            ("release", Event.release(obj)),
            ("read", Event.read(obj)),
        ], [("origin", "release"), ("release", "read")])

        def route(event_kind):
            return "presence" if event_kind in {
                "origin", "release", "read_storage"} else None

        with patch("lachesis.flow.patterns.evaluator_for_event",
                   side_effect=route):
            self.assertEqual(match_graph(graph), [])

    def test_matcher_preserves_distinct_external_launch_witnesses(self):
        obj = ObjRef("p", generation="g0")
        graph = SkeletonGraph()
        graph.add_node("source_a", None, fragment="main")
        graph.add_node("source_b", None, fragment="main")
        graph.add_node("release", Event.release(obj), fragment="main")
        graph.add_node("use", Event.read(obj), fragment="main")
        graph.add_edge("source_a", "release")
        graph.add_edge("source_b", "release")
        graph.add_edge("release", "use")
        graph.add_fragment("main", "source_a", ("use",))
        graph.source_reachable.update({"source_a", "source_b"})

        hits = [hit for hit in match_graph(graph) if hit["pattern"] == "uaf.deref"]
        self.assertEqual(len(hits), 2)
        self.assertEqual({hit["source_context"] for hit in hits},
                         {"source_a", "source_b"})

    def test_neutral_seam_parser_preserves_prefix_pointer_algebra(self):
        from lachesis.flow.emit import _call_bindings, _expression_objref

        self.assertEqual(_expression_objref("&node").path, ("&",))
        self.assertEqual(_expression_objref("**triple").path, ("*", "*"))
        self.assertEqual(_expression_objref("&node->field").path,
                         ("&", "*", "field"))

        class Sub:
            @staticmethod
            def label(value):
                return value

        bindings = _call_bindings(
            Sub(), {"args": [{"pos": 0, "root": "node", "expr": "&node"}]},
            ("formal",))
        self.assertEqual(bindings[0][1], ObjRef("node", ("&",), "g0"))

    def test_matcher_falls_back_when_serialized_launch_id_is_stale(self):
        obj = ObjRef("p", generation="g0")
        graph = self._graph([
            ("origin", Event.origin(obj)),
            ("release", Event.release(obj)),
            ("use", Event.read(obj)),
        ], [("origin", "release"), ("release", "use")])
        graph.source_reachable.add("removed-after-serialization")
        self.assertTrue(any(hit["pattern"] == "uaf.deref"
                            for hit in match_graph(graph)))

    def test_public_atropos_pattern_id_selects_the_internal_matcher(self):
        obj = ObjRef("object", generation="g0")
        g = self._graph(
            [("origin", Event.origin(obj)), ("free", Event.release(obj)),
             ("use", Event.read(obj))],
            [("origin", "free"), ("free", "use")],
        )
        hits = match_graph(g, patterns={"mem.lifetime.use-after-free"})
        self.assertEqual({hit["pattern"] for hit in hits}, {"uaf.deref"})
        self.assertEqual({hit["evaluator"] for hit in hits}, {"typestate"})

    def test_relational_and_index_guards_keep_distinct_typed_proofs(self):
        class Sub:
            @staticmethod
            def label(_node):
                return "idx < bound"

        proofs = _cfg_guard_proofs(Sub(), "condition", 0, 2)
        self.assertEqual([proof.kind for proof in proofs], ["VALUE", "BOUNDED"])

    def test_truthiness_guards_produce_compatible_nullability_proofs(self):
        class Sub:
            @staticmethod
            def label(_node):
                return "buffer->data"

        true_proofs = _cfg_guard_proofs(Sub(), "condition", 0, 2)
        false_proofs = _cfg_guard_proofs(Sub(), "condition", 1, 2)
        self.assertEqual([(p.kind, p.value) for p in true_proofs],
                         [("NONNULL", "buffer->data#g0"),
                          ("VALUE", "buffer->data!=0")])
        self.assertEqual([(p.kind, p.value) for p in false_proofs],
                         [("ISNULL", "buffer->data#g0"),
                          ("VALUE", "buffer->data==0")])

    def test_scalar_truthiness_also_emits_value_proofs(self):
        class Sub:
            @staticmethod
            def label(_node):
                return "mode"

        proofs = _cfg_guard_proofs(Sub(), "condition", 0, 2)
        self.assertEqual([(p.kind, p.value) for p in proofs], [
            ("NONNULL", "mode#g0"), ("VALUE", "mode!=0")])

    def test_compound_null_guards_preserve_only_provable_arm_facts(self):
        class Sub:
            @staticmethod
            def label(_node):
                return "!triple || !*triple || !**triple"

        true_proofs = _cfg_guard_proofs(Sub(), "condition", 0, 2)
        false_proofs = _cfg_guard_proofs(Sub(), "condition", 1, 2)
        # The true arm means "at least one is NULL" and cannot be represented
        # as a conjunction. The false arm proves every pointer level non-null.
        self.assertEqual(true_proofs, ())
        self.assertEqual([(p.kind, p.value) for p in false_proofs], [
            ("NONNULL", "triple#g0"),
            ("VALUE", "triple!=0"),
            ("NONNULL", "*triple#g0"),
            ("VALUE", "*triple!=0"),
            ("NONNULL", "**triple#g0"),
            ("VALUE", "**triple!=0"),
        ])

    def test_compound_nonnull_conjunction_proves_each_term(self):
        class Sub:
            @staticmethod
            def label(_node):
                return "triple && *triple && **triple"

        true_proofs = _cfg_guard_proofs(Sub(), "condition", 0, 2)
        false_proofs = _cfg_guard_proofs(Sub(), "condition", 1, 2)
        self.assertEqual([(p.kind, p.value) for p in true_proofs], [
            ("NONNULL", "triple#g0"),
            ("VALUE", "triple!=0"),
            ("NONNULL", "*triple#g0"),
            ("VALUE", "*triple!=0"),
            ("NONNULL", "**triple#g0"),
            ("VALUE", "**triple!=0"),
        ])
        self.assertEqual(false_proofs, ())

    def test_atropos_sink_history_matches_size_mismatch(self):
        events = [
            ("alloc", Event(EventKind.SINK, obj=ObjRef("buf"), facts={
                "family": "alloc-size", "callee": "malloc", "dst": "buf",
                "size_expr": "capacity", "tainted": True, "guarded": False,
            })),
            ("copy", Event(EventKind.SINK, obj=ObjRef("buf"), facts={
                "family": "buffer-write", "callee": "memcpy", "dst": "buf",
                "size_expr": "incoming", "tainted": True, "guarded": False,
            })),
        ]
        g = self._graph(events, [("alloc", "copy")])
        hit = next(hit for hit in match_graph(g)
                   if hit["pattern"] == "mem.alloc-copy.size-mismatch")
        self.assertEqual(hit["pattern_id"], "mem.alloc-copy.size-mismatch")

    def test_fall_through_guard_routes_to_missing_bounds(self):
        event = Event(EventKind.SINK, obj=ObjRef("buf"), facts={
            "family": "buffer-write", "callee": "memcpy", "arg": 2,
            "tainted": True, "guarded": False, "guard_status": "fall-through",
        })
        g = self._graph([("sink", event)], [])
        hit = next(hit for hit in match_graph(g) if hit["pattern"] == "missing-guard")
        self.assertEqual(hit["pattern_id"], "mem.write.missing-bounds")

    def test_inverted_capacity_guard_is_catalogued_and_generic(self):
        event = Event(EventKind.SINK, obj=ObjRef("name"), facts={
            "family": "buffer-write", "callee": "memcpy", "arg": 0,
            "tainted": True, "guarded": True,
            "guard_status": "guarded-region", "size_expr": "incoming",
            "guard_predicates": ("incoming >= capacity",),
        })
        g = self._graph([("sink", event)], [])
        hit = next(hit for hit in match_graph(g)
                   if hit["pattern"] == "inverted-capacity-guard")
        self.assertEqual(hit["pattern_id"],
                         "mem.write.inverted-capacity-guard")

    def test_arithmetic_overflow_guard_is_catalogued(self):
        event = Event(EventKind.SINK, obj=ObjRef("data"), facts={
            "family": "buffer-size", "callee": "memset", "arg": 2,
            "tainted": True, "guarded": True,
            "guard_predicates": ("offset + length <= capacity",),
        })
        g = self._graph([("sink", event)], [])
        hit = next(hit for hit in match_graph(g)
                   if hit["pattern"] == "arithmetic-overflow-guard")
        self.assertEqual(hit["pattern_id"],
                         "mem.arithmetic.overflow-before-bound")

    def test_pointer_arithmetic_before_validation_has_public_id(self):
        self.assertEqual(atropos.event_evaluator("pointer_arithmetic"), "typestate")
        self.assertEqual(atropos.event_evaluator("derive"), "typestate")
        base = ObjRef("buffer")
        derived = ObjRef("location")
        events = [
            ("derive", Event(EventKind.POINTER_ARITHMETIC,
                              obj=derived, base=base, line=1)),
            ("read", Event.read(derived, "*", 2)),
        ]
        g = self._graph(events, [("derive", "read")])
        hit = next(hit for hit in match_graph(g)
                   if hit["pattern"] == "pointer-arithmetic-before-validation")
        self.assertEqual(hit["pattern_id"],
                         "mem.pointer-arithmetic.before-validation")

    def test_checked_nullable_return_deref_is_not_unchecked(self):
        obj = ObjRef("result")
        events = [
            ("origin", Event(EventKind.ORIGIN, obj=obj,
                              facts={"return_may_null": True})),
            ("check", None),
            ("use", Event.read(obj)),
        ]
        g = self._graph(events, [("origin", "check"), ("check", "use")])
        g.edges["check"][0] = Edge(
            target="use", guard=(GuardProof("NONNULL", obj.render()),))
        self.assertNotIn("unchecked-return-deref",
                         {hit["pattern"] for hit in match_graph(g)})

    def test_branch_arms_do_not_form_a_linear_false_positive(self):
        o = ObjRef("O_buf", generation="g0")
        events = [("start", None), ("true_free", Event.release(o, 2)),
                  ("false_keep", None), ("merge", None),
                  ("use", Event.read(o, ".data", 5))]
        g = self._graph(events, [("start", "true_free"), ("start", "false_keep"),
                                 ("true_free", "merge"), ("false_keep", "merge"),
                                 ("merge", "use")])
        # The use is reachable from the true arm and is therefore correctly a lead; the graph
        # does not invent a free->use order by flattening the false arm into the true arm.
        self.assertEqual(len(match_graph(g)), 1)
        self.assertEqual(match_graph(g)[0]["pattern"], "uaf.deref")
        self.assertEqual(match_graph(g)[0]["witness"], ["start", "true_free", "merge", "use"])
        trace = match_graph(g)[0]["witness_trace"]
        self.assertEqual([item["node"] for item in trace],
                         ["start", "true_free", "merge", "use"])
        self.assertEqual(trace[1]["kind"], str(EventKind.RELEASE))
        self.assertEqual(trace[-1]["line"], 5)
        self.assertEqual(match_graph(g)[0]["source_node"], "start")
        self.assertIsNone(match_graph(g)[0]["source_entry"])

    def test_storage_free_does_not_free_pointee(self):
        buf = ObjRef("O_buf", generation="g0")
        payload = ObjRef("O_payload", generation="g0")
        events = [("start", None), ("capture", Event(EventKind.DERIVE, value=payload, line=1)),
                  ("free", Event.release(buf, 2)), ("saved_use", Event(EventKind.PASS_VALUE,
                                                                         obj=payload, line=3))]
        g = self._graph(events, [("start", "capture"), ("capture", "free"), ("free", "saved_use")])
        self.assertEqual(match_graph(g), [])

    def test_field_pointee_release_matches_field_pointee_dereference(self):
        aggregate = ObjRef("b", generation="g0")
        payload = aggregate.child("*data")
        events = [
            ("start", None),
            ("free", Event.release(payload, 2)),
            ("use", Event.read(payload, "[*]", 3)),
        ]
        g = self._graph(events, [("start", "free"), ("free", "use")])
        hits = match_graph(g)
        self.assertEqual([hit["pattern"] for hit in hits], ["uaf.deref"])
        self.assertEqual(hits[0]["object"], payload.render())

    def test_seam_rebase_does_not_repeat_same_base_field_suffix(self):
        caller_obj = ObjRef("n", generation="g0")
        alias = caller_obj.child("*borrowed_name")
        owned = caller_obj.child("*meta").child("*name")
        callee_obj = ObjRef("m", generation="g0")
        graph = SkeletonGraph()
        graph.add_node("start", Event(EventKind.DERIVE, obj=alias, value=owned),
                       fragment="caller")
        graph.add_node("enter", Event(EventKind.SEAM_ENTER), fragment="caller")
        graph.add_node("free", Event.release(callee_obj.child("*name")),
                       fragment="callee")
        graph.add_node("exit", Event(EventKind.SEAM_EXIT), fragment="caller")
        graph.add_node("use", Event.pass_value(alias), fragment="caller")
        graph.add_fragment("caller", "start", ["use"])
        graph.add_fragment("callee", "free", ["free"])
        graph.source_reachable = {"start"}
        graph.add_edge("start", "enter")
        graph.add_edge("enter", "free", kind="call", return_to="exit",
                       binding=((callee_obj, caller_obj.child("*meta")),))
        graph.add_edge("free", "exit", kind="return")
        graph.add_edge("exit", "use")

        hits = match_graph(graph)
        self.assertIn("use.dangling", {hit["pattern"] for hit in hits})

    def test_abstract_identity_prevents_same_named_local_false_uaf(self):
        obj = ObjRef("p", generation="g0")
        g = SkeletonGraph()
        g.add_node("caller", Event(EventKind.RELEASE, obj=obj, facts={
            "abstract_object_ids": ["('clobber', 'recent', 'caller', 'p')"],
        }), fragment="caller")
        g.add_node("callee", Event(EventKind.READ_STORAGE, base=obj, obj=obj,
                                     facts={"abstract_object_ids": ["('clobber', 'recent', 'callee', 'p')"]}),
                    fragment="callee")
        g.add_fragment("caller", "caller", ["caller"])
        g.add_fragment("callee", "callee", ["callee"])
        g.add_edge("caller", "callee")
        self.assertNotIn("uaf.deref", {hit["pattern"] for hit in match_graph(g)})

        g.nodes["callee"].event.facts["abstract_object_ids"] = ["('clobber', 'recent', 'caller', 'p')"]
        self.assertIn("uaf.deref", {hit["pattern"] for hit in match_graph(g)})

    def test_parameter_identity_is_scoped_between_unrelated_fragments(self):
        identity = "('param', 0, ('*', 'data'))"
        g = SkeletonGraph()
        g.add_node("release", Event(EventKind.RELEASE,
                                     obj=ObjRef("p", ("*", "data")),
                                     facts={"abstract_object_ids": [identity]}),
                   fragment="owner")
        g.add_node("use", Event(EventKind.READ_STORAGE,
                                 obj=ObjRef("q", ("*", "data")),
                                 base=ObjRef("q", ("*", "data")),
                                 facts={"abstract_object_ids": [identity]}),
                   fragment="unrelated")
        g.add_fragment("owner", "release", ["release"])
        g.add_fragment("unrelated", "use", ["use"])
        g.add_edge("release", "use")
        self.assertNotIn("uaf.deref", {hit["pattern"] for hit in match_graph(g)})

    def test_new_origin_clears_prior_abstract_release_at_same_site(self):
        obj = ObjRef("p", generation="g0")
        identity = ["('alloc', 'site', 'helper', 'p')"]
        events = [
            ("first", Event.origin(obj, facts={"abstract_object_ids": identity})),
            ("free", Event(EventKind.RELEASE, obj=obj,
                            facts={"abstract_object_ids": identity})),
            ("second", Event.origin(obj, facts={"abstract_object_ids": identity})),
            ("use", Event(EventKind.READ_STORAGE, obj=obj, base=obj,
                           facts={"abstract_object_ids": identity})),
        ]
        g = self._graph(events, [(events[i][0], events[i + 1][0])
                                 for i in range(len(events) - 1)])
        self.assertNotIn("uaf.deref", {hit["pattern"] for hit in match_graph(g)})

    def test_derive_preserves_alias_identity(self):
        original = ObjRef("O", generation="g0")
        alias = ObjRef("saved", generation="g0")
        events = [("start", Event.origin(original)),
                  ("derive", Event(EventKind.DERIVE, obj=alias, value=original)),
                  ("free", Event.release(original, 2)),
                  ("use", Event.read(alias, "*", 3))]
        g = self._graph(events, [("start", "derive"), ("derive", "free"), ("free", "use")])
        self.assertTrue(any(h["pattern"] == "uaf.deref" for h in match_graph(g)))

    def test_realloc_invalidation_matches_stale_alias_across_abstract_fields(self):
        """A stale loop-local alias must observe realloc's old incarnation."""
        old = ObjRef("b", ("*", "data"), "g0")
        cursor = ObjRef("cursor", generation="g0")
        identity = "('param', 0, ('*', 'data'))"
        events = [
            ("origin", Event.origin(old)),
            ("invalidate", Event(EventKind.INVALIDATE, obj=old,
                                  facts={"abstract_source_ids": [identity]})),
            ("use", Event(EventKind.WRITE_STORAGE, obj=cursor, base=cursor,
                           path="*", facts={"abstract_object_ids": [identity]})),
        ]
        g = self._graph(events, [("origin", "invalidate"),
                                 ("invalidate", "use")])
        self.assertTrue(any(hit["pattern"] == "uaf.deref"
                            and hit["node"] == "use"
                            for hit in match_graph(g)))

    def test_address_and_deref_algebra_survives_a_call_seam(self):
        """A multi-level address chain must identify the released pointee.

        The shape is deliberately expressed only in the skeleton alphabet: the caller
        builds ``p1 = &object`` and ``p2 = &p1``; the callee receives ``p2`` as a
        triple-pointer formal and releases ``**formal``.  The unrelated alias must still
        match the release after the pushdown return.
        """
        obj = ObjRef("object", generation="g0")
        alias = ObjRef("alias", generation="g0")
        p1 = ObjRef("p1", generation="g0")
        p2 = ObjRef("p2", generation="g0")
        formal = ObjRef("formal", generation="g0")
        target = ObjRef("target", generation="g0")

        g = SkeletonGraph()
        for node, event in [
                ("start", Event.origin(obj)),
                ("alias", Event(EventKind.DERIVE, obj=alias, value=obj)),
                ("p1", Event(EventKind.DERIVE, obj=p1,
                              value=ObjRef(obj.base, ("&",), obj.generation))),
                ("p2", Event(EventKind.DERIVE, obj=p2,
                              value=ObjRef(p1.base, ("&",), p1.generation))),
                ("enter", Event(EventKind.SEAM_ENTER)),
                ("target", Event(EventKind.DERIVE, obj=target,
                                  value=ObjRef(formal.base, ("*", "*"), formal.generation))),
                ("free", Event.release(target)),
                ("return", Event(EventKind.SEAM_EXIT)),
                ("use", Event.read(alias)),
                ("exit", None),
        ]:
            g.add_node(node, event, fragment="main")
        g.add_edge("start", "alias")
        g.add_edge("alias", "p1")
        g.add_edge("p1", "p2")
        g.add_edge("p2", "enter")
        g.add_edge("enter", "target", kind="call", return_to="return",
                    binding=((formal, p2),))
        g.add_edge("target", "free")
        g.add_edge("free", "return", kind="return")
        g.add_edge("return", "use")
        g.add_edge("use", "exit")
        g.add_fragment("main", "start", ["exit"])
        g.validate()

        hits = match_graph(g)
        self.assertTrue(any(hit["pattern"] == "uaf.deref"
                            and hit["node"] == "use" for hit in hits))

    def test_compare_is_a_dangling_value_use_not_a_deref(self):
        obj = ObjRef("p", generation="g0")
        events = [("origin", Event.origin(obj)), ("free", Event.release(obj, 2)),
                  ("compare", Event(EventKind.COMPARE_VALUE, obj=obj, line=3))]
        g = self._graph(events, [("origin", "free"), ("free", "compare")])
        patterns = {hit["pattern"] for hit in match_graph(g)}
        self.assertEqual(patterns, {"use.dangling"})

    def test_leak_requires_a_non_escaped_origin_at_top_level_exit(self):
        leaked = ObjRef("leaked", generation="g0")
        g = self._graph([("origin", Event.origin(leaked)), ("exit", None)],
                        [("origin", "exit")])
        self.assertEqual({hit["pattern"] for hit in match_graph(g)}, {"leak"})

        returned = ObjRef("returned", generation="g0")
        g = self._graph([("origin", Event.origin(returned)),
                         ("return", Event(EventKind.RETURN_VALUE, obj=returned)),
                         ("exit", None)], [("origin", "return"), ("return", "exit")])
        self.assertNotIn("leak", {hit["pattern"] for hit in match_graph(g)})

    def test_null_rebind_is_not_a_second_free_and_null_deref_is_distinct(self):
        obj = ObjRef("p", generation="g0")
        events = [("start", Event.origin(obj)),
                  ("null", Event(EventKind.WRITE_STORAGE_NULL, obj=obj)),
                  ("free", Event.release(obj, 2)),
                  ("use", Event.read(obj, "*", 3))]
        g = self._graph(events, [("start", "null"), ("null", "free"), ("free", "use")])
        patterns = {h["pattern"] for h in match_graph(g)}
        self.assertIn("null-deref", patterns)
        self.assertNotIn("double-free", patterns)

    def test_nulling_one_alias_does_not_null_the_other_slot(self):
        obj = ObjRef("p", generation="g0")
        alias = ObjRef("q", generation="g0")
        events = [
            ("origin", Event.origin(obj)),
            ("derive", Event(EventKind.DERIVE, obj=alias, value=obj)),
            ("null_p", Event(EventKind.WRITE_STORAGE_NULL, obj=obj)),
            ("free_q", Event.release(alias, 4)),
            ("use_q", Event.read(alias, "*", 5)),
        ]
        g = self._graph(events, [("origin", "derive"), ("derive", "null_p"),
                                 ("null_p", "free_q"), ("free_q", "use_q")])
        patterns = {hit["pattern"] for hit in match_graph(g)}
        self.assertIn("uaf.deref", patterns)
        self.assertNotIn("null-deref", patterns)

    def test_realloc_failure_loses_slot_but_preserves_an_existing_alias(self):
        old = ObjRef("p", generation="g0")
        saved = ObjRef("saved", generation="g0")
        events = [
            ("origin", Event.origin(old)),
            ("derive", Event(EventKind.DERIVE, obj=saved, value=old)),
            ("failed", Event.realloc_failed(old, old)),
            ("null", Event.write_null(old)),
            ("lost", Event(EventKind.LOST_FROM_SLOT, obj=old, slot=old)),
            ("exit", None),
        ]
        g = self._graph(events, [(events[i][0], events[i + 1][0]) for i in range(len(events) - 1)])
        self.assertNotIn("leak", {hit["pattern"] for hit in match_graph(g)})

    def test_realloc_failure_without_an_alias_is_a_leak(self):
        old = ObjRef("p", generation="g0")
        events = [
            ("origin", Event.origin(old)),
            ("failed", Event.realloc_failed(old, old)),
            ("null", Event.write_null(old)),
            ("lost", Event(EventKind.LOST_FROM_SLOT, obj=old, slot=old)),
            ("exit", None),
        ]
        g = self._graph(events, [(events[i][0], events[i + 1][0]) for i in range(len(events) - 1)])
        self.assertEqual({hit["pattern"] for hit in match_graph(g)},
                         {"leak", "mem.lifetime.realloc-failure-leak"})

    def test_loop_reorigin_does_not_rebind_an_old_alias(self):
        slot = ObjRef("p", generation="g0")
        alias = ObjRef("saved", generation="g0")
        events = [
            ("first_origin", Event.origin(slot)),
            ("save", Event(EventKind.DERIVE, obj=alias, value=slot)),
            ("loop", Event(EventKind.LOOP)),
            ("release_old", Event.release(slot)),
            # The source-level slot spelling is unchanged; the matcher must
            # widen this into a new incarnation at the loop boundary.
            ("next_origin", Event.origin(slot, facts={"loop_widening": True})),
            ("use_old_alias", Event.read(alias)),
        ]
        g = self._graph(events, [(events[i][0], events[i + 1][0])
                                 for i in range(len(events) - 1)])
        hit = next(hit for hit in match_graph(g) if hit["pattern"] == "uaf.deref")
        self.assertEqual(hit["object"], "p#g0")

    def test_repeated_loop_origins_reset_the_current_incarnation(self):
        slot = ObjRef("p", generation="g0")
        events = [
            ("first", Event.origin(slot)),
            ("loop1", Event(EventKind.LOOP)),
            ("second", Event.origin(slot, facts={"loop_widening": True})),
            ("release1", Event.release(slot)),
            ("loop2", Event(EventKind.LOOP)),
            ("third", Event.origin(slot, facts={"loop_widening": True})),
            ("release2", Event.release(slot)),
        ]
        g = self._graph(events, [
            (events[index][0], events[index + 1][0])
            for index in range(len(events) - 1)
        ])
        self.assertNotIn("double-free",
                         {hit["pattern"] for hit in match_graph(g)})

    def test_branch_reorigin_rebinds_slot_but_not_captured_alias(self):
        slot0 = ObjRef("p", generation="g0")
        slot1 = ObjRef("p", generation="g1")
        alias = ObjRef("saved", generation="g0")
        g = SkeletonGraph()
        for node, event in [
                ("start", Event.origin(slot0)),
                ("save", Event(EventKind.DERIVE, obj=alias, value=slot0)),
                ("branch", Event(EventKind.BRANCH)),
                ("reorigin", Event.origin(slot1)),
                ("free", Event.release(slot1)),
                ("other", None),
                ("merge", Event(EventKind.MERGE)),
                ("use", Event.read(slot0, line=8)),
                ("exit", None)]:
            g.add_node(node, event, fragment="main")
        g.add_edge("start", "save")
        g.add_edge("save", "branch")
        g.add_edge("branch", "reorigin")
        g.add_edge("branch", "other")
        g.add_edge("reorigin", "free")
        g.add_edge("free", "merge")
        g.add_edge("other", "merge")
        g.add_edge("merge", "use")
        g.add_edge("use", "exit")
        g.add_fragment("main", "start", ["exit"])
        hits = [hit for hit in match_graph(g) if hit["pattern"] == "uaf.deref"]
        self.assertEqual([hit["node"] for hit in hits], ["use"])
        self.assertEqual(hits[0]["object"], "p#g1")

    def test_returning_an_owner_keeps_its_field_allocation_reachable(self):
        owner = ObjRef("b", generation="g0")
        field = ObjRef("b", ("*", "data"), generation="g0")
        events = [
            ("owner", Event.origin(owner)),
            ("field", Event.origin(field)),
            ("return_value", Event(EventKind.RETURN_VALUE, obj=owner)),
            ("return", Event(EventKind.RETURN, obj=owner)),
        ]
        g = self._graph(events, [(events[i][0], events[i + 1][0])
                                 for i in range(len(events) - 1)])
        self.assertNotIn("leak", {hit["pattern"] for hit in match_graph(g)})

    def test_live_is_not_a_frozen_guard_proof(self):
        obj = ObjRef("p", generation="g0")
        g = self._graph(
            [("origin", Event.origin(obj)), ("free", Event.release(obj)),
             ("use", Event.read(obj))],
            [("origin", "free"), ("free", "use", "normal")],
        )
        g.edges["free"][0] = Edge(target="use", guard=(GuardProof("LIVE", obj.render()),))
        self.assertIn("uaf.deref", {hit["pattern"] for hit in match_graph(g)})

    def test_address_and_deref_bindings_cancel_across_multiple_derives(self):
        node = ObjRef("node")
        p1 = ObjRef("p1")
        p2 = ObjRef("p2")
        target = ObjRef("target")
        alias = ObjRef("alias")
        events = [
            ("origin", Event.origin(node)),
            ("p1", Event(EventKind.DERIVE, obj=p1, value=ObjRef("node", ("&",)))),
            ("p2", Event(EventKind.DERIVE, obj=p2, value=ObjRef("p1", ("&",)))),
            ("target", Event(EventKind.DERIVE, obj=target,
                             value=ObjRef("p2", ("*", "*")))),
            ("release", Event.release(target)),
            ("alias", Event(EventKind.DERIVE, obj=alias, value=node)),
            ("use", Event.write(alias)),
        ]
        g = self._graph(events, [(events[i][0], events[i + 1][0]) for i in range(len(events) - 1)])
        self.assertIn("uaf.deref", {hit["pattern"] for hit in match_graph(g)})

    def test_field_binding_composes_across_a_call_seam(self):
        formal = ObjRef("formal", ("*", "data"))
        actual = ObjRef("actual", ("*", "data"))
        g = SkeletonGraph()
        for node, event in [("caller", Event.origin(ObjRef("actual"))),
                            ("enter", Event(EventKind.SEAM_ENTER)),
                            ("free", Event.release(formal)),
                            ("exit", Event(EventKind.SEAM_EXIT)),
                            ("use", Event.write(actual))]:
            g.add_node(node, event)
        g.add_fragment("caller", "caller", ["use"])
        g.add_fragment("callee", "enter", ["exit"])
        g.add_edge("caller", "enter", kind="call", return_to="use",
                   binding=((ObjRef("formal"), ObjRef("actual")),))
        g.add_edge("enter", "free")
        g.add_edge("free", "exit")
        g.add_edge("exit", "use", kind="return")
        self.assertIn("uaf.deref", {hit["pattern"] for hit in match_graph(g)})

    def test_abstract_provenance_composes_across_a_call_seam(self):
        formal = ObjRef("formal")
        actual = ObjRef("actual")
        formal_id = repr(("param", 0, ()))
        actual_id = repr(("alloc", "recent", "caller-site"))
        g = SkeletonGraph()
        g.add_node("caller", Event.origin(actual))
        g.add_node("enter", Event(EventKind.SEAM_ENTER))
        g.add_node("free", Event(EventKind.RELEASE, obj=formal,
                                   facts={"abstract_object_ids": [formal_id]}))
        g.add_node("exit", Event(EventKind.SEAM_EXIT))
        g.add_node("use", Event(EventKind.READ_STORAGE, obj=actual, base=actual,
                                  facts={"abstract_object_ids": [actual_id]}))
        g.add_fragment("caller", "caller", ["use"])
        g.add_fragment("callee", "enter", ["exit"])
        g.add_edge("caller", "enter", kind="call", return_to="use",
                   binding=((formal, actual),), provenance=((formal_id, actual_id),))
        g.add_edge("enter", "free")
        g.add_edge("free", "exit")
        g.add_edge("exit", "use", kind="return")
        self.assertIn("uaf.deref", {hit["pattern"] for hit in match_graph(g)})

    def test_source_tiers_are_preserved_on_leads(self):
        obj = ObjRef("p", generation="g0")
        g = SkeletonGraph()
        g.add_node("s", Event.release(obj), fragment="source",
                   source_reachable=True, source_influenced=True)
        g.add_node("u", Event.read(obj), fragment="source",
                   source_reachable=True, source_influenced=False)
        g.add_edge("s", "u")
        g.add_fragment("source", "s", ["u"])
        hits = match_graph(g)
        self.assertEqual([(h["pattern"], h["tier"]) for h in hits if h["pattern"] == "uaf.deref"],
                         [("uaf.deref", 2)])

    def test_witness_reports_edges_and_external_context(self):
        obj = ObjRef("p", generation="g0")
        g = SkeletonGraph()
        g.add_node("launch", Event.origin(obj, 17), fragment="main",
                   source_site="read@17")
        g.add_node("free", Event.release(obj), fragment="main")
        g.add_node("use", Event.read(obj), fragment="main")
        g.add_edge("launch", "free", guard=(GuardProof("NONNULL", "p#g0"),))
        g.add_edge("free", "use", kind="normal")
        g.add_fragment("main", "launch", ["use"])
        g.source_reachable.add("launch")
        hit = next(item for item in match_graph(g) if item["pattern"] == "uaf.deref")
        self.assertEqual(hit["source_context"], "launch")
        self.assertEqual(hit["source_function"], "main")
        self.assertEqual(hit["source_site"], "read@17")
        self.assertEqual(hit["source_line"], 17)
        self.assertTrue(hit["witness_complete"])
        self.assertEqual(hit["witness_edges"][0]["guards"][0]["kind"], "NONNULL")

    def test_escape_is_first_class_and_keeps_the_object_live_for_leak_matching(self):
        obj = ObjRef("p", generation="g0")
        g = SkeletonGraph()
        g.add_node("origin", Event.origin(obj), fragment="main")
        g.add_node("escape", Event(EventKind.ESCAPE, obj=obj), fragment="main")
        g.add_node("exit", None, fragment="main")
        g.add_edge("origin", "escape")
        g.add_edge("escape", "exit")
        g.add_fragment("main", "origin", ("exit",))
        self.assertNotIn("leak", {hit["pattern"] for hit in match_graph(g)})

    def test_persistent_slot_alias_observes_release_through_another_alias(self):
        obj = ObjRef("node", generation="g0")
        slot = ObjRef("cached", generation="g0")
        g = self._graph([
            ("origin", Event.origin(obj)),
            ("store", Event(EventKind.DERIVE, obj=slot, value=obj,
                             facts={"persistent_slot": True})),
            ("release", Event.release(obj)),
            ("read", Event.read(slot)),
        ], [("origin", "store"), ("store", "release"), ("release", "read")])
        patterns = {hit["pattern"] for hit in match_graph(g)}
        self.assertIn("uaf.deref", patterns)
        self.assertNotIn("leak", patterns)

    def test_stack_address_store_is_use_after_return(self):
        local = ObjRef("local", ("&",), generation="g0")
        g = self._graph([
            ("store", Event(EventKind.RETURN_VALUE, obj=local,
                             facts={"stack_local": True, "escape_store": True})),
            ("exit", None),
        ], [("store", "exit")])
        self.assertIn("use-after-return", {hit["pattern"] for hit in match_graph(g)})

    def test_generic_ir_preserves_stack_escape_event(self):
        from .emit import build_semantic_graph

        graph = build_semantic_graph(
            object(),
            {"main": {"is_source": True, "source_reachable": True,
                      "events": [{"kind": "stack_escape", "var": "local", "line": 3}],
                      "calls": []}},
            {"main": []}, lang="python", graph={})
        self.assertIn("use-after-return", {hit["pattern"] for hit in match_graph(graph)})

    def test_pointer_slot_value_propagates_to_release_and_read(self):
        item = ObjRef("item", generation="g0")
        slot = ObjRef("items", ("[i]",), generation="g0")
        g = self._graph([
            ("origin", Event.origin(item)),
            ("store", Event.write(slot, value=item)),
            ("release", Event.release(slot)),
            ("read", Event.read(slot)),
        ], [("origin", "store"), ("store", "release"), ("release", "read")])
        self.assertIn("uaf.deref",
                      {hit["pattern"] for hit in match_graph(g)})

    def test_pointer_slot_binding_rebases_across_call_return_seam(self):
        value = ObjRef("new", generation="g0")
        formal = ObjRef("out", generation="g0")
        actual = ObjRef("holder", generation="g0")
        g = SkeletonGraph()
        nodes = [
            ("launch", None, "main"),
            ("enter", Event(EventKind.SEAM_ENTER), "main"),
            ("hentry", None, "helper"),
            ("origin", Event.origin(value), "helper"),
            ("store", Event.write(formal.child("*"), value=value), "helper"),
            ("hexit", None, "helper"),
            ("cont", Event(EventKind.SEAM_EXIT), "main"),
            ("release", Event.release(actual.child("*")), "main"),
            ("read", Event.read(actual.child("*")), "main"),
            ("exit", None, "main"),
        ]
        for node, event, fragment in nodes:
            g.add_node(node, event, fragment=fragment)
        g.add_edge("launch", "enter")
        g.add_edge("enter", "hentry", kind="call", return_to="cont",
                   binding=((formal, actual),))
        g.add_edge("hentry", "origin")
        g.add_edge("origin", "store")
        g.add_edge("store", "hexit")
        g.add_edge("hexit", "cont", kind="return")
        g.add_edge("cont", "release")
        g.add_edge("release", "read")
        g.add_edge("read", "exit")
        g.add_fragment("main", "launch", ("exit",))
        g.add_fragment("helper", "hentry", ("hexit",), params=("out",))
        g.source_reachable.add("launch")
        g.validate()
        self.assertIn("uaf.deref",
                      {hit["pattern"] for hit in match_graph(g)})

    def test_witness_keeps_the_edge_taken_when_parallel_guards_share_nodes(self):
        obj = ObjRef("p", generation="g0")
        g = SkeletonGraph()
        g.add_node("start", Event.origin(obj), fragment="main")
        g.add_node("free", Event.release(obj), fragment="main")
        g.add_node("use", Event.read(obj), fragment="main")
        # The ISNULL arm cannot release p; only the NONNULL arm reaches the
        # lifecycle violation.  Both arms intentionally have the same nodes,
        # so choosing the first graph edge during report reconstruction would
        # attach the wrong proof to the witness.
        g.add_edge("start", "free", guard=(GuardProof("ISNULL", "p#g0"),))
        g.add_edge("start", "free", guard=(GuardProof("NONNULL", "p#g0"),))
        g.add_edge("free", "use")
        g.add_fragment("main", "start", ["use"])
        hit = next(item for item in match_graph(g) if item["pattern"] == "uaf.deref")
        self.assertTrue(hit["witness_complete"])
        self.assertEqual(hit["witness_edges"][0]["guards"],
                         [{"kind": "NONNULL", "value": "p#g0"}])

    def test_guard_compatibility_survives_a_formal_to_field_seam(self):
        actual = ObjRef("s", ("*", "request"), generation="g0")
        formal = ObjRef("b", generation="g0")
        g = SkeletonGraph()
        for node, event in [
                ("start", Event.origin(actual)),
                ("enter", Event(EventKind.SEAM_ENTER)),
                ("check", None),
                ("free", Event.release(formal)),
                ("exit", Event(EventKind.SEAM_EXIT)),
                ("after", Event.read(actual)),
        ]:
            g.add_node(node, event, fragment="caller" if node in {"start", "after"}
                       else "callee")
        g.add_edge("start", "enter", kind="call", return_to="after",
                   binding=((formal, actual),))
        g.add_edge("enter", "check")
        g.add_edge("check", "free", guard=(GuardProof("ISNULL", "b#g0"),))
        g.add_edge("check", "free", guard=(GuardProof("NONNULL", "b#g0"),))
        g.add_edge("free", "exit")
        g.add_edge("exit", "after", kind="return")
        g.add_fragment("caller", "start", ["after"])
        g.add_fragment("callee", "enter", ["exit"])
        hit = next(item for item in match_graph(g) if item["pattern"] == "uaf.deref")
        self.assertEqual(hit["witness_edges"][2]["guards"],
                         [{"kind": "NONNULL", "value": "b#g0"}])

    def test_guard_state_does_not_cross_mutually_exclusive_cfg_arms(self):
        obj = ObjRef("p", generation="g0")
        g = SkeletonGraph()
        g.add_node("start", Event.origin(obj), fragment="main")
        g.add_node("first_check", Event(EventKind.BRANCH), fragment="main")
        g.add_node("success", None, fragment="main")
        g.add_node("failure", None, fragment="main")
        g.add_node("merge", None, fragment="main")
        g.add_node("second_check", Event(EventKind.BRANCH), fragment="main")
        g.add_node("free", Event.release(obj), fragment="main")
        g.add_node("use", Event.read(obj), fragment="main")
        g.add_edge("start", "first_check")
        g.add_edge("first_check", "success",
                   guard=(GuardProof("NONNULL", "p#g0"),))
        g.add_edge("first_check", "failure",
                   guard=(GuardProof("ISNULL", "p#g0"),))
        g.add_edge("success", "merge")
        g.add_edge("failure", "merge")
        # This resembles a real CFG join: the later null arm is only feasible
        # on the earlier null path, never after the known-nonnull arm.
        g.add_edge("merge", "second_check")
        g.add_edge("second_check", "free",
                   guard=(GuardProof("ISNULL", "p#g0"),))
        g.add_edge("free", "use")
        g.add_fragment("main", "start", ["use"])
        self.assertNotIn("uaf.deref", {hit["pattern"] for hit in match_graph(g)})

    def test_value_guards_do_not_create_an_impossible_temporal_path(self):
        obj = ObjRef("p", generation="g0")
        g = SkeletonGraph()
        for node, event in [
                ("start", Event.origin(obj)),
                ("first_check", Event(EventKind.BRANCH)),
                ("free", Event.release(obj)),
                ("merge", None),
                ("use", Event.read(obj)),
        ]:
            g.add_node(node, event, fragment="main")
        g.add_edge("start", "first_check")
        g.add_edge("first_check", "free",
                   guard=(GuardProof("VALUE", "mode==1"),))
        g.add_edge("first_check", "merge",
                   guard=(GuardProof("VALUE", "mode!=1"),))
        g.add_edge("free", "merge")
        # The only edge to the use requires mode != 1.  A release on the
        # mode == 1 arm must not be carried through the join into this use.
        g.add_edge("merge", "use",
                   guard=(GuardProof("VALUE", "mode!=1"),))
        g.add_fragment("main", "start", ["use"])
        self.assertNotIn("uaf.deref", {hit["pattern"] for hit in match_graph(g)})

    def test_call_returns_only_to_pushed_continuation(self):
        o = ObjRef("O", generation="g0")
        g = SkeletonGraph()
        for node, event in [("caller", None), ("enter", Event(EventKind.SEAM_ENTER)),
                            ("free", Event.release(o, 10)), ("exit", Event(EventKind.SEAM_EXIT)),
                            ("after", Event(EventKind.READ_STORAGE, base=o, line=11)),
                            ("wrong", Event(EventKind.READ_STORAGE, base=o, line=99)),
                            ("callee_end", None)]:
            g.add_node(node, event)
        g.add_fragment("caller", "caller", ["after"])
        g.add_fragment("callee", "enter", ["exit"])
        g.add_edge("caller", "enter", kind="call", return_to="after")
        g.add_edge("enter", "free")
        g.add_edge("free", "exit")
        g.add_edge("exit", "after", kind="return")
        g.add_edge("exit", "wrong", kind="return")
        self.assertEqual([h["node"] for h in match_graph(g) if h["pattern"] == "uaf.deref"], ["after"])

    def test_null_return_cannot_cross_a_caller_nonnull_guard(self):
        receiver = ObjRef("p", generation="g0")
        returned = ObjRef("__return__", generation="g0")
        g = SkeletonGraph()
        g.add_node("caller", None, fragment="caller")
        g.add_node("enter", None, fragment="callee")
        g.add_node("null", Event(EventKind.RETURN_VALUE,
                                  facts={"return_null": True}), fragment="callee")
        g.add_node("exit", Event(EventKind.RETURN), fragment="callee")
        g.add_node("check", Event(EventKind.BRANCH), fragment="caller")
        g.add_node("use", Event.read(receiver, line=9), fragment="caller")
        g.add_edge("caller", "enter", kind="call", return_to="check")
        g.add_edge("enter", "null")
        g.add_edge("null", "exit")
        g.add_edge("exit", "check", kind="return",
                   binding=((receiver, returned),))
        g.add_edge("check", "use", guard=(GuardProof("NONNULL", "p#g0"),))
        g.add_fragment("caller", "caller", ("use",))
        g.add_fragment("callee", "enter", ("exit",))
        self.assertNotIn("uaf.deref", {hit["pattern"] for hit in match_graph(g)})

    def test_semantic_graph_dict_round_trip_preserves_identity_and_seams(self):
        obj = ObjRef("buf", ("*", "data", "&"), "g7")
        formal = ObjRef("formal", ("*",), "g0")
        g = SkeletonGraph(language="c")
        g.add_node("start", Event.origin(obj, 4), fragment="main",
                   source_site="read@4")
        g.add_node("use", Event.read(obj, "data", 9), fragment="main")
        g.add_edge("start", "use", kind="call", return_to="use",
                   guard=(GuardProof("NONNULL", "buf#g7"),),
                   binding=((formal, obj),), provenance=(("a", "b"),))
        g.add_fragment("main", "start", ("use",), ("p",))
        g.source_reachable.add("start")
        g.coverage = {"converged": True, "covered_states": [["main", "main"]]}

        restored = SkeletonGraph.from_dict(g.to_dict())
        self.assertEqual(restored.nodes["start"].event.obj, obj)
        self.assertEqual(restored.edges["start"][0].binding, ((formal, obj),))
        self.assertEqual(restored.edges["start"][0].provenance, (("a", "b"),))
        self.assertEqual(restored.source_reachable, {"start"})
        self.assertEqual(restored.coverage["converged"], True)


if __name__ == "__main__":
    unittest.main()
