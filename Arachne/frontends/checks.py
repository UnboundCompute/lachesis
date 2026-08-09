"""Executable checks for every registered compiler frontend."""
from __future__ import annotations

import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from Arachne import analyze_files, read_file, walk
from Arachne.compiler_adapter import (
    analyze_typescript_with_compiler, run_project_frontends, snapshot_file_infos,
)
from Arachne.taint_analysis import taint_path
from Arachne.core.snapshot import load_snapshot
from Arachne.core.validation import validate_snapshot
from Arachne.core.contract import ContractError, FrontendSnapshot
from Arachne.core.boundaries import import_boundary_violations
from Arachne.core.identities import stable_id
from Arachne.core.query import GraphIndex
from Arachne.ecosystems import EcosystemRegistry
from Arachne.ecosystems.common import GenericRouteModel


class CompilerFrontendTests(unittest.TestCase):
    def run_command(self, *command: str) -> None:
        completed = subprocess.run(
            command, cwd=ROOT, text=True, capture_output=True, check=False,
        )
        self.assertEqual(
            completed.returncode, 0,
            f"command failed: {' '.join(command)}\n{completed.stdout}\n{completed.stderr}",
        )

    def test_contract_v2_enforces_ownership_provenance_and_extensions(self) -> None:
        file_id = stable_id("frontend", "typescript-compiler-api", "file", "/app.ts")
        function_id = stable_id(
            "frontend", "typescript-compiler-api", "function", "/app.ts", 0, 25,
        )
        snapshot = FrontendSnapshot(
            frontend_id="typescript-compiler-api",
            contract_version=2,
            languages=("typescript", "javascript"),
            capabilities={"syntax": "complete"},
            manifest={"node_count": 2, "edge_count": 1},
            nodes=[
                {
                    "id": file_id, "kind": "file", "label": "app.ts", "tier": "T0",
                    "properties": {
                        "fact_origin": "compiler", "confidence": "exact", "evidence_ids": [],
                    },
                },
                {
                    "id": function_id, "kind": "function", "label": "run", "tier": "T1",
                    "properties": {
                        "fact_origin": "compiler", "confidence": "exact", "evidence_ids": [],
                        "frontend_id": "typescript-compiler-api", "language": "typescript",
                        "absolute_file": "/app.ts", "content_hash": "abc",
                        "start_offset": 0, "end_offset": 25,
                        "start_line": 1, "start_column": 1,
                        "end_line": 1, "end_column": 26,
                        "compiler_node_id": "typescript:0:25",
                        "frontend_extensions": {
                            "typescript": {"type_parameters": ["T"]},
                        },
                    },
                },
            ],
            edges=[{
                "kind": "DECLARES", "source": file_id, "target": function_id,
                "properties": {
                    "fact_origin": "compiler", "confidence": "exact", "evidence_ids": [],
                },
            }],
        )
        validate_snapshot(snapshot)
        del snapshot.nodes[1]["properties"]["compiler_node_id"]
        with self.assertRaisesRegex(ContractError, "compiler_node_id"):
            validate_snapshot(snapshot)

    def test_core_has_no_frontend_ecosystem_or_compatibility_imports(self) -> None:
        self.assertEqual([], import_boundary_violations(ROOT / "Arachne"))

    def test_ecosystem_models_register_without_core_changes(self) -> None:
        class RouteModel:
            model_id = "test-routes"
            supported_languages = ("typescript", "javascript")
            required_capabilities = ("calls",)

            def applies(self, graph, package_inventory):
                return "tiny-web" in package_inventory

            def enrich(self, graph):
                raise AssertionError("selection must not execute enrichment")

        registry = EcosystemRegistry()
        registry.register(RouteModel())
        selected = registry.applicable(
            {"nodes": [], "edges": []}, {"tiny-web"}, {"typescript"},
            {"calls": "complete"},
        )
        self.assertEqual(("test-routes",), tuple(model.model_id for model in selected))

    def test_typescript_contextual_tokens_and_library_provenance(self) -> None:
        with tempfile.TemporaryDirectory() as output:
            self.run_command(
                "node", "Arachne/frontends/typescript/build_graph.mjs", "src", output,
            )
            snapshot = load_snapshot(output)
            validate_snapshot(snapshot)
            self.assertEqual(2, snapshot.contract_version)
            self.assertTrue(all(
                node["id"].startswith("v2:frontend:typescript-compiler-api:")
                for node in snapshot.nodes
            ))
            self.assertTrue(all(
                node["properties"].get("legacy_id")
                for node in snapshot.nodes
            ))
            self.assertEqual("complete", snapshot.capability("scopes"))
            self.assertTrue(any(node["kind"] == "scope" for node in snapshot.nodes))
            self.assertTrue(any(node["kind"] == "symbol" for node in snapshot.nodes))
            regex_tokens = [
                node for node in snapshot.nodes
                if node["kind"] == "token"
                and node["properties"].get("token_kind") == "RegularExpressionLiteral"
                and "```" in node["label"]
            ]
            self.assertTrue(regex_tokens, "backtick-bearing regex must remain one regex token")
            functions = {
                node["label"]: node for node in snapshot.nodes
                if node["kind"] == "function"
                and node["properties"].get("file") == "regress/backtick-in-regex.ts"
            }
            self.assertEqual({"strip", "after"}, set(functions))
            self.assertEqual(18, functions["strip"]["properties"]["end_line"])
            self.assertEqual(20, functions["after"]["properties"]["start_line"])
            dependency_files = [
                node for node in snapshot.nodes
                if node["kind"] == "file"
                and node["properties"].get("provenance") in {"dependency", "standard-library"}
            ]
            self.assertTrue(dependency_files)
            self.assertTrue(any(
                node["properties"]["absolute_file"].endswith("lib.dom.d.ts")
                for node in dependency_files
            ))
            self.assertTrue(any(edge["kind"] == "PACKAGE_CONTAINS" for edge in snapshot.edges))

    def test_typescript_reachable_framework_runtime_sources(self) -> None:
        with tempfile.TemporaryDirectory() as output:
            self.run_command(
                "node", "Arachne/frontends/typescript/build_graph.mjs",
                "Arachne/frontends/typescript/fixtures/framework", output,
            )
            snapshot = load_snapshot(output)
            validate_snapshot(snapshot)
            self.assertEqual(2, snapshot.contract_version)
            self.assertFalse(snapshot.legacy_contract)
            self.assertEqual(1, snapshot.manifest["root_file_count"])
            self.assertEqual(1, snapshot.manifest["runtime_dependency_file_count"])
            runtime_file = next(
                node for node in snapshot.nodes
                if node["kind"] == "file"
                and node["properties"].get("absolute_file", "").endswith(
                    "node_modules/tiny-web/index.js"
                )
            )
            self.assertEqual("dependency", runtime_file["properties"]["provenance"])
            runtime_functions = {
                node["label"]: node
                for node in snapshot.nodes
                if node["tier"] == "T1"
                and node["properties"].get("absolute_file", "").endswith(
                    "node_modules/tiny-web/index.js"
                )
            }
            self.assertTrue({"createRouter", "get", "dispatch"}.issubset(runtime_functions))
            self.assertTrue(any(
                edge["kind"] == "RUNTIME_DEPENDS_ON"
                and edge["target"] == runtime_file["id"]
                for edge in snapshot.edges
            ))
            self.assertTrue(any(
                edge["kind"] == "IMPLEMENTED_BY"
                and edge["target"] == runtime_functions["createRouter"]["id"]
                for edge in snapshot.edges
            ))
            app_calls = [
                node for node in snapshot.nodes
                if node["kind"] == "call"
                and node["properties"].get("file") == "app.ts"
            ]
            create_call = next(node for node in app_calls if node["label"] == "createRouter()")
            self.assertIn(
                runtime_functions["createRouter"]["id"],
                create_call["properties"]["runtime_target_ids"],
            )
            self.assertTrue(any(
                edge["kind"] == "MAY_INVOKE"
                and edge["source"] == create_call["id"]
                and edge["target"] == runtime_functions["createRouter"]["id"]
                for edge in snapshot.edges
            ))
            canonical = {"nodes": snapshot.nodes, "edges": snapshot.edges}
            model_registry = EcosystemRegistry()
            model_registry.register(GenericRouteModel())
            modeled = model_registry.enrich(
                canonical,
                GraphIndex(canonical).package_inventory(),
                snapshot.languages,
                snapshot.capabilities,
            )
            modeled_route = next(
                node for node in modeled["nodes"]
                if node["kind"] == "route" and node["properties"].get("path") == "/documents"
            )
            modeled_handler = next(
                node for node in modeled["nodes"]
                if node["kind"] == "function" and node["label"] == "documentHandler"
            )
            self.assertTrue(any(
                edge["kind"] == "ROUTE_HANDLED_BY"
                and edge["source"] == modeled_route["id"]
                and edge["target"] == modeled_handler["id"]
                for edge in modeled["edges"]
            ))
            route_source = next(
                node for node in modeled["nodes"]
                if node["kind"] == "source"
                and node["properties"].get("route_id") == modeled_route["id"]
            )
            self.assertEqual("route-handler-parameter", route_source["properties"]["source_kind"])
            self.assertTrue(any(
                edge["kind"] == "TAINT_SOURCE"
                and edge["source"] == route_source["id"]
                for edge in modeled["edges"]
            ))
            files, composed, _ = analyze_typescript_with_compiler(
                str(ROOT / "Arachne" / "frontends" / "typescript" / "fixtures" / "framework"),
            )
            handler = next(
                function for info in files for function in info["functions"]
                if function["name"] == "documentHandler"
            )
            route = next(
                boundary for info in files for boundary in info["wiring_boundaries"]
                if boundary["kind"] == "route" and boundary["key"] == "/documents"
            )
            self.assertEqual(handler["id"], route["target_function_id"])
            self.assertTrue(any(
                node["id"] == runtime_functions["get"]["id"]
                for node in composed["nodes"]
            ))

    def test_typescript_compiler_emits_structured_type_and_receiver_facts(self) -> None:
        with tempfile.TemporaryDirectory() as output:
            self.run_command(
                "node", "Arachne/frontends/typescript/build_graph.mjs",
                "Arachne/frontends/typescript/fixtures/semantics", output,
            )
            snapshot = load_snapshot(output)
            validate_snapshot(snapshot)
            self.assertEqual("none", snapshot.capability("security_roles"))
            self.assertFalse(any(
                node.get("properties", {}).get("roles") for node in snapshot.nodes
            ))
            entities = {
                (node["kind"], node["label"]): node for node in snapshot.nodes
                if node["kind"] in {"class", "interface", "function"}
            }
            runner = entities[("interface", "Runner")]
            identity = entities[("function", "identity")]
            string_runner = entities[("class", "StringRunner")]
            self.assertEqual(
                "T",
                runner["properties"]["frontend_extensions"]["typescript"]
                ["type_parameters"][0]["name"],
            )
            self.assertEqual(
                "T",
                identity["properties"]["frontend_extensions"]["typescript"]
                ["type_parameters"][0]["name"],
            )
            self.assertIn(
                "implements",
                {
                    item["relationship"]
                    for item in string_runner["properties"]["frontend_extensions"]
                    ["typescript"]["heritage"]
                },
            )
            calls = [node for node in snapshot.nodes if node["kind"] == "call"]
            method_call = next(node for node in calls if node["label"].startswith("runner.run"))
            self.assertEqual(
                "Runner<string>", method_call["properties"]["receiver_type_facts"]["text"],
            )
            generic_call = next(node for node in calls if node["label"] == "identity(value)")
            self.assertEqual(
                "string",
                generic_call["properties"]["frontend_extensions"]["typescript"]
                ["return_type"],
            )
            predicate_call = next(node for node in calls if node["label"] == "isString(value)")
            self.assertEqual(
                "string",
                predicate_call["properties"]["frontend_extensions"]["typescript"]
                ["type_predicate"]["type"],
            )
            narrowed = next(
                node for node in snapshot.nodes
                if node["kind"] == "identifier" and node["label"] == "value"
                and node["properties"].get("declared_type_facts", {}).get("text")
                    == "string | number"
                and node["properties"].get("type_facts", {}).get("text") == "string"
            )
            self.assertEqual(
                "string | number", narrowed["properties"]["declared_type_facts"]["text"],
            )
            self.assertEqual("string", narrowed["properties"]["type_facts"]["text"])

            type_parameters = [
                node for node in snapshot.nodes if node["kind"] == "type-parameter"
            ]
            self.assertTrue(any(
                node["label"] == "T"
                and snapshot.nodes_by_id[node["properties"]["owner_id"]]["label"]
                    == "identity"
                for node in type_parameters
            ))
            self.assertEqual(
                len(type_parameters),
                sum(edge["kind"] == "HAS_TYPE_PARAMETER" for edge in snapshot.edges),
            )
            refinements = [
                node for node in snapshot.nodes if node["kind"] == "type-refinement"
            ]
            self.assertTrue(any(
                node["properties"]["refinement_kind"] == "type-predicate"
                and node["properties"]["narrowed_type"] == "string"
                for node in refinements
            ))
            self.assertTrue(any(
                node["properties"]["refinement_kind"] == "discriminant"
                and node["properties"]["property_path"] == "kind"
                and node["properties"]["compared_value"] == "text"
                for node in refinements
            ))
            substitutions = [
                node for node in snapshot.nodes
                if node["kind"] == "generic-substitution"
            ]
            self.assertTrue(any(
                node["properties"]["bindings"].get("T") == "string"
                and snapshot.nodes_by_id[node["properties"]["function_id"]]["label"]
                    == "identity"
                for node in substitutions
            ))
            self.assertEqual(
                2, sum(edge["kind"] == "OVERLOAD_OF" for edge in snapshot.edges),
            )
            self.assertTrue(any(
                edge["kind"] == "STRUCTURALLY_COMPATIBLE_WITH"
                for edge in snapshot.edges
            ))

            compatibility = snapshot_file_infos(snapshot)
            self.assertTrue(any(
                refinement.get("compiler_node_id")
                for info in compatibility for refinement in info["type_refinements"]
            ))
            self.assertFalse((ROOT / "Arachne" / "type_system_analysis.py").exists())

    def test_typescript_compiler_emits_dispatch_mutation_and_runtime_facts(self) -> None:
        with tempfile.TemporaryDirectory() as output:
            self.run_command(
                "node", "Arachne/frontends/typescript/build_graph.mjs",
                "Arachne/frontends/typescript/fixtures/semantics", output,
            )
            snapshot = load_snapshot(output)
            validate_snapshot(snapshot)
            nodes = snapshot.nodes_by_id
            decorator = next(
                node for node in snapshot.nodes
                if node["kind"] == "decorator" and node["label"] == "Controller"
            )
            self.assertEqual("/runner", decorator["properties"]["arguments"][0]["value"])
            self.assertEqual(1, sum(edge["kind"] == "OVERRIDES" for edge in snapshot.edges))
            self.assertEqual(
                1, sum(edge["kind"] == "IMPLEMENTS_MEMBER" for edge in snapshot.edges),
            )
            function_values = [
                edge for edge in snapshot.edges if edge["kind"] == "FUNCTION_VALUE"
            ]
            self.assertTrue(any(
                nodes[edge["source"]]["label"] == "isString"
                and nodes[edge["target"]]["label"] == "callbacks.check"
                for edge in function_values
            ))
            self.assertTrue(any(
                edge["kind"] == "PASSES_CALLBACK" for edge in snapshot.edges
            ))
            computed_call = next(
                node for node in snapshot.nodes
                if node["kind"] == "call" and node["label"].startswith("callbacks[action]")
            )
            self.assertEqual("isString", nodes[computed_call["properties"]["primary_target_id"]]["label"])
            self.assertTrue(all(
                nodes[edge["target"]]["tier"] == "T1"
                for edge in snapshot.edges
                if edge["kind"] in {"INVOKES", "MAY_INVOKE"}
                and edge["source"] == computed_call["id"]
            ))
            behavior_kinds = {
                node["properties"]["behavior_kind"]
                for node in snapshot.nodes if node["kind"] == "dynamic-behavior"
            }
            self.assertTrue({
                "dynamic-import", "reflection", "proxy", "computed-property-read",
            }.issubset(behavior_kinds))
            self.assertGreaterEqual(sum(
                node["kind"] == "module-initializer" for node in snapshot.nodes
            ), 4)
            self.assertEqual(2, sum(
                node["kind"] == "static-initializer" for node in snapshot.nodes
            ))
            self.assertTrue(any(
                node["kind"] == "allocation"
                and node["properties"].get("allocated_type") == "Map<string, string>"
                and node["properties"].get("module_singleton")
                for node in snapshot.nodes
            ))
            self.assertTrue(any(
                node["kind"] == "write" and node["label"] == "mutableState"
                and node["properties"].get("write_kind") == "assignment"
                for node in snapshot.nodes
            ))

    def test_c_header_declarations_and_calls(self) -> None:
        with tempfile.TemporaryDirectory() as output:
            self.run_command(
                sys.executable, "Arachne/frontends/c/build_graph.py",
                "Arachne/frontends/c/fixtures", output,
            )
            snapshot = load_snapshot(output)
            validate_snapshot(snapshot)
            self.assertEqual(2, snapshot.contract_version)
            self.assertFalse(snapshot.legacy_contract)
            self.assertTrue(all(
                node["id"].startswith("v2:frontend:clang-c:")
                for node in snapshot.nodes
            ))
            functions = {
                node["label"]: node for node in snapshot.nodes
                if node["kind"] == "function"
            }
            self.assertIn("route_register", functions)
            self.assertIn("configure_application", functions)
            calls = [node for node in snapshot.nodes if node["kind"] == "call"]
            route_call = next(node for node in calls if node["properties"].get("callee") == "route_register")
            self.assertEqual("exact", route_call["properties"]["resolution"])
            self.assertEqual(functions["route_register"]["id"], route_call["properties"]["primary_target_id"])
            pointer_call = next(node for node in calls if "handler" in node["label"])
            self.assertEqual("function-pointer", pointer_call["properties"]["resolution"])
            self.assertEqual(2, sum(
                edge["kind"] == "ARGUMENT_BINDS_PARAMETER"
                for edge in snapshot.edges
            ))
            self.assertTrue(any(
                edge["kind"] == "WRITES_PARAMETER_PROPERTY"
                for edge in snapshot.edges
            ))

    def test_canonical_module_initialization_overlay(self) -> None:
        semantics, _ = run_project_frontends(
            str(ROOT / "Arachne" / "frontends" / "typescript" / "fixtures" / "semantics")
        )
        core_singletons = [
            node for node in semantics["nodes"]
            if node["kind"] == "singleton"
            and node["id"].startswith("v2:core:module-initialization:")
        ]
        self.assertEqual(
            {"callbacks", "proxied", "singleton"},
            {node["label"] for node in core_singletons},
        )
        core_state = [
            node for node in semantics["nodes"]
            if node["kind"] == "module-state"
            and node["id"].startswith("v2:core:module-initialization:")
        ]
        self.assertIn("mutableState", {node["label"] for node in core_state})
        self.assertTrue(all(
            node["properties"]["fact_origin"] == "core-inference"
            and node["properties"]["evidence_ids"]
            for node in [*core_singletons, *core_state]
        ))

        cycle_graph, _ = run_project_frontends(
            str(ROOT / "Arachne" / "frontends" / "typescript" / "fixtures" / "module_cycle")
        )
        cycle = next(
            node for node in cycle_graph["nodes"]
            if node["kind"] == "import-cycle"
            and node["id"].startswith("v2:core:module-initialization:")
        )
        self.assertEqual(2, cycle["properties"]["size"])
        self.assertEqual(2, sum(
            edge["kind"] == "PARTICIPATES_IN_IMPORT_CYCLE"
            and edge["target"] == cycle["id"]
            for edge in cycle_graph["edges"]
        ))

    def test_canonical_control_flow_overlay(self) -> None:
        graph, _ = run_project_frontends(
            str(ROOT / "Arachne" / "frontends" / "typescript" / "fixtures" / "control_flow")
        )
        function = next(
            node for node in graph["nodes"]
            if node["kind"] == "function" and node["label"] == "controlFlow"
        )
        owned = {
            node["id"]: node for node in graph["nodes"]
            if node.get("properties", {}).get("function_id") == function["id"]
        }
        self.assertEqual(1, sum(node["kind"] == "cfg-entry" for node in owned.values()))
        self.assertEqual(1, sum(node["kind"] == "cfg-exit" for node in owned.values()))
        self.assertGreaterEqual(sum(node["kind"] == "cfg-condition" for node in owned.values()), 5)
        self.assertGreaterEqual(sum(node["kind"] == "cfg-merge" for node in owned.values()), 5)
        edge_kinds = {
            edge["kind"] for edge in graph["edges"]
            if edge["source"] in owned or edge["target"] in owned
        }
        self.assertTrue({
            "CFG_NEXT", "TRUE_BRANCH", "FALSE_BRANCH", "LOOP_BACK",
            "SWITCH_CASE", "MERGES_AT",
        }.issubset(edge_kinds))
        unreachable = [
            node for node in owned.values() if node["kind"] == "unreachable-region"
        ]
        self.assertEqual(1, len(unreachable))
        body = next(
            node for node in graph["nodes"]
            if node["id"] == unreachable[0]["properties"]["body_id"]
        )
        self.assertEqual("total = 999;", body["label"])

    def test_mixed_language_registry_composes_one_graph(self) -> None:
        with tempfile.TemporaryDirectory() as output:
            with patch(
                "Arachne.compiler_adapter.snapshot_file_infos",
                side_effect=AssertionError("primary project graph used FileInfo"),
            ):
                graph, snapshots = run_project_frontends(str(ROOT), output)
            self.assertEqual({"typescript-compiler-api", "clang-c"}, {
                snapshot.frontend_id for snapshot in snapshots
            })
            frontend_ids = {
                node["properties"].get("frontend_id") for node in graph["nodes"]
            }
            self.assertTrue({"typescript-compiler-api", "clang-c"}.issubset(frontend_ids))
            self.assertTrue(all(
                node["id"].startswith("v2:") for node in graph["nodes"]
            ))
            self.assertTrue(any(
                node["kind"] == "taint-reach"
                and node["id"].startswith("v2:core:taint-propagation:")
                for node in graph["nodes"]
            ))
            self.assertTrue(any(
                node["kind"] == "source"
                and node["id"].startswith(("v2:runtime-model:", "v2:framework-model:"))
                for node in graph["nodes"]
            ))
            self.assertTrue(any(node["kind"] == "route" for node in graph["nodes"]))
            self.assertTrue(any(
                edge["kind"] == "ROUTE_HANDLED_BY" for edge in graph["edges"]
            ))
            self.assertTrue(any(
                node["kind"] == "call"
                and node["properties"].get("frontend_id") == "clang-c"
                for node in graph["nodes"]
            ))
            c_pointer_call = next(
                node for node in graph["nodes"]
                if node["kind"] == "call"
                and node["properties"].get("frontend_id") == "clang-c"
                and "handler" in node["label"]
            )
            self.assertEqual(
                "function-pointer",
                c_pointer_call["properties"]["resolution"],
            )
            self.assertTrue(any(
                edge["kind"] == "MAY_INVOKE"
                and edge["source"] == c_pointer_call["id"]
                and edge["properties"].get("resolution")
                    == "interprocedural-property-effect"
                for edge in graph["edges"]
            ))
            core_contexts = [
                node for node in graph["nodes"] if node["kind"] == "call-context"
                and node["id"].startswith("v2:core:interprocedural-contexts:")
            ]
            self.assertTrue(core_contexts)
            self.assertTrue(all(
                node["properties"]["fact_origin"] == "core-inference"
                and node["properties"]["evidence_ids"]
                for node in core_contexts
            ))
            core_locations = [
                node for node in graph["nodes"] if node["kind"] == "heap-location"
                and node["id"].startswith("v2:core:parameter-property-effects:")
            ]
            self.assertTrue(core_locations)
            self.assertTrue(all(
                node["properties"]["fact_origin"] == "core-inference"
                and node["properties"]["evidence_ids"]
                for node in core_locations
            ))

    def test_typescript_compiler_facts_feed_semantic_overlays(self) -> None:
        with tempfile.TemporaryDirectory() as output:
            files, graph, snapshot = analyze_typescript_with_compiler(
                str(ROOT / "src"), output,
            )
            self.assertEqual("typescript-compiler-api", snapshot.frontend_id)
            totals = {
                field: sum(len(info[field]) for info in files)
                for field in (
                    "functions", "function_calls", "scopes", "symbols",
                    "properties", "definitions", "reads", "arguments", "returns",
                    "statements", "expressions", "operations", "cfg_nodes",
                    "taint_sources", "taint_flows", "taint_reaches", "tainted_calls", "effect_summaries",
                    "dynamic_behaviors", "wiring_boundaries",
                )
            }
            self.assertEqual(22, totals["functions"])
            self.assertEqual(74, totals["function_calls"])
            self.assertEqual(82, totals["scopes"])
            self.assertEqual(154, totals["symbols"])
            self.assertEqual(72, totals["properties"])
            self.assertEqual(222, totals["definitions"])
            self.assertEqual(198, totals["reads"])
            self.assertEqual(81, totals["arguments"])
            self.assertEqual(38, totals["returns"])
            self.assertEqual(159, totals["statements"])
            self.assertEqual(1118, totals["expressions"])
            self.assertEqual(326, totals["operations"])
            self.assertEqual(81, totals["cfg_nodes"])
            self.assertEqual(24, totals["taint_sources"])
            self.assertEqual(1188, totals["taint_flows"])
            self.assertEqual(709, totals["taint_reaches"])
            self.assertEqual(93, totals["tainted_calls"])
            self.assertEqual(5, totals["wiring_boundaries"])
            self.assertEqual(387, sum(len(info["cfg_edges"]) for info in files))
            self.assertEqual(0, sum(len(info["unreachable"]) for info in files))
            self.assertTrue(all(
                function.get("scope_id")
                for info in files for function in info["functions"]
            ))
            self.assertTrue(all(
                call.get("scope_id")
                for info in files for call in info["function_calls"]
            ))
            for field in (
                "scopes", "symbols", "cfg_nodes", "taint_flows",
                "effect_summaries", "dynamic_behaviors", "wiring_boundaries",
            ):
                self.assertGreater(totals[field], 0, field)
            self.assertTrue(any(
                node["properties"].get("frontend_id") == "typescript-compiler-api"
                for node in graph["nodes"]
            ))
            self.assertTrue(all(
                expression.get("compiler_node_id")
                for info in files for expression in info["expressions"]
            ))
            self.assertTrue(any(
                edge["kind"] == "COMPILER_BODY_VIEW_OF"
                for edge in graph["edges"]
            ))
            graph_nodes = {node["id"]: node for node in graph["nodes"]}
            canonical_reaches = [
                node for node in graph["nodes"]
                if node["kind"] == "taint-reach"
                and node["id"].startswith("v2:core:taint-propagation:")
            ]
            self.assertTrue(any(
                node["kind"] == "source"
                and node["id"].startswith("v2:runtime-model:generic-security-roles:")
                for node in graph["nodes"]
            ))
            self.assertTrue(any(
                node["kind"] == "sink"
                and node["id"].startswith("v2:runtime-model:generic-security-roles:")
                for node in graph["nodes"]
            ))
            reach_pairs = {
                (
                    graph_nodes[node["properties"]["source_value_id"]]["label"],
                    graph_nodes[node["properties"]["sink_value_id"]]["label"],
                )
                for node in canonical_reaches
            }
            self.assertIn(
                ("documentId", "findById(documentId)"), reach_pairs,
            )
            self.assertIn(
                ("invoiceId", "findById(invoiceId)"), reach_pairs,
            )
            self.assertNotIn(
                ("documentId", "findById(invoiceId)"), reach_pairs,
            )
            self.assertNotIn(
                ("invoiceId", "findById(documentId)"), reach_pairs,
            )
            request_to_document = next(
                node for node in canonical_reaches
                if graph_nodes[node["properties"]["source_value_id"]]["label"] == "req"
                and graph_nodes[node["properties"]["sink_value_id"]]["label"]
                    == "findById(documentId)"
            )
            self.assertIn(
                "req.body.id",
                {
                    graph_nodes[node_id]["label"]
                    for node_id in request_to_document["properties"]["witness_ids"]
                },
            )
            self.assertGreater(
                max(map(len, request_to_document["properties"]["context_trace"])), 0,
            )
            self.assertFalse((ROOT / "Arachne" / "variable_analysis.py").exists())
            self.assertFalse((ROOT / "Arachne" / "scope_utils.py").exists())
            self.assertFalse((ROOT / "Arachne" / "dynamic_analysis.py").exists())
            self.assertTrue(all(
                behavior.get("compiler_node_id")
                for info in files for behavior in info["dynamic_behaviors"]
            ))
            request_id = next(
                source for info in files for source in info["taint_sources"]
                if source["label"] == "req.body.id"
            )
            document_sink = next(
                tainted for info in files for tainted in info["tainted_calls"]
                if tainted["source_id"] == request_id["id"]
                and tainted["callee"] == "findById"
            )
            witness = taint_path(files, request_id["id"], document_sink["call_id"])
            self.assertEqual(request_id["id"], witness[0])
            self.assertEqual(document_sink["call_id"], witness[-1])
            self.assertGreaterEqual(len(witness), 8)
            direct = sum(len(info["taint_flows"]) for info in files)
            closure = [
                reach for info in files for reach in info["taint_reaches"]
            ]
            self.assertLess(len(closure), direct)
            self.assertGreater(
                max(item.get("context_variant_count", 0) for item in closure), 1,
            )
            tainted = next(
                item for info in files for item in info["tainted_calls"]
            )
            witness = taint_path(files, tainted["source_id"], tainted["call_id"])
            self.assertEqual(tainted["source_id"], witness[0])
            self.assertEqual(tainted["call_id"], witness[-1])

    def test_legacy_file_api_is_compiler_backed(self) -> None:
        paths = walk(str(ROOT / "src"))
        files = analyze_files(paths)
        principal = read_file(str(ROOT / "src" / "auth" / "principal.ts"))
        self.assertEqual(14, len(files))
        self.assertEqual(22, sum(len(info["functions"]) for info in files))
        self.assertEqual(74, sum(len(info["function_calls"]) for info in files))
        self.assertEqual(
            {"decodeSession", "resolvePrincipal", "principalKey"},
            {function["name"] for function in principal["functions"]},
        )


if __name__ == "__main__":
    unittest.main()
