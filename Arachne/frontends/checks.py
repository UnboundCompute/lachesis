"""Executable checks for every registered compiler frontend."""
from __future__ import annotations

import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from Arachne import analyze_files, read_file, walk
from Arachne.compiler_adapter import (
    analyze_typescript_with_compiler, run_project_frontends,
)
from Arachne.taint_analysis import taint_path
from Arachne.core.snapshot import load_snapshot
from Arachne.core.validation import validate_snapshot
from Arachne.core.contract import ContractError, FrontendSnapshot
from Arachne.core.boundaries import import_boundary_violations
from Arachne.core.identities import stable_id
from Arachne.ecosystems import EcosystemRegistry


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

    def test_c_header_declarations_and_calls(self) -> None:
        with tempfile.TemporaryDirectory() as output:
            self.run_command(
                sys.executable, "Arachne/frontends/c/build_graph.py",
                "Arachne/frontends/c/fixtures", output,
            )
            snapshot = load_snapshot(output)
            validate_snapshot(snapshot)
            self.assertEqual(1, snapshot.contract_version)
            self.assertTrue(snapshot.legacy_contract)
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

    def test_mixed_language_registry_composes_one_graph(self) -> None:
        with tempfile.TemporaryDirectory() as output:
            graph, snapshots = run_project_frontends(str(ROOT), output)
            self.assertEqual({"typescript-compiler-api", "clang-c"}, {
                snapshot.frontend_id for snapshot in snapshots
            })
            frontend_ids = {
                node["properties"].get("frontend_id") for node in graph["nodes"]
            }
            self.assertTrue({"typescript-compiler-api", "clang-c"}.issubset(frontend_ids))
            self.assertTrue(any(node["kind"] == "tainted-call" for node in graph["nodes"]))
            self.assertTrue(any(node["kind"] == "wiring-boundary" for node in graph["nodes"]))
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
                "effect-resolved-function-pointer",
                c_pointer_call["properties"]["resolution"],
            )
            self.assertTrue(any(
                edge["kind"] == "MAY_INVOKE"
                and edge["source"] == c_pointer_call["id"]
                for edge in graph["edges"]
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
            self.assertEqual(1121, totals["expressions"])
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
            self.assertFalse((ROOT / "Arachne" / "variable_analysis.py").exists())
            self.assertFalse((ROOT / "Arachne" / "scope_utils.py").exists())
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
