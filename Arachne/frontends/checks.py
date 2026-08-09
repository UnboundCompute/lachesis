"""Executable checks for every registered compiler frontend."""
from __future__ import annotations

import asyncio
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from Arachne.compatibility.file_view import analyze_files, read_file, walk
from Arachne.compatibility.projector import (
    compatibility_taint_path as taint_path, graph_file_infos,
)
from Arachne.pipeline import run_project, semantic_snapshot_graph, snapshot_graph
from Arachne.projections import build_layered_graph
from Arachne.reasoning import InvestigationAgent, ReasoningQuery
from Arachne.reasoning.agent import ACTION_SCHEMA, AgentRequest
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
        snapshot.contract_version = 1
        with self.assertRaisesRegex(ContractError, "required version is 2"):
            validate_snapshot(snapshot)
        snapshot.contract_version = 2
        del snapshot.nodes[1]["properties"]["compiler_node_id"]
        with self.assertRaisesRegex(ContractError, "compiler_node_id"):
            validate_snapshot(snapshot)

    def test_core_has_no_frontend_ecosystem_or_compatibility_imports(self) -> None:
        self.assertEqual([], import_boundary_violations(ROOT / "Arachne"))

    def test_parser_migration_has_one_compiler_native_path(self) -> None:
        removed = {
            "source_analysis.py", "compiler_body_adapter.py",
            "compiler_value_adapter.py", "data_flow.py", "receiver_analysis.py",
            "operation_analysis.py", "context_analysis.py", "heap_analysis.py",
            "control_flow.py", "branch_analysis.py", "taint_analysis.py",
            "runtime_models.py", "async_analysis.py", "effect_analysis.py",
            "dispatch_analysis.py", "exception_analysis.py",
            "module_init_analysis.py", "wiring_analysis.py", "graph.py",
        }
        self.assertEqual([], sorted(
            str(path.relative_to(ROOT))
            for path in (ROOT / "Arachne").rglob("*.py")
            if path.name in removed and path.parent.name != "overlays"
        ))
        c_frontend = (
            ROOT / "Arachne" / "frontends" / "c" / "build_graph.py"
        ).read_text(encoding="utf-8")
        typescript_frontend = (
            ROOT / "Arachne" / "frontends" / "typescript" / "build_graph.mjs"
        ).read_text(encoding="utf-8")
        self.assertNotIn("import re", c_frontend)
        self.assertNotIn("TOKEN_RE", c_frontend)
        self.assertNotIn("legacy_id", c_frontend)
        self.assertNotIn("legacy_id", typescript_frontend)

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

    def test_cli_canonical_views_end_to_end(self) -> None:
        with tempfile.TemporaryDirectory() as output:
            graph_path = Path(output) / "canonical.json"
            layered_path = Path(output) / "layered"
            self.run_command(
                sys.executable, "read_files.py", "src", "--taint",
                "--graph-json", str(graph_path),
                "--layered-out", str(layered_path),
            )
            self.assertTrue(graph_path.is_file())
            self.assertTrue((layered_path / "manifest.json").is_file())
            self.assertTrue((layered_path / "node_index.json").is_file())
            overview = subprocess.run(
                [
                    sys.executable, "Arachne/cli/query.py", str(graph_path),
                    "overview",
                ],
                cwd=ROOT, text=True, capture_output=True, check=False,
            )
            self.assertEqual(0, overview.returncode, overview.stderr)
            overview_payload = json.loads(overview.stdout)
            self.assertEqual(2, overview_payload["manifest"]["schema_version"])
            project = overview_payload["manifest"]["project"]
            frontend_capabilities = project["frontend_capabilities"]
            self.assertTrue(frontend_capabilities["typescript-compiler-api"])
            effective = project["capabilities"]
            for capability in ("heap_identity", "effects", "taint_policy"):
                self.assertEqual("partial", effective[capability])
            self.assertEqual(
                "none",
                frontend_capabilities["typescript-compiler-api"]["heap_identity"],
            )
            function = subprocess.run(
                [
                    sys.executable, "Arachne/cli/query.py", str(graph_path),
                    "--budget-tokens", "1000", "function", "getDocument",
                    "--file", "document-service.ts",
                ],
                cwd=ROOT, text=True, capture_output=True, check=False,
            )
            self.assertEqual(0, function.returncode, function.stderr)
            function_payload = json.loads(function.stdout)
            self.assertEqual("getDocument", function_payload["focus"]["label"])
            self.assertLessEqual(function_payload["budget"]["estimated_tokens"], 1000)
            self.assertNotIn(
                "FileInfo",
                (ROOT / "Arachne" / "cli" / "query.py").read_text(encoding="utf-8"),
            )

    def test_layered_v2_exposes_cross_tier_navigation(self) -> None:
        graph, _ = run_project(str(ROOT / "src"))
        layered = build_layered_graph(graph)
        manifest = layered["manifest"]
        self.assertEqual(2, manifest["schema_version"])
        self.assertEqual(len(graph["nodes"]), len(layered["node_index"]))
        self.assertEqual(
            manifest["integrity"]["cross_tier_canonical_edges"],
            manifest["integrity"]["cross_tier_exposed_edges"],
        )
        exposed_cross_tier = [
            edge for payload in layered["tiers"].values()
            for collection in ("expands_to", "links")
            for edge in payload[collection]
            if not edge.get("derived")
        ]
        self.assertEqual(
            len(exposed_cross_tier),
            len({edge["id"] for edge in exposed_cross_tier}),
        )
        tiers = {item["tier"]: item for item in manifest["tiers"]}
        self.assertTrue(all(tiers[tier]["expands_to_count"] for tier in ("T0", "T1", "T2")))
        relationships = {
            tier: {edge.get("relationship") for edge in layered["tiers"][tier]["expands_to"]}
            for tier in ("T0", "T1", "T2", "T3")
        }
        self.assertIn("DECLARES", relationships["T0"])
        self.assertIn("CONTAINS_BODY", relationships["T1"])
        self.assertIn("PATH_STEP", relationships["T2"])
        self.assertIn("EVIDENCED_BY", relationships["T3"])
        self.assertTrue(any(
            edge["kind"] == "DEPENDS_ON_SUMMARY"
            for edge in layered["tiers"]["T0"]["edges"]
        ))

        document_file = next(
            node for node in layered["tiers"]["T0"]["nodes"]
            if node["kind"] == "file"
            and node["location"]["file"].endswith("resources/document-service.ts")
        )
        document_function_id = next(
            edge["target"] for edge in layered["tiers"]["T0"]["expands_to"]
            if edge["source"] == document_file["id"]
            and edge["relationship"] == "DECLARES"
            and layered["node_index"][edge["target"]]["label"] == "getDocument"
        )
        body_id = next(
            edge["target"] for edge in layered["tiers"]["T1"]["expands_to"]
            if edge["source"] == document_function_id
            and edge["relationship"] == "CONTAINS_BODY"
        )
        self.assertTrue(any(
            edge["source"] == body_id and edge["relationship"] == "EVIDENCED_BY"
            for edge in layered["tiers"]["T3"]["expands_to"]
        ))
        paths = [node for node in layered["tiers"]["T2"]["nodes"] if node["kind"] == "taint-reach"]
        self.assertTrue(paths)
        self.assertTrue(all(node["details"]["steps"] for node in paths))
        self.assertTrue(any(
            "req.body.id" in step.get("label", "")
            for node in paths for step in node["details"]["steps"]
        ))

    def test_reasoning_queries_are_typed_contextual_and_budgeted(self) -> None:
        graph, _ = run_project(str(ROOT / "src"))
        query = ReasoningQuery(graph)
        manifest = query.overview()["manifest"]
        self.assertEqual(2, manifest["schema_version"])
        for capability in ("heap_identity", "effects", "taint_policy"):
            self.assertEqual("partial", manifest["project"]["capabilities"][capability])
        self.assertEqual("ambiguous", query.find_entity("getDocument")["status"])
        document_match = query.find_entity("getDocument", kind="function")
        invoice_match = query.find_entity("getInvoice", kind="function")
        self.assertEqual("exact", document_match["status"])
        document_id = document_match["matches"][0]["id"]
        invoice_id = invoice_match["matches"][0]["id"]

        document = query.handler_security_slice(document_id)
        invoice = query.handler_security_slice(invoice_id)
        self.assertEqual(
            "UNGUARDED", document["summary"]["guard_verdicts"][0]["status"],
        )
        self.assertIn(
            "getInvoice",
            document["summary"]["guard_verdicts"][0]["differential_siblings"],
        )
        self.assertEqual("GUARDED", invoice["summary"]["guard_verdicts"][0]["status"])

        request_paths = [
            node for node in graph["nodes"]
            if node["kind"] == "taint-reach" and "public parameter:req" in node["label"]
        ]
        self.assertEqual(2, len(request_paths))
        slices = [query.security_path(node["id"]) for node in request_paths]
        self.assertTrue(all(
            any("req.body.id" in step["label"] for step in item["sections"]["path"])
            for item in slices
        ))
        contexts = {tuple(item["summary"]["context_ids"]) for item in slices}
        self.assertEqual(2, len(contexts))

        call = next(
            node for node in graph["nodes"]
            if node["kind"] == "call" and node["label"] == "findById(documentId)"
        )
        explanation = query.explain_call(call["id"])
        self.assertEqual("exact", explanation["summary"]["resolution"])
        self.assertTrue(explanation["sections"]["targets"])

        small = query.value_history(
            request_paths[0]["properties"]["source_value_id"], budget_tokens=1_000,
        )
        self.assertLessEqual(small["budget"]["estimated_tokens"], 1_000)
        self.assertTrue(small["budget"]["truncated"])
        self.assertTrue(small["continuations"])
        self.assertTrue(all(
            "via" in record for record in small["sections"]["history"]
        ))

    def test_lightweight_agent_uses_observed_evidence_and_rejects_repeats(self) -> None:
        class Response:
            def __init__(self, data):
                self.data = data
                self.status = "ok"
                self.usage = {"input_tokens": 10, "output_tokens": 5}

        class ScriptedLLM:
            def __init__(self, decisions):
                self.decisions = list(decisions)
                self.requests = []

            async def complete(self, request):
                self.requests.append(request)
                return Response(self.decisions.pop(0))

        graph, _ = run_project(str(ROOT / "src"))
        query = ReasoningQuery(graph)
        function_id = query.find_entity(
            "getDocument", kind="function",
        )["matches"][0]["id"]
        nodes_by_id = {node["id"]: node for node in graph["nodes"]}
        reach_id = next(
            node["id"] for node in graph["nodes"]
            if node["kind"] == "taint-reach"
            and "public parameter:req" in node["label"]
            and any(
                nodes_by_id[witness_id].get("properties", {}).get("owner_function_id")
                == function_id
                for witness_id in node["properties"]["witness_ids"]
            )
        )
        repeated = {
            "action": "handler_security", "node_id": function_id,
            "rationale": "inspect the handler guard and paths",
            "hypothesis": "document lookup may lack tenant authorization",
        }
        llm = ScriptedLLM([
            repeated,
            repeated,
            {
                "action": "security_path", "node_id": reach_id,
                "rationale": "inspect the contextual request-to-repository path",
            },
            {
                "action": "finish", "outcome": "CONFIRMED_FOR_PROOF",
                "rationale": "the observed path and handler evidence support runtime proof",
                "finding": {
                    "title": "Document lookup lacks tenant binding",
                    "claim": "Attacker-controlled document identity reaches repository lookup.",
                    "affected_node_ids": [function_id],
                    "evidence_ids": [function_id, reach_id],
                    "attack_preconditions": ["Reach the webhook handler"],
                    "potential_impact": ["Cross-tenant document access"],
                    "contradicting_evidence": [],
                    "unresolved_boundaries": [],
                    "confidence": "high",
                    "next_action": "Run a cross-tenant request proof",
                },
            },
        ])
        result = asyncio.run(
            InvestigationAgent(query, llm, max_steps=4).run(function_id),
        )
        self.assertEqual("CONFIRMED_FOR_PROOF", result["status"])
        self.assertEqual(2, len(result["steps"]))
        self.assertIn("repeated action rejected", result["errors"][0]["error"])
        self.assertEqual({function_id, reach_id}, {
            record["id"] for record in result["evidence"]
        })
        json.loads(json.dumps(result))
        self.assertTrue(all(
            isinstance(request, AgentRequest) and request.schema == ACTION_SCHEMA
            for request in llm.requests
        ))
        self.assertTrue(all(
            len(json.dumps(request.context, default=str)) < 24_000
            for request in llm.requests
        ))

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

    def test_typescript_optional_catch_binding_is_null_safe(self) -> None:
        frontend = (
            ROOT / "Arachne" / "frontends" / "typescript" / "build_graph.mjs"
        ).read_text(encoding="utf-8")
        self.assertNotIn("ts.isCatchClause(current?.parent)", frontend)
        with tempfile.TemporaryDirectory() as output:
            self.run_command(
                "node", "Arachne/frontends/typescript/build_graph.mjs",
                "Arachne/frontends/typescript/fixtures/optional_catch", output,
            )
            snapshot = load_snapshot(output)
            validate_snapshot(snapshot)
            functions = {
                node["label"] for node in snapshot.nodes if node["kind"] == "function"
            }
            self.assertEqual(
                {"parseOptional", "continuesAfterCatch"}, functions,
            )

    def test_typescript_reachable_framework_runtime_sources(self) -> None:
        with tempfile.TemporaryDirectory() as output:
            self.run_command(
                "node", "Arachne/frontends/typescript/build_graph.mjs",
                "Arachne/frontends/typescript/fixtures/framework", output,
            )
            snapshot = load_snapshot(output)
            validate_snapshot(snapshot)
            self.assertEqual(2, snapshot.contract_version)
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
            composed, _ = run_project(
                str(ROOT / "Arachne" / "frontends" / "typescript" / "fixtures" / "framework"),
            )
            files = graph_file_infos(composed)
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

            compatibility = graph_file_infos(snapshot_graph(snapshot))
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
            self.assertTrue(all(
                node["id"].startswith("v2:frontend:clang-c:")
                for node in snapshot.nodes
            ))
            self.assertTrue(any(node["kind"] == "token" for node in snapshot.nodes))
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
        semantics, _ = run_project(
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

        cycle_graph, _ = run_project(
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
        graph, _ = run_project(
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

    def test_canonical_branch_history_overlay(self) -> None:
        graph, _ = run_project(
            str(ROOT / "Arachne" / "frontends" / "typescript" / "fixtures" / "branch_history")
        )
        nodes = {node["id"]: node for node in graph["nodes"]}
        function = next(
            node for node in nodes.values()
            if node["kind"] == "function" and node["label"] == "choose"
        )
        phis = [
            node for node in nodes.values()
            if node["kind"] == "phi"
            and node["properties"].get("function_id") == function["id"]
        ]
        result_phi = next(node for node in phis if node["label"] == "phi:result")
        self.assertEqual(2, len(result_phi["properties"]["incoming_definition_ids"]))
        self.assertTrue(result_phi["id"].startswith("v2:core:branch-history:phi:"))
        self.assertEqual(2, sum(
            edge["kind"] == "PHI_INPUT" and edge["target"] == result_phi["id"]
            for edge in graph["edges"]
        ))
        return_read = next(
            node for node in nodes.values()
            if node["kind"] == "read" and node["label"] == "result"
            and node["properties"].get("start_line") == 8
        )
        self.assertTrue(any(
            edge["kind"] == "BRANCH_READS_FROM"
            and edge["source"] == result_phi["id"]
            and edge["target"] == return_read["id"]
            for edge in graph["edges"]
        ))

    def test_canonical_heap_identity_overlay(self) -> None:
        graph, _ = run_project(
            str(ROOT / "Arachne" / "frontends" / "typescript" / "fixtures" / "heap")
        )
        nodes = {node["id"]: node for node in graph["nodes"]}
        variables = {
            node["label"]: node for node in nodes.values()
            if node["kind"] == "variable" and node["label"] in {"a", "b"}
        }
        points = {
            variable: {
                edge["target"] for edge in graph["edges"]
                if edge["kind"] == "POINTS_TO" and edge["source"] == node["id"]
                and nodes[edge["target"]]["kind"] == "heap-object"
            }
            for variable, node in variables.items()
        }
        self.assertTrue(points["a"])
        self.assertEqual(points["a"], points["b"])
        secret_paths = [
            node for node in nodes.values()
            if node["kind"] == "property-path" and node["properties"].get("path") == "secret"
        ]
        self.assertEqual({"a.secret", "b.secret"}, {node["label"] for node in secret_paths})
        write_locations = {
            edge["target"] for edge in graph["edges"] if edge["kind"] == "WRITES_HEAP"
        }
        read_locations = {
            edge["source"] for edge in graph["edges"] if edge["kind"] == "READS_HEAP"
        }
        self.assertTrue(write_locations & read_locations)
        self.assertTrue(all(
            nodes[location]["id"].startswith("v2:core:heap-identity:heap-location:")
            for location in write_locations & read_locations
        ))
        context_variables = {
            node["label"]: node for node in nodes.values()
            if node["kind"] == "variable" and node["label"] in {"first", "second"}
        }
        context_points = {
            name: {
                edge["target"] for edge in graph["edges"]
                if edge["kind"] == "POINTS_TO" and edge["source"] == variable["id"]
                and nodes[edge["target"]]["kind"] == "heap-object"
                and nodes[edge["target"]]["properties"].get("context_id")
            }
            for name, variable in context_variables.items()
        }
        self.assertTrue(context_points["first"])
        self.assertTrue(context_points["second"])
        self.assertTrue(context_points["first"].isdisjoint(context_points["second"]))
        effects = [
            node for node in nodes.values()
            if node["kind"] == "function-effect"
            and node["properties"].get("effect_kind") == "parameter-property-write"
        ]
        self.assertEqual(1, len(effects))
        applied_locations = {
            edge["target"] for edge in graph["edges"]
            if edge["kind"] == "APPLIES_EFFECT"
            and edge["properties"].get("effect_id") == effects[0]["id"]
        }
        account_read_locations = {
            edge["source"] for edge in graph["edges"]
            if edge["kind"] == "READS_HEAP"
            and nodes[edge["target"]].get("label") == "account.admin"
        }
        self.assertTrue(applied_locations & account_read_locations)

    def test_canonical_runtime_and_async_event_overlays(self) -> None:
        graph, _ = run_project(
            str(ROOT / "Arachne" / "frontends" / "typescript" / "fixtures" / "async_events")
        )
        nodes = {node["id"]: node for node in graph["nodes"]}
        effects = [
            node for node in nodes.values()
            if node["kind"] == "function-effect"
            and node["id"].startswith("v2:runtime-model:generic-runtime-behaviors:")
        ]
        self.assertTrue(effects)
        handle = next(
            node for node in nodes.values()
            if node["kind"] == "function" and node["label"] == "handle"
        )
        self.assertGreaterEqual(sum(
            edge["kind"] == "REGISTERS_CALLBACK" and edge["target"] == handle["id"]
            for edge in graph["edges"]
        ), 3)
        data_events = [
            node for node in nodes.values()
            if node["kind"] == "async-event"
            and node["properties"].get("event_name") == "data"
        ]
        self.assertEqual(1, len(data_events))
        self.assertTrue(any(
            edge["kind"] == "HANDLED_BY"
            and edge["source"] == data_events[0]["id"]
            and edge["target"] == handle["id"]
            for edge in graph["edges"]
        ))
        self.assertTrue(any(
            edge["kind"] == "EMITS_EVENT" and edge["target"] == data_events[0]["id"]
            for edge in graph["edges"]
        ))
        self.assertTrue(any(
            edge["kind"] == "SCHEDULES" and edge["target"] == handle["id"]
            and edge["properties"].get("queue") == "timer"
            for edge in graph["edges"]
        ))
        self.assertTrue(any(
            edge["kind"] == "ASYNC_CONTINUES_AT"
            and edge["properties"].get("suspension") == "await"
            for edge in graph["edges"]
        ))

    def test_canonical_dynamic_dispatch_overlay(self) -> None:
        graph, _ = run_project(
            str(ROOT / "Arachne" / "frontends" / "typescript" / "fixtures" / "dispatch")
        )
        nodes = {node["id"]: node for node in graph["nodes"]}
        action = next(
            node for node in nodes.values()
            if node["kind"] == "function" and node["label"] == "action"
        )
        invoke = next(
            node for node in nodes.values()
            if node["kind"] == "function" and node["label"] == "invoke"
        )
        callback_call = next(
            node for node in nodes.values()
            if node["kind"] == "call" and node["label"] == "callback()"
            and node["properties"].get("owner_function_id") == invoke["id"]
        )
        self.assertTrue(any(
            edge["kind"] == "MAY_INVOKE" and edge["source"] == callback_call["id"]
            and edge["target"] == action["id"]
            and edge["properties"].get("reason") == "contextual-callback-binding"
            for edge in graph["edges"]
        ))
        for label in ("action.call(null)", "action.apply(null)", "bound()"):
            call = next(
                node for node in nodes.values()
                if node["kind"] == "call" and node["label"] == label
            )
            self.assertTrue(any(
                edge["kind"] in {"INVOKES", "MAY_INVOKE"}
                and edge["source"] == call["id"] and edge["target"] == action["id"]
                for edge in graph["edges"]
            ), label)
        service_call = next(
            node for node in nodes.values()
            if node["kind"] == "call" and node["label"] == "service.run()"
        )
        implementations = {
            node["id"] for node in nodes.values()
            if node["kind"] == "method" and node["label"] == "run"
            and nodes.get(node["properties"].get("owner_id"), {}).get("label")
                in {"First", "Second"}
        }
        self.assertEqual(2, len(implementations))
        reached = {
            edge["target"] for edge in graph["edges"]
            if edge["kind"] == "MAY_INVOKE" and edge["source"] == service_call["id"]
        }
        self.assertTrue(implementations.issubset(reached))

    def test_compiler_dynamic_facts_and_core_boundaries(self) -> None:
        graph, _ = run_project(
            str(ROOT / "Arachne" / "frontends" / "typescript" / "fixtures" / "dynamic")
        )
        nodes = {node["id"]: node for node in graph["nodes"]}
        compiler_behaviors = [
            node for node in nodes.values()
            if node["kind"] == "dynamic-behavior"
            and node["id"].startswith("v2:frontend:typescript-compiler-api:")
        ]
        kinds = {node["properties"].get("behavior_kind") for node in compiler_behaviors}
        self.assertTrue({
            "eval", "new-function", "runtime-module-load", "reflection", "proxy",
            "computed-property-write", "monkey-patch", "dynamic-import",
        }.issubset(kinds))
        self.assertEqual(1, sum(
            node["properties"].get("behavior_kind") == "eval"
            for node in compiler_behaviors
        ), "the locally shadowed eval must not be tagged as the global builtin")
        boundaries = [
            node for node in nodes.values()
            if node["kind"] == "boundary"
            and node["properties"].get("boundary_kind") == "dynamic-runtime"
        ]
        represented = {node["properties"].get("behavior_id") for node in boundaries}
        self.assertTrue({node["id"] for node in compiler_behaviors}.issubset(represented))
        computed = next(
            node for node in compiler_behaviors
            if node["properties"].get("behavior_kind") == "computed-property-write"
        )
        self.assertTrue(computed["properties"].get("key_value_id"))
        self.assertTrue(computed["properties"].get("target_id"))
        self.assertTrue(any(
            edge["kind"] == "DYNAMIC_INPUT" and edge["target"] == computed["id"]
            for edge in graph["edges"]
        ))

    def test_mixed_language_registry_composes_one_graph(self) -> None:
        with tempfile.TemporaryDirectory() as output:
            graph, snapshots = run_project(str(ROOT), output)
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
            overview = ReasoningQuery(graph).overview()["manifest"]
            self.assertTrue(
                {"c", "typescript"}.issubset(overview["project"]["languages"]),
            )
            self.assertEqual(
                len(graph["nodes"]), overview["node_index"]["count"],
            )

    def test_typescript_compiler_facts_feed_semantic_overlays(self) -> None:
        with tempfile.TemporaryDirectory() as output:
            graph, snapshots = run_project(str(ROOT / "src"), output)
            files = graph_file_infos(graph)
            snapshot = next(
                item for item in snapshots
                if item.frontend_id == "typescript-compiler-api"
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
                "dynamic_behaviors", "wiring_boundaries",
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
            self.assertFalse(any(
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
                if source["label"] == "public parameter:req"
                and any(
                    tainted["source_id"] == source["id"]
                    and tainted["callee"] == "findById"
                    for candidate in files for tainted in candidate["tainted_calls"]
                )
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
            self.assertTrue(all(item.get("witness_ids") for item in closure))
            tainted = next(
                item for info in files for item in info["tainted_calls"]
            )
            witness = taint_path(files, tainted["source_id"], tainted["call_id"])
            self.assertEqual(tainted["source_id"], witness[0])
            self.assertEqual(tainted["call_id"], witness[-1])

    def test_file_compatibility_view_is_compiler_backed(self) -> None:
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
