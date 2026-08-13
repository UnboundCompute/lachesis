"""Executable checks for every registered compiler frontend."""
from __future__ import annotations

import asyncio
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from typing import Optional


ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

# The multi-file TypeScript project the end-to-end tests analyze. Defaults to the
# fixture corpus shipped in-tree so a fresh clone can run the whole suite; point
# LACHESIS_CORPUS at any other TypeScript tree to re-run these tests against it.
CORPUS = Path(os.environ.get(
    "LACHESIS_CORPUS",
    ROOT / "lachesis" / "frontends" / "typescript" / "fixtures" / "project",
))
# The two-package workspace Lever 3's per-package build is exercised against: a root
# workspace manifest plus `packages/api` and `packages/core`, with a real import across
# the boundary. Always in-tree — this one is not swappable, because the test is about
# the package partition itself.
WORKSPACE_FIXTURE = (
    ROOT / "lachesis" / "frontends" / "typescript" / "fixtures" / "workspace"
)
requires_corpus = unittest.skipIf(
    not CORPUS.is_dir(), f"corpus not present at {CORPUS} (set LACHESIS_CORPUS)",
)

# The shipped corpus is pinned by identity, not by magic totals: the exact files it
# contributes, the exact functions it declares, and the exact number of calls the
# frontend recovers from them. A count alone passes when the graph loses one entry
# and gains another; these sets do not. When LACHESIS_CORPUS points somewhere else
# the identity assertions are skipped and the structural ones still run.
CORPUS_IS_FIXTURE = "LACHESIS_CORPUS" not in os.environ
CORPUS_FILES = {
    "auth/principal.ts", "data/cache.ts", "data/repository.ts", "http/router.ts",
    "http/webhook.ts", "index.ts", "regress/backtick-in-regex.ts",
    "resources/document-service.ts", "resources/invoice-service.ts",
    "runtime/plugins.ts", "types.ts", "util/ids.ts",
}
CORPUS_FUNCTIONS = {
    "after", "decodeSession", "dispatch", "findById", "get", "getDocument",
    "getInvoice", "handleWebhook", "isBlank", "loadPlugin", "markHit",
    "normalizeId", "principalKey", "recall", "remember", "resolvePrincipal",
    "save", "strip",
}
CORPUS_FUNCTION_CALLS = 32

from lachesis.compatibility.file_view import analyze_files, read_file, walk
from lachesis.compatibility.projector import (
    compatibility_taint_path as taint_path, graph_file_infos,
)
from lachesis.pipeline import run_project, semantic_snapshot_graph, snapshot_graph
from lachesis.projections import build_layered_graph
from lachesis.reasoning import InvestigationAgent, ReasoningQuery
from lachesis.reasoning.agent import ACTION_SCHEMA, AgentRequest
from lachesis.core.snapshot import load_snapshot
from lachesis.core.validation import validate_snapshot
from lachesis.core.contract import ContractError, FrontendSnapshot
from lachesis.core.boundaries import import_boundary_violations
from lachesis.core.identities import stable_id
from lachesis.core.query import GraphIndex
from lachesis.ecosystems import EcosystemRegistry
from lachesis.ecosystems.common import GenericRouteModel


class CompilerFrontendTests(unittest.TestCase):
    def run_command(self, *command: str, environment: Optional[dict] = None) -> None:
        completed = subprocess.run(
            command, cwd=ROOT, text=True, capture_output=True, check=False,
            env={**os.environ, **environment} if environment else None,
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
        self.assertEqual([], import_boundary_violations(ROOT / "lachesis"))

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
            for path in (ROOT / "lachesis").rglob("*.py")
            if path.name in removed and path.parent.name != "overlays"
        ))
        c_frontend = (
            ROOT / "lachesis" / "frontends" / "c" / "build_graph.py"
        ).read_text(encoding="utf-8")
        typescript_frontend = (
            ROOT / "lachesis" / "frontends" / "typescript" / "build_graph.mjs"
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

    @requires_corpus
    def test_cli_canonical_views_end_to_end(self) -> None:
        with tempfile.TemporaryDirectory() as output:
            graph_path = Path(output) / "canonical.kuzu"
            layered_path = Path(output) / "layered"
            self.run_command(
                sys.executable, "lachesis/cli/analyze.py", str(CORPUS), str(graph_path),
                "--frontend-out", str(Path(output) / "frontends"),
                "--layered-out", str(layered_path),
            )
            self.assertTrue((graph_path / "graph.kuzu").exists())
            self.assertTrue((graph_path / "lachesis-manifest.json").is_file())
            self.assertTrue((layered_path / "manifest.json").is_file())
            self.assertTrue((layered_path / "node_index.json").is_file())
            overview = subprocess.run(
                [
                    sys.executable, "lachesis/cli/query.py", str(graph_path),
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
                    sys.executable, "lachesis/cli/query.py", str(graph_path),
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
                (ROOT / "lachesis" / "cli" / "query.py").read_text(encoding="utf-8"),
            )

    @requires_corpus
    def test_layered_v2_exposes_cross_tier_navigation(self) -> None:
        graph, _ = run_project(str(CORPUS))
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

    @requires_corpus
    def test_reasoning_queries_are_typed_contextual_and_budgeted(self) -> None:
        graph, _ = run_project(str(CORPUS))
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

    @requires_corpus
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

        graph, _ = run_project(str(CORPUS))
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

    @requires_corpus
    def test_typescript_contextual_tokens_and_library_provenance(self) -> None:
        with tempfile.TemporaryDirectory() as output:
            self.run_command(
                "node", "lachesis/frontends/typescript/build_graph.mjs", str(CORPUS), output,
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
            ROOT / "lachesis" / "frontends" / "typescript" / "build_graph.mjs"
        ).read_text(encoding="utf-8")
        self.assertNotIn("ts.isCatchClause(current?.parent)", frontend)
        with tempfile.TemporaryDirectory() as output:
            self.run_command(
                "node", "lachesis/frontends/typescript/build_graph.mjs",
                "lachesis/frontends/typescript/fixtures/optional_catch", output,
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
                "node", "lachesis/frontends/typescript/build_graph.mjs",
                "lachesis/frontends/typescript/fixtures/framework", output,
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
                str(ROOT / "lachesis" / "frontends" / "typescript" / "fixtures" / "framework"),
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
                "node", "lachesis/frontends/typescript/build_graph.mjs",
                "lachesis/frontends/typescript/fixtures/semantics", output,
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
            self.assertFalse((ROOT / "lachesis" / "type_system_analysis.py").exists())

    def test_typescript_compiler_emits_dispatch_mutation_and_runtime_facts(self) -> None:
        with tempfile.TemporaryDirectory() as output:
            self.run_command(
                "node", "lachesis/frontends/typescript/build_graph.mjs",
                "lachesis/frontends/typescript/fixtures/semantics", output,
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
                sys.executable, "lachesis/frontends/c/build_graph.py",
                "lachesis/frontends/c/fixtures", output,
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
            self.assertEqual(3, sum(
                edge["kind"] == "ARGUMENT_BINDS_PARAMETER"
                for edge in snapshot.edges
            ))
            self.assertTrue(any(
                edge["kind"] == "WRITES_PARAMETER_PROPERTY"
                for edge in snapshot.edges
            ))
            # Indirect-dispatch resolution (dispatch.c): the ops-struct initializer
            # binds .read -> ext4_read, so the ops->read(...) call-site resolves to
            # MAY_INVOKE; a function handed to a callee is PASSES_CALLBACK.
            functions_by_label = {
                node["label"]: node["id"] for node in snapshot.nodes
                if node["kind"] == "function"
            }
            may_invoke = [edge for edge in snapshot.edges if edge["kind"] == "MAY_INVOKE"]
            self.assertTrue(any(
                edge["target"] == functions_by_label["ext4_read"]
                and edge["properties"].get("dispatch") == "ops-struct"
                for edge in may_invoke
            ))
            self.assertTrue(any(
                edge["kind"] == "PASSES_CALLBACK"
                and edge["target"] == functions_by_label["ext4_write"]
                for edge in snapshot.edges
            ))
            # Macro recovery (macros.c): the post-preprocessor AST has no #defines,
            # so the -E -dD pass reconstructs them as first-class `macro` nodes with
            # object-like vs function-like distinguished and their definition site.
            macros = {
                node["label"]: node for node in snapshot.nodes
                if node["kind"] == "macro"
            }
            self.assertEqual("object-like", macros["MAX_PATH"]["properties"]["form"])
            self.assertEqual(
                "function-like", macros["SQUARE"]["properties"]["form"]
            )
            self.assertEqual(["x"], macros["SQUARE"]["properties"]["parameters"])
            # The file->macro containment is a cross-tier structural edge, surfaced
            # as EXPANDS_TO(via=DECLARES) like every other file->declaration link.
            macro_id = macros["MAX_PATH"]["id"]
            self.assertTrue(any(
                edge["kind"] == "EXPANDS_TO" and edge["target"] == macro_id
                and edge["properties"].get("via") == "DECLARES"
                for edge in snapshot.edges
            ))

    def test_c_skipping_tokens_removes_the_tokens_and_nothing_else(self) -> None:
        """``LACHESIS_EMIT_TOKENS=0`` drops one whole clang pass per file.

        The saving is only legitimate if what it removes is exactly what the store's
        ``prune`` lever would have deleted anyway. So this compares the two bundles as
        sets rather than as counts: every non-token node and every edge that does not
        touch a token must survive byte-identically, and the bundle must say ``lexical:
        none`` so a consumer can tell an absent stream from an empty one.
        """
        def bundle(directory: str, tokens: str) -> FrontendSnapshot:
            self.run_command(
                sys.executable, "lachesis/frontends/c/build_graph.py",
                "lachesis/frontends/c/fixtures", directory,
                environment={"LACHESIS_EMIT_TOKENS": tokens},
            )
            snapshot = load_snapshot(directory)
            validate_snapshot(snapshot)
            return snapshot

        with tempfile.TemporaryDirectory() as full, tempfile.TemporaryDirectory() as lean:
            with_tokens = bundle(full, "1")
            without = bundle(lean, "0")

        self.assertTrue(any(node["kind"] == "token" for node in with_tokens.nodes))
        self.assertFalse(any(node["kind"] == "token" for node in without.nodes))
        self.assertEqual("partial", with_tokens.capability("lexical"))
        self.assertEqual("none", without.capability("lexical"))

        def keep(snapshot: FrontendSnapshot):
            tokens = {node["id"] for node in snapshot.nodes if node["kind"] == "token"}
            nodes = {json.dumps(node, sort_keys=True)
                     for node in snapshot.nodes if node["id"] not in tokens}
            edges = {json.dumps(edge, sort_keys=True) for edge in snapshot.edges
                     if edge["source"] not in tokens and edge["target"] not in tokens}
            return nodes, edges

        self.assertEqual(keep(with_tokens), keep(without))

    def test_c_compile_commands_supply_per_file_flags(self) -> None:
        # A two-directory project whose header lives outside the source dir fails to
        # parse under a single global -I, but parses cleanly once compile_commands.json
        # supplies the include dir; a per-file -D also changes the parsed AST.
        with tempfile.TemporaryDirectory() as project:
            root = Path(project)
            (root / "src").mkdir()
            (root / "include").mkdir()
            (root / "include" / "helper.h").write_text("int helper_value(void);\n", encoding="utf-8")
            (root / "src" / "main.c").write_text(
                '#include "helper.h"\n'
                "#ifdef FEATURE\n"
                "int feature_enabled(void) { return helper_value(); }\n"
                "#endif\n"
                "int main(void) { return helper_value(); }\n",
                encoding="utf-8",
            )
            (root / "compile_commands.json").write_text(
                json.dumps([{
                    "directory": str(root), "file": "src/main.c",
                    "arguments": ["clang", "-c", "src/main.c", "-Iinclude", "-DFEATURE=1", "-o", "main.o"],
                }]),
                encoding="utf-8",
            )
            with tempfile.TemporaryDirectory() as output:
                self.run_command(
                    sys.executable, "lachesis/frontends/c/build_graph.py",
                    str(root), output,
                )
                snapshot = load_snapshot(output)
                validate_snapshot(snapshot)
                functions = {
                    node["label"] for node in snapshot.nodes if node["kind"] == "function"
                }
                # -Iinclude resolved the header; -DFEATURE enabled the guarded function.
                self.assertIn("helper_value", functions)
                self.assertIn("feature_enabled", functions)

    def test_c_nonzero_exit_with_ast_recovers_full_semantics(self) -> None:
        # Clang emits a complete AST on stdout even when it exits nonzero from
        # residual diagnostics — routine for real-world TUs (e.g. an unconfigured
        # kernel tree). Recovery must not gate on the return code: the file's whole
        # semantic layer (functions, calls) has to survive, the file must count as
        # analyzed rather than failed, and the diagnostic still lands as T4 proof.
        with tempfile.TemporaryDirectory() as project:
            root = Path(project)
            # The duplicate definition makes clang exit 1 while still dumping the
            # full AST for `handler`/`dispatch` and the call between them.
            (root / "mod.c").write_text(
                "static int handler(int x) { return x + 1; }\n"
                "int dispatch(int x) { return handler(x); }\n"
                "int dup(void) { return 42; }\n"
                "int dup(void) { return 43; }\n",
                encoding="utf-8",
            )
            with tempfile.TemporaryDirectory() as output:
                self.run_command(
                    sys.executable, "lachesis/frontends/c/build_graph.py",
                    str(root), output,
                )
                snapshot = load_snapshot(output)
                validate_snapshot(snapshot)
                manifest = json.loads((Path(output) / "manifest.json").read_text(encoding="utf-8"))
                # Nonzero exit, but the AST was consumed: file analyzed, not failed.
                self.assertEqual(0, manifest["failed_file_count"])
                self.assertEqual(1, manifest["analyzed_file_count"])
                functions = {
                    node["label"] for node in snapshot.nodes if node["kind"] == "function"
                }
                self.assertIn("handler", functions)
                self.assertIn("dispatch", functions)
                # The dispatch -> handler call survived the nonzero exit.
                self.assertTrue(any(
                    edge["kind"] in {"CALLS", "INVOKES"} for edge in snapshot.edges
                ))
                # Diagnostics are still recorded even though the file was recovered.
                self.assertTrue(any(node["kind"] == "diagnostic" for node in snapshot.nodes))

    def test_c_partial_ingest_keeps_failed_file_and_downgrades_capability(self) -> None:
        # A file that clang cannot parse must not vanish: its file node survives,
        # its diagnostics land as T4 proof, the manifest counts it as failed, and
        # the "complete" parse claims collapse to "partial" — while a sibling file
        # that parses cleanly still contributes its declarations.
        with tempfile.TemporaryDirectory() as project:
            root = Path(project)
            (root / "good.c").write_text("int good(void) { return 1; }\n", encoding="utf-8")
            (root / "broken.c").write_text("int broken( { this is not valid C ;;;\n", encoding="utf-8")
            with tempfile.TemporaryDirectory() as output:
                self.run_command(
                    sys.executable, "lachesis/frontends/c/build_graph.py",
                    str(root), output,
                )
                snapshot = load_snapshot(output)
                validate_snapshot(snapshot)
                manifest = json.loads((Path(output) / "manifest.json").read_text(encoding="utf-8"))
                self.assertEqual(1, manifest["failed_file_count"])
                self.assertEqual(1, manifest["analyzed_file_count"])
                # A parse hole downgrades the otherwise-complete parse capabilities.
                self.assertEqual("partial", manifest["capabilities"]["syntax"])
                # The failed file keeps its file node rather than being dropped.
                self.assertTrue(any(
                    node["kind"] == "file" and node["label"].endswith("broken.c")
                    for node in snapshot.nodes
                ))
                # Its diagnostics are retained as T4 proof.
                self.assertTrue(any(node["kind"] == "diagnostic" for node in snapshot.nodes))
                # The clean sibling still yields its declaration.
                self.assertTrue(any(
                    node["kind"] == "function" and node["label"] == "good"
                    for node in snapshot.nodes
                ))

    def test_c_cross_tu_call_linking_and_nav(self) -> None:
        # A call whose definition lives in another translation unit only sees the
        # header prototype at parse time, so intra-TU resolution leaves it
        # "dynamic-or-unresolved". The post-merge cross-TU linker must connect it to
        # the unique body-bearing definition, collapse the prototype/definition twins,
        # and the nav resolver must then land a bare name on the definition.
        import sys as _sys
        from pathlib import Path as _Path
        _sys.path.insert(0, str(_Path(ROOT)))
        from lachesis.nav.graphlib import GraphLib
        from lachesis.nav.symbol_index import build_index, _resolve, callees
        from lachesis.nav.file_graph import _find_file_node
        from lachesis.nav.folder_graph import build_folder_graph

        with tempfile.TemporaryDirectory() as output:
            self.run_command(
                sys.executable, "lachesis/frontends/c/build_graph.py",
                "lachesis/frontends/c/fixtures_crosstu", output,
            )
            snapshot = load_snapshot(output)
            validate_snapshot(snapshot)

            functions = [n for n in snapshot.nodes if n["kind"] == "function"]
            defs = [n for n in functions
                    if n["label"] == "lib_compute"
                    and not n["properties"].get("declaration_only")]
            protos = [n for n in functions
                      if n["label"] == "lib_compute"
                      and n["properties"].get("declaration_only")]
            self.assertEqual(1, len(defs), "exactly one body-bearing definition")
            self.assertEqual(1, len(protos), "the header prototype twin survives")
            def_id = defs[0]["id"]
            proto_id = protos[0]["id"]
            client = next(n for n in functions if n["label"] == "client_run")

            # Fix C: the cross-TU call is linked to the DEFINITION, not the prototype.
            call = next(n for n in snapshot.nodes
                        if n["kind"] == "call" and n["properties"].get("callee") == "lib_compute")
            self.assertEqual("cross-tu", call["properties"]["resolution"])
            self.assertEqual(def_id, call["properties"]["primary_target_id"])
            self.assertTrue(any(
                e["kind"] == "CALLS" and e["source"] == client["id"] and e["target"] == def_id
                for e in snapshot.edges
            ), "CALLS(client_run -> lib_compute definition)")
            # The prototype is connected to its definition so the body stays reachable.
            self.assertTrue(any(
                e["kind"] == "REFERS_TO" and e["source"] == proto_id and e["target"] == def_id
                for e in snapshot.edges
            ), "REFERS_TO(prototype -> definition)")

            gl = GraphLib({"nodes": list(snapshot.nodes), "edges": list(snapshot.edges)})
            index = build_index(gl)

            # Fix A: a bare-name resolve prefers the body-bearing definition twin, and
            # a nav traversal off it reaches the callee a resolve-to-prototype misses.
            resolved = _resolve(gl, index, "lib_compute")
            self.assertEqual(def_id, resolved[0]["node_id"])
            client_resolved = _resolve(gl, index, "client_run")[0]
            self.assertIn("lib_compute",
                          [c["name"] for c in callees(gl, client_resolved["node_id"])])

            # Fix B: the file node resolves from every path form — the absolute path,
            # the source-relative path, and the bare basename all reach one node.
            client_file = next(n for n in snapshot.nodes
                               if n["kind"] == "file" and n["label"].endswith("client.c"))
            absolute = client_file["properties"]["absolute_file"]
            relative = client_file["properties"]["file"]
            by_abs = _find_file_node(gl, path=absolute, file_id=None)
            by_rel = _find_file_node(gl, path=relative, file_id=None)
            by_base = _find_file_node(gl, path="client.c", file_id=None)
            self.assertIsNotNone(by_abs)
            self.assertEqual(client_file["id"], by_abs["id"])
            self.assertEqual(client_file["id"], by_rel["id"])
            self.assertEqual(client_file["id"], by_base["id"])
            # open_folder resolves the source-dir root by absolute path too.
            source_root = str(_Path(absolute).parent)
            folder = build_folder_graph(gl, root=source_root)
            self.assertTrue(any(
                n["kind"] == "file" and n["label"] == "client.c"
                for n in folder["nodes"]
            ), "open_folder finds the fixture files under the absolute root")

    def test_c_ops_struct_registration_reverse_navigation(self) -> None:
        # An entry-point handler registered into a dispatch table but never called
        # in-tree (the runtime dispatches through the table) must still be reachable
        # by reverse navigation: the frontend models each ops-struct slot binding as
        # MAY_INVOKE(table -> handler), so callers(handler) walks back to the table.
        import sys as _sys
        from pathlib import Path as _Path
        _sys.path.insert(0, str(_Path(ROOT)))
        from lachesis.nav.graphlib import GraphLib
        from lachesis.nav.symbol_index import build_index, _resolve, callers

        with tempfile.TemporaryDirectory() as output:
            self.run_command(
                sys.executable, "lachesis/frontends/c/build_graph.py",
                "lachesis/frontends/c/fixtures_opsreg", output,
            )
            snapshot = load_snapshot(output)
            validate_snapshot(snapshot)

            ops = next(n for n in snapshot.nodes
                       if n["kind"] == "variable" and n["label"] == "driver_ops")
            handlers = {n["label"]: n["id"] for n in snapshot.nodes
                        if n["kind"] == "function" and n["label"] in {"drv_start", "drv_stop"}}
            # Each slot binding is a MAY_INVOKE(table -> handler), tagged as an
            # ops-struct registration and carrying the slot it fills.
            reg = {e["target"]: e for e in snapshot.edges
                   if e["kind"] == "MAY_INVOKE" and e["source"] == ops["id"]
                   and e["properties"].get("resolution") == "registration"}
            self.assertEqual(set(handlers.values()), set(reg),
                             "every registered handler has a table->handler edge")
            self.assertEqual("ops-struct", reg[handlers["drv_start"]]["properties"]["dispatch"])
            self.assertEqual("start", reg[handlers["drv_start"]]["properties"]["slot"])

            # The handler is never called directly, so reverse navigation must come
            # from the registration: callers(drv_start) surfaces the ops table.
            gl = GraphLib({"nodes": list(snapshot.nodes), "edges": list(snapshot.edges)})
            index = build_index(gl)
            resolved = _resolve(gl, index, "drv_start")[0]
            callers_of = callers(gl, resolved["node_id"])
            self.assertIn("driver_ops", [c["name"] for c in callers_of])
            self.assertTrue(all(c["via"].startswith("indirect") for c in callers_of))

    def test_c_ops_struct_registration_with_header_defined_type(self) -> None:
        # Kernel shape: the dispatch-table *type* is defined in a header outside the
        # ingested tree (e.g. `struct net_device_ops` in netdevice.h), while the table
        # instance is initialized in the .c. The struct's header is never parsed as its
        # own compiler root, so its FieldDecls never become graph nodes — the binding
        # must recover the slot layout (field names, in order) from the .c's own
        # included copy of the RecordDecl. Header-subtree pruning keeps RecordDecls for
        # exactly this reason; without it, reverse navigation from an entry-point
        # handler back to its table silently breaks (the class the in-tree ops-struct
        # fixture cannot exercise, since it defines the struct in the main .c).
        import sys as _sys
        from pathlib import Path as _Path
        _sys.path.insert(0, str(_Path(ROOT)))
        from lachesis.nav.graphlib import GraphLib
        from lachesis.nav.symbol_index import build_index, _resolve, callers

        with tempfile.TemporaryDirectory() as output:
            self.run_command(
                sys.executable, "lachesis/frontends/c/build_graph.py",
                "lachesis/frontends/c/fixtures_opsreg_hdr/src", output,
            )
            snapshot = load_snapshot(output)
            validate_snapshot(snapshot)

            ops = next(n for n in snapshot.nodes
                       if n["kind"] == "variable" and n["label"] == "driver_ops")
            handlers = {n["label"]: n["id"] for n in snapshot.nodes
                        if n["kind"] == "function" and n["label"] in {"drv_start", "drv_stop"}}
            reg = {e["target"]: e for e in snapshot.edges
                   if e["kind"] == "MAY_INVOKE" and e["source"] == ops["id"]
                   and e["properties"].get("resolution") == "registration"}
            self.assertEqual(set(handlers.values()), set(reg),
                             "every handler registered via a header-defined ops struct has a table->handler edge")
            # The slot is labeled by the header FieldDecl's name even though that field
            # is not itself a graph node.
            self.assertEqual("start", reg[handlers["drv_start"]]["properties"]["slot"])
            self.assertEqual("stop", reg[handlers["drv_stop"]]["properties"]["slot"])

            gl = GraphLib({"nodes": list(snapshot.nodes), "edges": list(snapshot.edges)})
            index = build_index(gl)
            resolved = _resolve(gl, index, "drv_start")[0]
            callers_of = callers(gl, resolved["node_id"])
            self.assertIn("driver_ops", [c["name"] for c in callers_of])
            self.assertTrue(all(c["via"].startswith("indirect") for c in callers_of))

    def test_python_declarations_and_byte_exact_read_body(self) -> None:
        # The CPython AST frontend, at its declaration layer: the nodes `search`,
        # `read_body` and `open_folder` navigate by. The offset assertions are the
        # point of the test — `ast` reports column offsets as UTF-8 byte counts into
        # the physical line while nav slices decoded text by character, so on any
        # file with one non-ASCII character an unconverted offset silently returns
        # the wrong source. app/util/text.py is written to expose exactly that.
        import ast as ast_module
        import tokenize as tokenize_module

        from lachesis.nav.graphlib import GraphLib
        from lachesis.nav.symbol_index import build_index, _resolve

        fixtures = ROOT / "lachesis" / "frontends" / "python" / "fixtures"
        with tempfile.TemporaryDirectory() as output:
            self.run_command(
                sys.executable, "-m", "lachesis.frontends.python.build_graph",
                str(fixtures), output,
            )
            snapshot = load_snapshot(output)
            validate_snapshot(snapshot)
            self.assertEqual(2, snapshot.contract_version)
            self.assertEqual(("python",), tuple(snapshot.languages))
            self.assertTrue(all(
                node["id"].startswith("v2:frontend:cpython-ast:")
                for node in snapshot.nodes
            ))
            self.assertEqual(0, snapshot.manifest["failed_file_count"])
            # Nothing may be silently discarded: every edge's endpoints exist.
            self.assertEqual(0, snapshot.manifest["dropped_edge_count"])

            by_kind: dict[str, dict[str, dict]] = {}
            for node in snapshot.nodes:
                by_kind.setdefault(node["kind"], {})[node["label"]] = node
            # def inside a class is a method, __init__ is a constructor, and a def
            # at module level (or nested in one) is a plain function.
            self.assertIn("open_repository", by_kind["function"])
            self.assertIn("fetch", by_kind["method"])
            self.assertIn("__init__", by_kind["constructor"])
            self.assertIn("Repository", by_kind["class"])
            self.assertIn("CachingRepository", by_kind["class"])
            self.assertIn("Nested", by_kind["class"])
            self.assertNotIn("fetch", by_kind["function"])
            self.assertNotIn("open_repository", by_kind["method"])
            # A nested def belongs to the function that declares it, not the module.
            self.assertEqual(
                by_kind["function"]["outer"]["id"],
                by_kind["function"]["inner"]["properties"]["owner_function_id"],
            )
            self.assertTrue(by_kind["function"]["counter"]["properties"]["is_generator"])
            self.assertFalse(by_kind["function"]["outer"]["properties"]["is_generator"])
            self.assertTrue(by_kind["function"]["fetch_all"]["properties"]["is_async"])
            self.assertEqual(
                "full_parameter_matrix(positional, standard, defaulted=..., *rest, "
                "keyword, keyword_defaulted=..., **extra)",
                by_kind["function"]["full_parameter_matrix"]["properties"]["signature"],
            )
            parameter_forms = {
                node["label"]: node["properties"]["parameter_form"]
                for node in snapshot.nodes
                if node["kind"] == "parameter"
                and node["properties"]["owner_function_id"]
                == by_kind["function"]["full_parameter_matrix"]["id"]
            }
            self.assertEqual({
                "positional": "positional-only", "standard": "positional-or-keyword",
                "defaulted": "positional-or-keyword", "rest": "var-positional",
                "keyword": "keyword-only", "keyword_defaulted": "keyword-only",
                "extra": "var-keyword",
            }, parameter_forms)
            # file -> declaration is a cross-tier structural link, surfaced as
            # EXPANDS_TO(via=DECLARES) exactly as the C frontend surfaces its own.
            repository_id = by_kind["class"]["Repository"]["id"]
            self.assertTrue(any(
                edge["kind"] == "EXPANDS_TO" and edge["target"] == repository_id
                and edge["properties"].get("via") == "DECLARES"
                for edge in snapshot.edges
            ))
            # class -> method stays within T1, so it is a plain DECLARES_MEMBER and
            # is not wrapped. `fetch` is declared twice (base and override), so the
            # edge is matched by owner, never by label alone.
            base_fetch = next(
                node for node in snapshot.nodes
                if node["kind"] == "method" and node["label"] == "fetch"
                and node["properties"]["owner_id"] == repository_id
            )
            self.assertTrue(any(
                edge["kind"] == "DECLARES_MEMBER" and edge["source"] == repository_id
                and edge["target"] == base_fetch["id"]
                for edge in snapshot.edges
            ))

            # read_body, on the file built to break naive offsets. Every declaration
            # in it must slice back to exactly what the compiler itself reports.
            gl = GraphLib({"nodes": list(snapshot.nodes), "edges": list(snapshot.edges)})
            index = build_index(gl)
            unicode_file = fixtures / "app" / "util" / "text.py"
            with tokenize_module.open(str(unicode_file)) as handle:
                text = handle.read()
            tree = ast_module.parse(text)
            expected = {
                statement.name: ast_module.get_source_segment(text, statement)
                for statement in tree.body
                if isinstance(statement, ast_module.FunctionDef)
            }
            self.assertEqual({"greet", "shout", "normalize", "banner"}, set(expected))
            for name, segment in expected.items():
                resolved = _resolve(gl, index, name)
                self.assertTrue(resolved, f"search found no node named {name!r}")
                node = gl.nodes[resolved[0]["node_id"]]
                self.assertEqual(segment, gl.source_text(node), f"read_body({name})")
            # `banner`'s parameters sit to the right of a non-ASCII default on the
            # same line, which is where a byte column and a character column part
            # ways; both must still slice to their own name.
            for node in snapshot.nodes:
                if node["kind"] != "parameter":
                    continue
                properties = node["properties"]
                if properties["absolute_file"] != str(unicode_file):
                    continue
                self.assertEqual(
                    node["label"],
                    text[properties["start_offset"]:properties["end_offset"]],
                )
                self.assertEqual(
                    node["label"][0],
                    text.split("\n")[properties["start_line"] - 1][
                        properties["start_column"] - 1
                    ],
                )

    def test_python_import_resolution_and_open_file(self) -> None:
        # Python has no compiler-supplied module map, so resolution is a function of
        # the directory layout and the root file set alone. The interpreter's
        # sys.path is never probed: the graph must not depend on the analyst's
        # virtualenv. Each row below is one resolution rule.
        from lachesis.nav.graphlib import GraphLib
        from lachesis.nav.file_graph import _find_file_node, build_file_graph

        fixtures = ROOT / "lachesis" / "frontends" / "python" / "fixtures"
        with tempfile.TemporaryDirectory() as output:
            self.run_command(
                sys.executable, "-m", "lachesis.frontends.python.build_graph",
                str(fixtures), output,
            )
            snapshot = load_snapshot(output)
            validate_snapshot(snapshot)
            self.assertEqual("partial", snapshot.capabilities["modules"])
            by_id = {node["id"]: node for node in snapshot.nodes}
            imports = {
                (node["properties"]["file"], node["properties"]["specifier"]): node
                for node in snapshot.nodes if node["kind"] == "import"
            }

            def resolved_of(file: str, specifier: str) -> tuple[str, str]:
                node = imports[(file, specifier)]
                path = node["properties"].get("resolved_path") or ""
                return node["properties"]["resolution"], Path(path).name

            # absolute import of an in-tree module, through an __init__.py chain
            self.assertEqual(
                ("exact", "repository.py"),
                resolved_of("app/service.py", "app.repository :: Repository"),
            )
            # relative level 1, naming a submodule rather than a binding
            self.assertEqual(
                ("exact", "repository.py"),
                resolved_of("app/relative.py", ". :: repository"),
            )
            # relative level 2 out of a nested package, and level 3 back to the root
            self.assertEqual(
                ("exact", "text.py"),
                resolved_of("app/util/nested/deep.py", "..text :: normalize"),
            )
            self.assertEqual(
                ("exact", "__init__.py"),
                resolved_of("app/util/nested/deep.py", "... :: PACKAGE_NAME"),
            )
            # PEP 420 namespace layout: no __init__.py on the path, so the dotted
            # name is only an alias and the hit is conservative, never exact.
            self.assertEqual(
                ("conservative", "leaf.py"),
                resolved_of("entry.py", "namespace.inner.leaf :: identify"),
            )
            # Out of tree stays out of tree. Nothing is invented for it, and the
            # standard library is distinguished from an unresolved dependency by
            # CPython's own static name list, not by reading anything from disk.
            for specifier, package, provenance in (
                ("json", "json", "stdlib"),
                ("acme.vendor.client :: Client", "acme", "unresolved-dependency"),
            ):
                node = imports[("entry.py", specifier)]
                self.assertEqual("external", node["properties"]["resolution"])
                self.assertIsNone(node["properties"].get("resolved_path"))
                external = next(
                    by_id[edge["target"]] for edge in snapshot.edges
                    if edge["kind"] == "REFERS_TO" and edge["source"] == node["id"]
                )
                self.assertEqual("external-module", external["kind"])
                self.assertEqual(package, external["properties"]["package_name"])
                self.assertEqual(provenance, external["properties"]["provenance"])

            # `from a.b import c` where c is a name, not a submodule: the import
            # points at the declaration itself, which is what makes the call
            # resolver able to follow an aliased import to its definition.
            aliased = imports[("app/service.py", "app.util.text :: greet")]
            targets = [
                by_id[edge["target"]] for edge in snapshot.edges
                if edge["kind"] == "REFERS_TO" and edge["source"] == aliased["id"]
            ]
            self.assertEqual(
                {"file", "function"}, {node["kind"] for node in targets},
            )
            self.assertEqual("say_hello", aliased["label"])  # bound under its alias
            # A name the target module does not bind resolves to the module only.
            absent = imports[("app/util/nested/deep.py", "..text :: missing_symbol")]
            self.assertEqual(
                ["file"],
                [
                    by_id[edge["target"]]["kind"] for edge in snapshot.edges
                    if edge["kind"] == "REFERS_TO" and edge["source"] == absent["id"]
                ],
            )

            # __all__ on a package names submodules, not bindings; without __all__
            # the export surface is every public module-level name, which is what
            # `from module import *` binds.
            exports: dict[str, set[str]] = {}
            for edge in snapshot.edges:
                if edge["kind"] != "EXPORTS":
                    continue
                source = by_id[edge["source"]]["properties"]["file"]
                exports.setdefault(source, set()).add(edge["properties"]["name"])
            self.assertEqual({"service", "repository"}, exports["app/__init__.py"])
            self.assertEqual(
                {"greet", "shout", "normalize", "banner",
                 "SEPARATOR", "GREETING", "ARROW", "POINTER"},
                exports["app/util/text.py"],
            )
            # A class nested inside a class is not a module-level binding, so it is
            # not part of the module's export surface.
            self.assertIn("Shapes", exports["syntax_matrix.py"])
            self.assertNotIn("Nested", exports["syntax_matrix.py"])

            # open_file: the tool this step exists to unlock.
            gl = GraphLib({"nodes": list(snapshot.nodes), "edges": list(snapshot.edges)})
            file_node = _find_file_node(gl, path="app/service.py", file_id=None)
            self.assertIsNotNone(file_node)
            view = build_file_graph(gl, file_node)
            specifiers = {
                edge["properties"]["specifier"] for edge in view["edges"]
                if edge["kind"] == "DEPENDS_ON"
            }
            self.assertEqual(
                {"app.repository :: Repository", "app.repository :: open_repository",
                 "app.util.text :: greet", "app.util :: text"},
                specifiers,
            )
            self.assertEqual(
                {"Service", "build_service", "run", "unused_helper", "welcome",
                 "describe", "__init__"},
                {
                    node["label"] for node in view["nodes"]
                    if node["kind"] in ("function", "method", "class", "constructor")
                },
            )

    def test_python_scopes_closures_and_overrides(self) -> None:
        # symtable is CPython's own binding resolver, so `is_free` and
        # `is_declared_global` are facts rather than heuristics. What this test
        # pins is that the AST scope tree and the symtable block tree stay in
        # lockstep, since every classification below is wrong if they desync.
        fixtures = ROOT / "lachesis" / "frontends" / "python" / "fixtures"
        with tempfile.TemporaryDirectory() as output:
            self.run_command(
                sys.executable, "-m", "lachesis.frontends.python.build_graph",
                str(fixtures), output,
            )
            snapshot = load_snapshot(output)
            validate_snapshot(snapshot)
            manifest = snapshot.manifest
            self.assertEqual(0, manifest["scope_uncorrelated_file_count"])
            self.assertEqual(
                manifest["analyzed_file_count"],
                manifest["scope_correlated_file_count"],
            )
            by_id = {node["id"]: node for node in snapshot.nodes}

            bindings = {
                (node["properties"]["file"], node["label"]): node
                for node in snapshot.nodes if node["kind"] == "binding"
            }
            classification = {
                name: node["properties"]["binding_scope"]
                for (file, name), node in bindings.items()
                if file == "app/closures.py"
            }
            # One row per rule symtable decides and the AST cannot: a `global`
            # declaration, a `nonlocal` declaration, a plain function local, a
            # class bound inside a function, and a comprehension's own target.
            self.assertEqual("global", classification["COUNTER"])
            self.assertEqual("nonlocal", classification["total"])
            self.assertEqual("local", classification["advance"])
            self.assertEqual("local", classification["Holder"])
            self.assertEqual(
                "comprehension",
                bindings[("app/closures.py", "value")]["properties"]["scope_kind"],
            )
            # Every binding carries the attribution spine the navigation layer
            # climbs; a binding with no owning function would be unreachable.
            for (file, _name), node in bindings.items():
                if file != "app/closures.py":
                    continue
                self.assertIn("owner_function_id", node["properties"])

            captures = {
                (by_id[edge["source"]]["label"], by_id[edge["target"]]["label"]):
                    by_id[edge["target"]]
                for edge in snapshot.edges if edge["kind"] == "CAPTURES"
            }
            # A closure over an enclosing local, and over an enclosing parameter.
            self.assertIn(("advance", "total"), captures)
            self.assertIn(("advance", "step"), captures)
            self.assertEqual("binding", captures[("advance", "total")]["kind"])
            self.assertEqual("parameter", captures[("advance", "step")]["kind"])
            self.assertTrue(captures[("advance", "total")]["properties"]["is_captured"])
            # A class body is not a closure scope: `value` reaches the method from
            # the enclosing function directly, never through Holder.
            self.assertIn(("read", "value"), captures)
            self.assertEqual("parameter", captures[("read", "value")]["kind"])
            self.assertEqual(
                "shadowing",
                by_id[
                    captures[("read", "value")]["properties"]["owner_function_id"]
                ]["label"],
            )
            # Two levels of nesting: the innermost function captures across the one
            # between it and the binding.
            self.assertIn(("inner", "prefix"), captures)
            self.assertIn(("outer", "prefix"), captures)

            overrides = {
                (by_id[edge["source"]]["properties"]["owner_id"],
                 by_id[edge["source"]]["label"]): edge
                for edge in snapshot.edges if edge["kind"] == "OVERRIDES"
            }
            classes = {
                node["label"]: node["id"] for node in snapshot.nodes
                if node["kind"] == "class"
                and node["properties"]["file"] == "app/repository.py"
            }
            caching = classes["CachingRepository"]
            base = classes["Repository"]
            for member in ("fetch", "__init__"):
                edge = overrides[(caching, member)]
                # Single inheritance through a base the layout resolved is decided,
                # not guessed, so it is exact.
                self.assertEqual("exact", edge["properties"]["confidence"])
                self.assertEqual(base, by_id[edge["target"]]["properties"]["owner_id"])
            # A method with no inherited peer emits nothing.
            self.assertNotIn((base, "store"), overrides)

    def test_python_scope_correlation_gap_degrades_instead_of_crashing(self) -> None:
        # Correlation is advisory. The scope tree comes from the AST's own nesting
        # and is always complete; symtable only supplies classification. Feeding a
        # deliberately mismatched block tree is the honest way to force the gap,
        # because every module that ast.parse accepts, symtable also accepts.
        import ast

        from lachesis.frontends.python.declarations import DeclarationWalk
        from lachesis.frontends.python.emit import Graph, SourceFile, stable_id
        from lachesis.frontends.python.scopes import ScopeWalk, build_symbol_table

        text = "def holder(seed):\n    total = seed\n    return total\n"
        source = SourceFile(Path("mismatch.py"), "mismatch.py", text)
        module = ast.parse(text)
        graph = Graph()
        file_id = stable_id("file", source.display)
        graph.node(file_id, "file", source.display, **source.whole_file_position())
        walker = DeclarationWalk(graph, source, file_id, is_stub=False)
        walker.run(module)

        scopes = ScopeWalk(
            graph, source, file_id,
            walker.declarations_by_node, walker.parameters_by_function,
        )
        # A block tree built from different source: the keys cannot match.
        scopes.run(module, build_symbol_table("def other():\n    pass\n", Path("x.py")))

        self.assertFalse(scopes.correlated)
        self.assertEqual(1, scopes.uncorrelated_scopes)
        self.assertFalse(graph.nodes[file_id]["properties"]["symtable_correlated"])
        holder = walker.declarations_by_node[module.body[0]]
        self.assertFalse(graph.nodes[holder]["properties"]["symtable_correlated"])
        # Nothing is dropped. The AST-derived binding survives, and says plainly
        # that it is a fallback rather than symtable's answer.
        fallback = {
            node["label"]: node["properties"] for node in graph.nodes.values()
            if node["kind"] == "binding"
        }
        self.assertIn("total", fallback)
        self.assertEqual("conservative", fallback["total"]["confidence"])
        self.assertFalse(fallback["total"]["symtable_correlated"])
        self.assertEqual(holder, fallback["total"]["owner_function_id"])

    def test_python_call_resolution_table_and_call_navigation(self) -> None:
        # One assertion per row of the resolution table. The discipline being tested
        # is not "how many edges" but *which claim is made*: a decided target is an
        # INVOKES, an undecided one is either a capped set of MAY_INVOKE maybes or
        # no edge at all with the reason recorded on the call node. `confidence:
        # unresolved` describes an edge emitted on a guess; a missing edge is the
        # absence of a claim and is expressed through `resolution`.
        from lachesis.nav.graphlib import GraphLib
        from lachesis.nav.hubs import Hubs
        from lachesis.nav.symbol_index import build_index, _resolve, callers, callees

        fixtures = ROOT / "lachesis" / "frontends" / "python" / "fixtures"
        with tempfile.TemporaryDirectory() as output:
            self.run_command(
                sys.executable, "-m", "lachesis.frontends.python.build_graph",
                str(fixtures), output,
            )
            snapshot = load_snapshot(output)
            validate_snapshot(snapshot)
            self.assertEqual(0, snapshot.manifest["dropped_edge_count"])
            self.assertEqual("partial", snapshot.capabilities["calls"])
            self.assertEqual("partial", snapshot.capabilities["dynamic_behavior"])

            by_id = {node["id"]: node for node in snapshot.nodes}
            edges = list(snapshot.edges)

            def site(file: str, line: int, label: str) -> dict:
                found = [
                    node for node in snapshot.nodes
                    if node["kind"] in {"call", "construct"}
                    and node["properties"]["file"] == file
                    and node["properties"]["start_line"] == line
                    and node["label"] == label
                ]
                self.assertEqual(1, len(found), f"{file}:{line} {label}")
                return found[0]

            def targets_of(node: dict) -> set:
                # (edge kind, confidence, callee label, owning class or None)
                out = set()
                for edge in edges:
                    if edge["source"] != node["id"]:
                        continue
                    if edge["kind"] not in {"INVOKES", "MAY_INVOKE"}:
                        continue
                    target = by_id[edge["target"]]
                    owner = by_id.get(target["properties"].get("owner_id"))
                    out.add((
                        edge["kind"], edge["properties"]["confidence"],
                        target["label"], owner["label"] if owner else None,
                    ))
                return out

            # Every call site carries the attribution spine hubs and the indirect
            # half of callers/callees climb. Without it the ranking is garbage.
            for node in snapshot.nodes:
                if node["kind"] in {"call", "construct"}:
                    self.assertTrue(node["properties"]["owner_function_id"]
                                    or node["properties"]["owner_id"],
                                    f"{node['label']} has no owner")
                    self.assertTrue(node["properties"]["resolution"])

            # row: a module-level def bound exactly once, called from another module
            # through an import. Decided by the layout, so INVOKES at exact.
            welcome = site("app/service.py", 20, "say_hello")
            self.assertEqual("exact", welcome["properties"]["resolution"])
            self.assertEqual(
                {("INVOKES", "exact", "greet", None)}, targets_of(welcome))
            # ...and the caller declaration gets the decl->decl CALLS edge that
            # `callers`/`callees` read, only ever for a decided target.
            owner = welcome["properties"]["owner_function_id"]
            greet = next(node for node in snapshot.nodes
                         if node["label"] == "greet" and node["kind"] == "function")
            self.assertTrue(any(
                edge["kind"] == "CALLS" and edge["source"] == owner
                and edge["target"] == greet["id"] for edge in edges))

            # row: `Foo()` where Foo is an in-tree class. The site is a `construct`,
            # the call edge lands on __init__, and the class itself is named through
            # REFERS_TO rather than an invented edge kind no reader knows.
            built = site("app/repository.py", 46, "CachingRepository")
            self.assertEqual("construct", built["kind"])
            self.assertEqual(
                {("INVOKES", "exact", "__init__", "CachingRepository")},
                targets_of(built))
            self.assertTrue(any(
                edge["kind"] == "REFERS_TO" and edge["source"] == built["id"]
                and edge["properties"].get("reason") == "constructed-type"
                and by_id[edge["target"]]["label"] == "CachingRepository"
                for edge in edges))

            # row: the same name bound more than once at module level. Any binding
            # could be live at the call, so each is a maybe and none is the answer.
            rebound = site("app/dynamic.py", 52, "pick")
            self.assertEqual("rebound", rebound["properties"]["resolution"])
            self.assertEqual({("MAY_INVOKE", "conservative", "pick", None)},
                             targets_of(rebound))
            self.assertEqual(2, len(
                [e for e in edges if e["source"] == rebound["id"]
                 and e["kind"] == "MAY_INVOKE"]))

            # row: `self.m()` resolved through the lexical MRO. Left-to-right depth
            # first approximates a C3 linearization computed at run time from
            # objects this frontend never builds, so it is `high` and not `exact`.
            through_self = site("app/dynamic.py", 40, "self.fetch")
            self.assertEqual("lexical-mro", through_self["properties"]["resolution"])
            self.assertEqual(
                {("INVOKES", "high", "fetch", "RetryingRepository")},
                targets_of(through_self))

            # row: `super().m()` names the base implementation, which the layout
            # does decide. The bare `super` call beside it resolves to nothing,
            # which is the honest answer for a builtin with no in-tree definition.
            through_super = site("app/dynamic.py", 32, "super().fetch")
            self.assertEqual("super", through_super["properties"]["resolution"])
            self.assertEqual({("INVOKES", "exact", "fetch", "Repository")},
                             targets_of(through_super))

            # row: obj.m() on a value of unknown type, at or below the cap. The
            # method name is all there is to go on, so every in-tree m is a maybe.
            under = site("app/duck.py", 69, "handler.settle")
            self.assertEqual("candidates", under["properties"]["resolution"])
            self.assertEqual(2, under["properties"]["method_candidate_count"])
            self.assertEqual(
                {("MAY_INVOKE", "conservative", "settle", "Pair"),
                 ("MAY_INVOKE", "conservative", "settle", "Peer")},
                targets_of(under))

            # row: ...and above the cap, where "any of these nine" buries the
            # question instead of answering it. No edge, and the count on the node
            # so the silence is explained rather than merely absent.
            over = site("app/duck.py", 65, "handler.dispatch")
            self.assertEqual("over-cap", over["properties"]["resolution"])
            self.assertEqual(9, over["properties"]["method_candidate_count"])
            self.assertEqual(set(), targets_of(over))

            # row: getattr/eval/exec reach a name the source does not spell out. A
            # call edge would be fiction, so the site is located and marked for
            # lachesis/core/overlays/dynamic_behavior.py to consume.
            dynamic_sites = {}
            for label, line in (("getattr", 12), ("eval", 17), ("exec", 21)):
                node = site("app/dynamic.py", line, label)
                self.assertEqual("dynamic", node["properties"]["resolution"])
                self.assertEqual(set(), targets_of(node))
                dynamic_sites[label] = node["id"]
            marked = {
                node["properties"]["site_id"] for node in snapshot.nodes
                if node["kind"] == "dynamic-behavior"
            }
            self.assertEqual(set(dynamic_sites.values()), marked)
            self.assertTrue(all(any(
                edge["kind"] == "DYNAMIC_BEHAVIOR_AT" and edge["target"] == site_id
                for edge in edges) for site_id in dynamic_sites.values()))
            # The value getattr handed back is called on the next line. Nothing is
            # known about it, so no edge — but the local binding is named.
            indirect = site("app/dynamic.py", 13, "handler")
            self.assertEqual("local-value", indirect["properties"]["resolution"])
            self.assertEqual(set(), targets_of(indirect))

            # A def nested in a compound statement is an ordinary declaration:
            # nothing between it and the module opens a scope. Resolving a call to
            # it is the cheapest proof that it got a node at all, which a walk
            # reading only the top level of each body would not have given it.
            conditional = [node for node in snapshot.nodes
                           if node["kind"] == "function"
                           and node["label"] == "conditionally_declared"]
            self.assertEqual(1, len(conditional))
            conditional_call = [node for node in snapshot.nodes
                                if node["kind"] == "call"
                                and node["label"] == "conditionally_declared"]
            self.assertEqual(1, len(conditional_call))
            self.assertEqual(
                {("INVOKES", "exact", "conditionally_declared", None)},
                targets_of(conditional_call[0]))

            # Arguments bind to parameters positionally, the shape the shared
            # overlays and the TypeScript frontend already agree on.
            arguments = {
                node["properties"]["position"]: node for node in snapshot.nodes
                if node["kind"] == "argument"
                and node["properties"]["callsite_id"] == welcome["id"]
            }
            self.assertEqual({0}, set(arguments))
            # call (T2) -> argument (T3) crosses a tier, so the mechanical rule
            # wraps it as EXPANDS_TO(via=HAS_ARGUMENT); the position rides along.
            self.assertTrue(any(
                edge["kind"] == "EXPANDS_TO"
                and edge["properties"].get("via") == "HAS_ARGUMENT"
                and edge["source"] == welcome["id"]
                and edge["target"] == arguments[0]["id"]
                and edge["properties"]["position"] == 0 for edge in edges))
            bound = [by_id[edge["target"]] for edge in edges
                     if edge["kind"] == "ARGUMENT_BINDS_PARAMETER"
                     and edge["source"] == arguments[0]["id"]]
            self.assertEqual(["name"], [node["label"] for node in bound])
            self.assertEqual(greet["id"], bound[0]["properties"]["owner_function_id"])

            # dispatch.py transitively closes OVERRIDES and fans MAY_INVOKE out to
            # every implementation of a resolved target. That is what lets a
            # dynamically typed language resolve to the nearest definition and still
            # see the full override set, without the frontend guessing at any of it.
            enriched = semantic_snapshot_graph(snapshot)
            enriched_by_id = {node["id"]: node for node in enriched["nodes"]}
            fanned = set()
            for edge in enriched["edges"]:
                if edge["source"] != through_super["id"]:
                    continue
                if edge["properties"].get("reason") != \
                        "override-or-interface-implementation":
                    continue
                target = enriched_by_id[edge["target"]]
                owner = enriched_by_id.get(target["properties"].get("owner_id"))
                fanned.add((edge["kind"], target["label"],
                            owner["label"] if owner else None))
            self.assertEqual(
                {("MAY_INVOKE", "fetch", "CachingRepository"),
                 ("MAY_INVOKE", "fetch", "RetryingRepository")}, fanned)

            # The tools this step exists to unlock, across a module boundary.
            gl = GraphLib({"nodes": list(snapshot.nodes), "edges": list(snapshot.edges)})
            index = build_index(gl)

            def node_id_of(name: str) -> str:
                resolved = _resolve(gl, index, name)
                self.assertTrue(resolved, f"search found no node named {name!r}")
                return resolved[0]["node_id"]

            self.assertEqual(
                {("welcome", "app/service.py", "direct")},
                {(row["name"], row["file"], row["via"])
                 for row in callers(gl, node_id_of("greet"))})
            self.assertEqual(
                {("build_service", "app/service.py", "direct"),
                 ("welcome", "app/service.py", "indirect(may_invoke)")},
                {(row["name"], row["file"], row["via"])
                 for row in callees(gl, node_id_of("run"))})
            # normalize is called from three modules, one of them through a
            # relative import, so its callers prove resolution is not per-file.
            self.assertEqual(
                {"app/relative.py", "app/service.py", "app/util/nested/deep.py"},
                {row["file"] for row in callers(gl, node_id_of("normalize"))})
            # hubs ranks by call traffic, so the fixture chain has to appear at all
            # — an empty ranking is what a missing owner_function_id looks like.
            ranked = {row["name"] for row in Hubs(gl).top(20)}
            self.assertTrue({"run", "build_service", "open_repository"} <= ranked)

    def test_python_guard_shapes_classify_and_flag_the_unguarded_peer(self) -> None:
        # nav/guards.py reads the raw frontend guard edges, not the CFG overlay, and
        # classifies a function `guard` only when it both branches and throws. The C
        # frontend emits neither SHORT_CIRCUIT_* nor THROWS_VALUE, which is exactly
        # why C tops out at `validate`; the point of this step is that Python does
        # not, and that the peer differential can therefore name the sibling that
        # skipped the check its family performs.
        from lachesis.nav.graph_store import GraphStore
        from lachesis.nav.guards import GuardProfiles
        from lachesis.nav.siblings import SiblingDiff
        from lachesis.core.overlays.control_flow import CONTAINER_KINDS, TERMINAL_KINDS

        fixtures = ROOT / "lachesis" / "frontends" / "python" / "fixtures"
        with tempfile.TemporaryDirectory() as output:
            self.run_command(
                sys.executable, "-m", "lachesis.frontends.python.build_graph",
                str(fixtures), output,
            )
            snapshot = load_snapshot(output)
            validate_snapshot(snapshot)
            self.assertEqual(0, snapshot.manifest["dropped_edge_count"])
            self.assertEqual("partial", snapshot.capabilities["control_flow"])

            by_id = {node["id"]: node for node in snapshot.nodes}
            edges = list(snapshot.edges)

            # Every guard-shaped edge kind is actually emitted, and its endpoints
            # carry the attribution that buckets it by owning function. A guard edge
            # at module level genuinely has no owning function and says so by
            # omission; inside a body the property is mandatory, because an
            # unattributed edge is counted against whatever guards.py falls back to.
            for kind in ("CONDITION", "SHORT_CIRCUIT_LEFT", "SHORT_CIRCUIT_RIGHT",
                         "THROWS_VALUE", "EXCEPTION_BRANCH", "TRY_BODY"):
                found = [edge for edge in edges if edge["kind"] == kind]
                self.assertTrue(found, f"no {kind} edge was emitted")
                for edge in found:
                    for end in ("source", "target"):
                        node = by_id[edge[end]]
                        if node["kind"] in {"function", "method", "constructor"}:
                            continue
                        if node["properties"]["file"] != "app/guarded.py":
                            continue        # module-level shapes in other fixtures
                        self.assertTrue(
                            node["properties"].get("owner_function_id"),
                            f"{kind} {end} {node['label']!r} has no owning function")

            # control_flow.py builds its CFG from `control_kind` on statement nodes,
            # so the values have to come from its vocabulary rather than from a
            # parallel one this frontend invented.
            known = CONTAINER_KINDS | TERMINAL_KINDS | {
                "statement", "declaration", "expression", "break", "continue",
            }
            kinds = {node["properties"]["control_kind"] for node in snapshot.nodes
                     if node["kind"] == "statement"}
            self.assertTrue(kinds <= known, f"unknown control kinds: {kinds - known}")
            self.assertTrue({"if", "try", "while", "for-each", "switch", "return",
                             "throw"} <= kinds)
            # ...and the overlay does consume them: a CFG with no successor edges is
            # what emitting the property but not the AST_CHILD roles looks like.
            enriched = semantic_snapshot_graph(snapshot)
            self.assertTrue(
                [edge for edge in enriched["edges"] if edge["kind"] == "CFG_NEXT"])

            store = GraphStore(
                {"nodes": list(snapshot.nodes), "edges": list(snapshot.edges)})
            profiles = GuardProfiles(store)
            entries = {}
            for entry in store.entries:
                entries[(entry["name"], entry["file"])] = entry

            def profile_of(name: str) -> dict:
                entry = entries[(name, "app/guarded.py")]
                return profiles.profile(entry["node_id"])

            # validate-and-throw through two plain `if`s...
            mysql = profile_of("delete_mysql_record")
            self.assertEqual("guard", mysql["class"])
            self.assertEqual((2, 2), (mysql["conditions"], mysql["throws"]))
            # ...and through one `if` over an `or`, which reaches the same class
            # only because the short-circuit operands are edges here.
            postgres = profile_of("delete_postgres_record")
            self.assertEqual("guard", postgres["class"])
            self.assertEqual(2, postgres["short_circuits"])
            # the peer that does the same job and checks nothing
            self.assertEqual("passthrough", profile_of("delete_sqlite_record")["class"])
            # branch-without-throw stays `validate`: a conditional expression and a
            # comprehension `if` are conditions like any other.
            self.assertEqual("validate", profile_of("pick")["class"])
            self.assertEqual("validate", profile_of("enabled_names")["class"])
            # try/except/finally is handling, which is a separate axis from guarding
            handler = profile_of("read_config")
            self.assertEqual((2, 1), (handler["exception_branches"], handler["handles"]))

            # guards_top is the cold-start entry point, so an empty ranking is the
            # failure mode this step exists to remove.
            ranked = profiles.top(20)
            self.assertTrue(ranked)
            self.assertEqual("delete_mysql_record", ranked[0]["name"])

            # The peer differential: same verb, overlapping nouns, most of the
            # family guards, one does not, and it is named.
            diff = SiblingDiff(store).diff(entries[("delete_sqlite_record",
                                                    "app/guarded.py")])
            self.assertEqual(3, diff["family_size"])
            self.assertTrue(diff["verdict"]["peers_guard"])
            self.assertEqual(["delete_sqlite_record"],
                             [row["name"] for row in diff["flagged"]])
            self.assertEqual("delete_mysql_record",
                             diff["flagged"][0]["peer_guard"]["name"])

    def test_python_dataflow_carries_taint_end_to_end_and_answers_points_to(self) -> None:
        # The flow half of the navigation surface. `reaches` walks VALUE_FLOWS_TO
        # between value nodes, and `points_to`/`aliases` walk POINTS_TO, which no
        # frontend may emit: lachesis/core/overlays/heap.py derives it, and only
        # runs at all when an `allocation` node exists (heap.py:31-32). So the
        # assertion worth making is not that the right node kinds are present but
        # that the tools answer, which is why this drives them directly.
        from lachesis.nav.graph_store import GraphStore
        from lachesis.nav.reachability import Reachability

        fixtures = ROOT / "lachesis" / "frontends" / "python" / "fixtures"
        with tempfile.TemporaryDirectory() as output:
            self.run_command(
                sys.executable, "-m", "lachesis.frontends.python.build_graph",
                str(fixtures), output,
            )
            snapshot = load_snapshot(output)
            validate_snapshot(snapshot)
            self.assertEqual(0, snapshot.manifest["dropped_edge_count"])
            self.assertEqual("partial", snapshot.capabilities["direct_data_flow"])

            # heap_identity stays `none` on purpose: the overlay owns the result,
            # and a frontend claiming it would be claiming someone else's work.
            self.assertEqual("none", snapshot.capabilities["heap_identity"])

            graph = semantic_snapshot_graph(snapshot)
            store = GraphStore({"nodes": graph["nodes"], "edges": graph["edges"]})
            reach = Reachability(store)

            def find(kind, label, path="app/flow.py"):
                return [node for node in graph["nodes"]
                        if node["kind"] == kind and node["label"] == label
                        and node["properties"].get("file") == path]

            # A parameter through an f-string into a call argument, which is how
            # SQL injection is written in Python and the one path that has to work.
            source = find("parameter", "user_input")
            self.assertEqual(1, len(source))
            sink = find("argument", "query")
            self.assertEqual(1, len(sink))
            path = reach.reaches(source[0]["id"], sink[0]["id"])
            self.assertTrue(path["nodes"], "no path from user_input to the argument")
            reasons = {edge.get("reason") for edge in path["edges"]}
            self.assertIn("template-substitution", reasons)
            kinds = [node["kind"] for node in path["nodes"]]
            for expected in ("value", "definition", "read", "argument"):
                self.assertIn(expected, kinds)

            # sources_of is the same question asked backwards, and has to name the
            # parameter rather than stopping at the local it was copied into.
            origins = reach.sources_of(sink[0]["id"])
            self.assertIn(source[0]["id"],
                          {node["id"] for node in origins["nodes"]})

            # points_to: an allocation site gives the definition an object, which
            # is the answer no frontend outside TypeScript currently produces.
            rows = find("definition", "rows")
            self.assertTrue(rows)
            objects = list(store.index.targets(rows[0]["id"], "POINTS_TO"))
            self.assertTrue(objects, "points_to returned nothing for an allocation")
            self.assertEqual({"heap-object"}, {node["kind"] for node in objects})

            # A class instantiation is allocated and typed, so the object carries
            # the name of the class it is an instance of.
            instances = [node for node in graph["nodes"]
                         if node["kind"] == "allocation"
                         and node["properties"].get("allocation_kind") == "class-instance"
                         and node["properties"].get("file") == "app/flow.py"]
            self.assertEqual({"Row"},
                             {node["properties"]["allocated_type"] for node in instances})

            # aliases: `same = row` then `also = same` are three names for one
            # object, so each definition reaches the other two through the heap.
            names = {}
            for label in ("row", "same", "also"):
                found = [node for node in find("definition", label)
                         if node["properties"].get("origin") != "unknown"]
                self.assertTrue(found, f"no definition of {label}")
                names[label] = found[0]["id"]
            for label, node_id in names.items():
                siblings = {
                    other["id"]
                    for heap in store.index.targets(node_id, "POINTS_TO")
                    for other in store.index.sources(heap["id"], "POINTS_TO")
                }
                for peer, peer_id in names.items():
                    if peer != label:
                        self.assertIn(peer_id, siblings,
                                      f"{label} is not aliased with {peer}")

            # A parameter's definition says `parameter` exactly, because
            # branch_history.py:173 and heap.py:100 both key on that literal string.
            definitions = [node for node in graph["nodes"]
                           if node["kind"] == "definition"
                           and node["properties"].get("origin") == "parameter"]
            self.assertTrue(definitions)

            # self.x = param in a constructor, the shape the C frontend emits and
            # this file already asserts of it.
            stores = [edge for edge in graph["edges"]
                      if edge["kind"] == "WRITES_PARAMETER_PROPERTY"]
            self.assertTrue(stores, "no WRITES_PARAMETER_PROPERTY was emitted")

    def test_python_unparseable_file_keeps_its_file_node(self) -> None:
        # A syntax error must not evict the file: it still has to appear in search,
        # open_file and open_folder. Written to a temporary tree rather than
        # committed, so run_project(ROOT) never walks a deliberately broken file.
        with tempfile.TemporaryDirectory() as project, \
                tempfile.TemporaryDirectory() as output:
            root = Path(project)
            (root / "good.py").write_text("def kept():\n    return 1\n", encoding="utf-8")
            (root / "broken.py").write_text("def broken(:\n", encoding="utf-8")
            self.run_command(
                sys.executable, "-m", "lachesis.frontends.python.build_graph",
                str(root), output,
            )
            snapshot = load_snapshot(output)
            validate_snapshot(snapshot)
            self.assertEqual(2, snapshot.manifest["root_file_count"])
            self.assertEqual(1, snapshot.manifest["analyzed_file_count"])
            self.assertEqual(1, snapshot.manifest["failed_file_count"])
            self.assertEqual(1, snapshot.manifest["diagnostic_count"])
            files = {
                node["properties"]["file"] for node in snapshot.nodes
                if node["kind"] == "file"
            }
            self.assertEqual({"good.py", "broken.py"}, files)
            diagnostic = next(
                node for node in snapshot.nodes if node["kind"] == "diagnostic"
            )
            self.assertEqual("syntax-error", diagnostic["properties"]["category"])
            self.assertEqual("broken.py", diagnostic["properties"]["file"])
            # One unparseable file collapses the parse-dependent capability claim.
            self.assertEqual("partial", snapshot.capabilities["syntax"])

    def test_nav_compact_render_and_mcp_format(self) -> None:
        # Spec 1 + Spec 2: the MCP nav tools render compact text for LLM consumers
        # (no node_id / absolute paths / null; lists paginated), preserve byte-identical
        # JSON for programmatic callers, and drive over the real stdio JSON-RPC server.
        # fixtures_opsreg is used because it carries an ops-struct dispatch table, so the
        # `via=ops-struct[.slot]` reverse-dispatch differentiator can be asserted to
        # survive compaction.
        import sys as _sys
        import types as _types
        from pathlib import Path as _Path
        _sys.path.insert(0, str(_Path(ROOT)))
        from lachesis.nav.graphlib import GraphLib
        from lachesis.nav.graph_store import GraphStore
        from lachesis.nav.reachability import Reachability
        from lachesis.nav.hubs import Hubs
        from lachesis.nav.symbol_index import (
            build_index, _resolve, callers as _callers, search_page,
        )
        from lachesis.nav import mcp_server, render as render_mod

        with tempfile.TemporaryDirectory() as output:
            self.run_command(
                sys.executable, "lachesis/frontends/c/build_graph.py",
                "lachesis/frontends/c/fixtures_opsreg", output,
            )
            snapshot = load_snapshot(output)
            validate_snapshot(snapshot)
            graph = {"nodes": list(snapshot.nodes), "edges": list(snapshot.edges)}

            store = GraphStore(graph)
            mcp_server._CTX = _types.SimpleNamespace(
                store=store, reach=Reachability(store), hubs=Hubs(store.gl))
            mcp_server._PROFILE = "all"
            mcp_server._DEFAULT_FORMAT = "text"

            # -- compaction: no node_id / no absolute path / no null in text --------
            for tool, args in (("hubs", {"n": 10}), ("callers", {"name": "drv_start"}),
                               ("callees", {"name": "init_driver"}),
                               ("search", {"name": "drv"}),
                               ("read_body", {"name": "drv_start"})):
                text = mcp_server.call_tool(tool, args, format="text")
                self.assertNotIn("node_id", text, f"{tool}: node_id leaked into text")
                self.assertNotIn("/Users/", text, f"{tool}: absolute path leaked into text")
                self.assertNotIn("null", text, f"{tool}: null leaked into text")

            # -- the reverse-dispatch differentiator survives compaction -----------
            callers_text = mcp_server.call_tool("callers", {"name": "drv_start"}, format="text")
            self.assertIn("via=ops-struct[.start]", callers_text)

            # -- JSON byte-identical to the pre-render behavior --------------------
            gl = store.gl
            idx = build_index(gl)
            seed = _resolve(gl, idx, "drv_start")[0]["node_id"]
            self.assertEqual(
                json.dumps({"callers": _callers(gl, seed, direct_only=False), "of": "drv_start"}),
                mcp_server.call_tool("callers", {"name": "drv_start"}, format="json"),
                "callers JSON must be byte-identical to the legacy dump")
            hub_rows = Hubs(gl).top(10)
            self.assertEqual(
                json.dumps({"move": "hubs", "count": len(hub_rows), "ranked": hub_rows}),
                mcp_server.call_tool("hubs", {"n": 10}, format="json"),
                "hubs JSON must be byte-identical to the legacy dump")
            self.assertEqual(
                json.dumps(search_page(store.entries, "drv", "fuzzy", 25, 0)),
                mcp_server.call_tool("search", {"name": "drv"}, format="json"),
                "search JSON must be byte-identical to the legacy dump")

            # -- token reduction (char/4 proxy) >= 3x on hubs ----------------------
            j = mcp_server.call_tool("hubs", {"n": 10}, format="json")
            t = mcp_server.call_tool("hubs", {"n": 10}, format="text")
            self.assertGreaterEqual(len(j) / max(1, len(t)), 3.0,
                                    "compact text must be >=3x smaller than JSON")

            # -- truncation is text-only: cap 40 + footer; JSON returns all --------
            big = {"move": "hubs", "count": 45, "ranked": [
                {"name": f"fn{i}", "file": "a/b/c.c", "line": i,
                 "fan_in": 1, "fan_out": 0, "flags": []} for i in range(45)]}
            rendered = render_mod.render("hubs", big)
            self.assertIn("… +5 more (offset=40)", rendered)
            self.assertEqual(40, sum(1 for ln in rendered.splitlines()
                                     if ln.strip().startswith(tuple("0123456789"))))

            # -- Spec 2: real stdio JSON-RPC server, scripted client ---------------
            canon = _Path(output) / "canonical.kuzu"
            from lachesis.kuzu_store import write_kuzu_graph
            write_kuzu_graph(graph, [], str(canon),
                             prune=False, elide_constants=False)
            env = dict(__import__("os").environ, LACHESIS_GRAPH=str(canon),
                       LACHESIS_FORMAT="text")
            proc = subprocess.Popen(
                [sys.executable, "lachesis/nav/mcp_server.py"], stdin=subprocess.PIPE,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
                cwd=str(ROOT), env=env)
            try:
                def rpc(mid, method, params=None):
                    proc.stdin.write(json.dumps(
                        {"jsonrpc": "2.0", "id": mid, "method": method,
                         "params": params or {}}) + "\n")
                    proc.stdin.flush()
                    return json.loads(proc.stdout.readline())

                init = rpc(1, "initialize", {"protocolVersion": "2024-11-05"})
                self.assertEqual("nav-reasoning", init["result"]["serverInfo"]["name"])
                tools = rpc(2, "tools/list")["result"]["tools"]
                names = [t["name"] for t in tools]
                self.assertIn("load_graph", names)
                self.assertTrue(all("format" in t["inputSchema"]["properties"]
                                    for t in tools if t["name"] != "load_graph"),
                                "every graph tool advertises a format field")
                hubs_call = rpc(3, "tools/call", {"name": "hubs", "arguments": {"n": 3}})
                self.assertIn("HUBS", hubs_call["result"]["content"][0]["text"])
                # load_graph re-attaches the same target and reports node count.
                lg = rpc(4, "tools/call", {"name": "load_graph",
                                           "arguments": {"path": str(canon)}})
                self.assertIn("load_graph", lg["result"]["content"][0]["text"])
                proc.stdin.close()
                self.assertEqual(0, proc.wait(timeout=10))
            finally:
                if proc.poll() is None:
                    proc.kill()
                    proc.wait(timeout=5)
                for stream in (proc.stdout, proc.stderr):
                    if stream and not stream.closed:
                        stream.close()

    def test_kuzu_store_round_trips_the_source_graph_property_for_property(self) -> None:
        # The store's contract, stated at its strongest: what comes back out of
        # `materialize_graph` is what went in. Every other store test compares two
        # stores to each other (a bug symmetric across both writes passes clean) or
        # compares nav *tool output* (a lost property only shows if some tool happens
        # to surface it). This one compares against the source graph itself, so it is
        # the guardrail for any change to how properties are laid out on disk —
        # notably the promoted-column de-dup, where `props` no longer carries the
        # whole dict and the reader unions the typed columns back in.
        #
        # A parity build (prune + constant elision OFF) is the lossless setting: no
        # node is dropped and no constant is elided, so the reconstruction must be
        # exact. Key *order* inside `properties` is deliberately not asserted — dicts
        # compare order-insensitively and nothing in-tree depends on the order, but a
        # column-union reader does not preserve it.
        import os as _os
        import sys as _sys
        from pathlib import Path as _Path
        _sys.path.insert(0, str(_Path(ROOT)))
        from lachesis.nav.graph_store import GraphStore
        from lachesis.nav.kuzu_index import materialize_graph
        from lachesis.kuzu_store import write_kuzu_graph

        with tempfile.TemporaryDirectory() as output:
            self.run_command(
                sys.executable, "lachesis/frontends/c/build_graph.py",
                "lachesis/frontends/c/fixtures_opsreg", output,
            )
            snapshot = load_snapshot(output)
            validate_snapshot(snapshot)
            graph = {"nodes": list(snapshot.nodes), "edges": list(snapshot.edges)}

            store_dir = _os.path.join(output, "kuzu_roundtrip")
            write_kuzu_graph(graph, None, store_dir,
                             prune=False, elide_constants=False)
            restored = materialize_graph(GraphStore.load(store_dir).index)

            self.assertEqual(len(graph["nodes"]), len(restored["nodes"]))
            by_id = {node["id"]: node for node in restored["nodes"]}
            self.assertEqual(set(by_id), {node["id"] for node in graph["nodes"]})
            for node in graph["nodes"]:
                back = by_id[node["id"]]
                for field in ("kind", "label"):
                    self.assertEqual(node.get(field), back.get(field),
                                     f"{node['id']}: {field} changed in the store")
                self.assertEqual(node.get("properties") or {}, back["properties"],
                                 f"{node['id']}: properties changed in the store")

            def edge_key(edge):
                return (edge["kind"], edge["source"], edge["target"],
                        json.dumps(edge.get("properties") or {}, sort_keys=True))

            self.assertEqual(sorted(edge_key(e) for e in graph["edges"]),
                             sorted(edge_key(e) for e in restored["edges"]),
                             "edges changed in the store")

    def test_nav_parity_in_memory_graph_vs_kuzu_store(self) -> None:
        # The Kùzu store answers every nav tool identically to the same graph held in
        # memory as a dict. A parity build (prune + constant elision OFF) must
        # reconstruct the canonical node/edge dicts exactly, so the full nav set
        # matches byte-for-byte (order-normalized — the two backends may enumerate a
        # set in a different order, but the *content* is identical). A pruned build
        # must still answer the lossless nav set (read_body reads source by offset,
        # not the dropped token/span nodes).
        import os as _os
        import sys as _sys
        import types as _types
        from pathlib import Path as _Path
        _sys.path.insert(0, str(_Path(ROOT)))
        from lachesis.nav.graph_store import GraphStore
        from lachesis.nav.reachability import Reachability
        from lachesis.nav.hubs import Hubs
        from lachesis.nav.guards import GuardProfiles
        from lachesis.nav.call_roles import CallRoles
        from lachesis.nav.siblings import SiblingDiff
        from lachesis.nav import mcp_server
        from lachesis.kuzu_store import write_kuzu_graph

        def _run_nav(store, calls):
            # each store drives the same global nav dispatch, one at a time. The
            # security tools (guards/guards_top/call_roles/siblings) recompute from
            # base facts, so the injected context mirrors the real `_Ctx` — a Kùzu
            # store with an empty overlay must answer them identically to the in-memory
            # store, proving the overlay is a cache, not a dependency.
            guards = GuardProfiles(store)
            mcp_server._CTX = _types.SimpleNamespace(
                store=store, reach=Reachability(store), hubs=Hubs(store.gl),
                guards=guards, roles=CallRoles(store, guards=guards),
                siblings=SiblingDiff(store))
            mcp_server._PROFILE = "all"
            mcp_server._DEFAULT_FORMAT = "json"
            return {label: mcp_server.call_tool(tool, args, format="json")
                    for label, tool, args in calls}

        def _norm(payload):
            # order-invariant: sort every nested list so set-shaped results
            # (which the two backends may enumerate in a different order)
            # compare equal while any real content difference still shows.
            def walk(x):
                if isinstance(x, list):
                    return sorted((walk(v) for v in x),
                                  key=lambda e: json.dumps(e, sort_keys=True))
                if isinstance(x, dict):
                    return {k: walk(v) for k, v in x.items()}
                return x
            return walk(json.loads(payload))

        with tempfile.TemporaryDirectory() as output:
            # fixtures_opsreg carries an ops-struct dispatch table, so the nav set
            # exercises MAY_INVOKE / reverse-dispatch alongside CALLS and flow.
            self.run_command(
                sys.executable, "lachesis/frontends/c/build_graph.py",
                "lachesis/frontends/c/fixtures_opsreg", output,
            )
            snapshot = load_snapshot(output)
            validate_snapshot(snapshot)
            graph = {"nodes": list(snapshot.nodes), "edges": list(snapshot.edges)}

            memory_store = GraphStore(graph)
            # derive valid file / folder targets from the graph itself, so the
            # same args exercise a real answer on both backends.
            file_node = next(iter(memory_store.index.nodes_of_kind("file")), None)
            self.assertIsNotNone(file_node, "fixture must contain a file node")
            file_path = (file_node.get("properties") or {}).get("file")
            self.assertTrue(file_path, "file node must carry its path")
            root = file_path.rsplit("/", 1)[0] if "/" in file_path else file_path

            calls = [
                ("hubs", "hubs", {"n": 20}),
                ("search", "search", {"name": "drv"}),
                ("callers", "callers", {"name": "drv_start"}),
                ("callees", "callees", {"name": "init_driver"}),
                ("read_body", "read_body", {"name": "drv_start"}),
                ("flow", "flow", {"seed": "drv_start"}),
                ("reaches", "reaches", {"src": "drv_start", "sink": "init_driver"}),
                ("sources_of", "sources_of", {"sink": "init_driver"}),
                ("points_to", "points_to", {"value": "drv_start"}),
                ("aliases", "aliases", {"value": "drv_start"}),
                ("open_file", "open_file", {"file": file_path}),
                ("open_folder", "open_folder", {"root": root}),
                # security tools — recompute guard/role/sibling signals from base
                # facts (CONDITION/SHORT_CIRCUIT/THROWS_VALUE/CALLS edges); parity
                # here proves they need no overlay to answer identically off Kùzu.
                ("guards_top", "guards_top", {"n": 20}),
                ("guards", "guards", {"fn": "drv_start"}),
                ("call_roles", "call_roles", {"fn": "drv_start"}),
                ("siblings", "siblings", {"sym": "drv_start"}),
            ]
            memory_out = _run_nav(memory_store, calls)

            # -- parity build (prune + elide OFF): full nav set identical ----------
            parity_dir = _os.path.join(output, "kuzu_parity")
            write_kuzu_graph(graph, None, parity_dir,
                             prune=False, elide_constants=False)
            parity_out = _run_nav(GraphStore.load(parity_dir), calls)
            for label, _tool, _args in calls:
                self.assertEqual(
                    _norm(memory_out[label]), _norm(parity_out[label]),
                    f"{label}: Kùzu parity store must match the in-memory store")

            # -- pruned build: the lossless nav set still answers identically ------
            # prune drops pure-lexical token/source-span nodes (and dangling edges);
            # read_body reads the source file by offset, so this set is unaffected.
            lossless = ("hubs", "search", "callers", "callees", "read_body")
            pruned_dir = _os.path.join(output, "kuzu_pruned")
            write_kuzu_graph(graph, None, pruned_dir,
                             prune=True, elide_constants=True)
            pruned_out = _run_nav(GraphStore.load(pruned_dir),
                                  [c for c in calls if c[0] in lossless])
            for label in lossless:
                self.assertNotIn('"error"', pruned_out[label],
                                 f"{label}: pruned Kùzu store must still answer")
                self.assertEqual(
                    _norm(memory_out[label]), _norm(pruned_out[label]),
                    f"{label}: pruned Kùzu store must match the in-memory store")

            # -- guard-rich synthetic graph: exercise the NONZERO guard-count path --
            # The C fixtures emit no CONDITION/THROWS_VALUE edges (those come from
            # TS control-flow overlays), so the parity above only proves the empty
            # guard path. Guard kinds are cold (not HOT_REL_KINDS): they live in the
            # catch-all EDGE table and edges_of_kind matches them by `semantic_kind`.
            # This synthetic graph drives real, nonzero guard counts through that
            # path so a store vs in-memory divergence in guard attribution would show.
            fn = {"id": "fn1", "kind": "function", "label": "validate_input",
                  "properties": {"file": "g.c", "start_line": 1}}
            stmt = {"id": "s1", "kind": "statement", "label": "if",
                    "properties": {"file": "g.c", "start_line": 2,
                                   "owner_function_id": "fn1"}}
            callee = {"id": "authn", "kind": "function", "label": "authenticate",
                      "properties": {"file": "g.c", "start_line": 9}}
            guard_graph = {
                "nodes": [fn, stmt, callee],
                # guard edges (cold → catch-all EDGE table), source owned by fn1:
                "edges": [
                    {"kind": "CONDITION", "source": "s1", "target": "fn1", "properties": {}},
                    {"kind": "THROWS_VALUE", "source": "s1", "target": "fn1", "properties": {}},
                    {"kind": "SHORT_CIRCUIT_LEFT", "source": "s1", "target": "fn1", "properties": {}},
                    # a hot CALLS edge so call_roles/security_weight also runs:
                    {"kind": "CALLS", "source": "fn1", "target": "authn", "properties": {}},
                ],
            }
            guard_calls = [
                ("guards_top", "guards_top", {"n": 20}),
                ("guards", "guards", {"fn": "validate_input"}),
                ("call_roles", "call_roles", {"fn": "validate_input"}),
            ]
            guard_memory = _run_nav(GraphStore(guard_graph), guard_calls)
            # sanity: the counting path actually fired (not a vacuous all-zero match)
            gsig = json.loads(guard_memory["guards"])["guard_signal"]
            self.assertEqual("guard", gsig["class"])
            self.assertGreaterEqual(gsig["conditions"], 1)
            self.assertGreaterEqual(gsig["throws"], 1)

            guard_dir = _os.path.join(output, "kuzu_guard")
            write_kuzu_graph(guard_graph, None, guard_dir,
                             prune=False, elide_constants=False)
            guard_kuzu = _run_nav(GraphStore.load(guard_dir), guard_calls)
            for label, _tool, _args in guard_calls:
                self.assertEqual(
                    _norm(guard_memory[label]), _norm(guard_kuzu[label]),
                    f"{label}: Kùzu must match the in-memory store on the nonzero guard-count path")

    @requires_corpus
    def test_core_only_store_defers_the_overlay_tier_and_nav_rebuilds_it(self) -> None:
        # Lever 1. A default build writes the core tier only; the overlay dataflow tier
        # is a pure function of that core plus the store manifest, so nav rebuilds it on
        # first use and caches it beside the store. Three claims:
        #   1. the core store holds *zero* overlay-tier nodes and edges, by kind;
        #   2. the lazily rebuilt tier equals the eagerly enriched one node for node and
        #      edge for edge — deferring costs no precision;
        #   3. the second load hits the cache, and a cache that does not match the
        #      core's content hash is rejected rather than served stale.
        import sys as _sys
        from pathlib import Path as _Path
        _sys.path.insert(0, str(_Path(ROOT)))
        from lachesis.nav.graph_store import GraphStore, enriched_store_path
        from lachesis.nav.kuzu_index import materialize_graph
        from lachesis.kuzu_store import (read_store_manifest, store_manifest_file,
                                         write_kuzu_graph)
        from lachesis.pipeline import _enrich_graph

        overlay_node_kinds = {
            "source", "sink", "taint-reach", "heap-object", "heap-location",
            "call-context", "context-parameter", "context-return", "phi", "route",
            "async-event", "boundary", "module-state", "singleton",
            "unreachable-region", "function-effect", "taint-budget-note",
        }
        # Overlay-*exclusive* kinds only. MAY_INVOKE and VALUE_FLOWS_TO look like
        # dataflow but the TypeScript frontend emits them in the core tier as well, so
        # asserting their absence would assert something false.
        overlay_edge_kinds = {
            "TAINT_SOURCE", "TAINT_SINK", "TAINT_FLOWS_TO", "TAINT_REACHES",
            "ROUTE_HANDLED_BY", "POINTS_TO", "CONTEXT_CALLS", "CONTEXT_RETURNS",
            "CONTEXTUALIZES", "BINDS_PARAMETER", "READS_HEAP", "WRITES_HEAP",
            "APPLIES_EFFECT", "ENTRY_POINT_OF",
        }

        with tempfile.TemporaryDirectory() as output:
            core_dir = os.path.join(output, "core.kuzu")
            eager_dir = os.path.join(output, "eager.kuzu")
            # one compile, two consumers: the same core graph is both what the store
            # holds and what the eager reference is enriched from, so the comparison
            # isolates *when* enrichment runs and nothing else.
            core, snapshots = run_project(str(CORPUS), os.path.join(output, "fe"),
                                          enrich=False)
            write_kuzu_graph(core, snapshots, core_dir, prune=False, enriched=False)
            write_kuzu_graph(_enrich_graph(core, snapshots), snapshots, eager_dir,
                             prune=False, enriched=True)

            def _kinds(path):
                graph = materialize_graph(_open_index(path))
                return ({node["kind"] for node in graph["nodes"]},
                        {edge["kind"] for edge in graph["edges"]})

            def _open_index(path):
                from lachesis.nav.kuzu_index import KuzuGraphIndex
                return KuzuGraphIndex(path)

            node_kinds, edge_kinds = _kinds(core_dir)
            self.assertEqual(set(), node_kinds & overlay_node_kinds)
            self.assertEqual([], [k for k in node_kinds if k.startswith("cfg-")])
            self.assertEqual(set(), edge_kinds & overlay_edge_kinds)
            # and the eager store is a real positive control: the kinds above are not
            # simply absent from this corpus.
            eager_node_kinds, eager_edge_kinds = _kinds(eager_dir)
            self.assertTrue(eager_node_kinds & overlay_node_kinds)
            self.assertTrue(eager_edge_kinds & overlay_edge_kinds)

            manifest = read_store_manifest(core_dir)
            self.assertFalse(manifest["enriched"])
            self.assertTrue(manifest["core_content_hash"])

            def _rebuild():
                store = GraphStore.load(core_dir)
                self.assertFalse(store.dataflow_ready)
                store.ensure_dataflow_tier()
                self.assertTrue(store.dataflow_ready)
                return materialize_graph(store.index)

            lazy = _rebuild()
            reference = materialize_graph(_open_index(eager_dir))
            self.assertEqual(reference["nodes"], lazy["nodes"])
            self.assertEqual(reference["edges"], lazy["edges"])

            # the cache is keyed to this core, and a second load opens it directly
            cache = enriched_store_path(core_dir)
            self.assertEqual(manifest["core_content_hash"],
                             read_store_manifest(cache)["core_content_hash"])
            self.assertTrue(GraphStore.load(core_dir).dataflow_ready)

            # a cache that does not describe this core is a miss, not a stale hit
            tampered = read_store_manifest(cache)
            tampered["core_content_hash"] = "0" * 64
            with open(store_manifest_file(cache), "w", encoding="utf-8") as handle:
                json.dump(tampered, handle)
            self.assertFalse(GraphStore.load(core_dir).dataflow_ready)

    def test_package_detection_assigns_each_file_to_its_deepest_package(self) -> None:
        # Lever 3's partitioning unit. The two-package workspace fixture has a
        # package.json at the root *and* one per package, so a shallowest-match rule
        # would put everything in the root bucket and the build would not parallelize.
        from lachesis.packages import ROOT_PACKAGE_KEY, detect_packages
        from lachesis.pipeline import source_inventory

        workspace = WORKSPACE_FIXTURE
        buckets = detect_packages(str(workspace), source_inventory(str(workspace)))
        self.assertEqual([".", "packages/api", "packages/core"], list(buckets))
        self.assertEqual(
            [str(workspace / "packages" / "api" / "package.json"),
             str(workspace / "packages" / "api" / "src" / "index.ts")],
            buckets["packages/api"])
        # the root package.json is a workspace manifest, so the root bucket holds only
        # the files no package claims — and it is a bucket, not a discard pile
        self.assertEqual([str(workspace / "package.json"),
                          str(workspace / "tsconfig.json")], buckets["."])
        self.assertNotIn(ROOT_PACKAGE_KEY, buckets)

    def test_parallel_package_build_matches_serial_over_the_same_partition(self) -> None:
        # Lever 3. The claim is narrow and deliberate: a pooled per-package build equals
        # a *serial per-package* build exactly. It is NOT a claim that either equals a
        # whole-repo single-program build — each package compiles as its own program, so
        # types resolve within a package rather than across the tree, and that is why
        # the flag is opt-in. The whole-repo comparison at the end of this test measures
        # that gap rather than asserting it away.
        from lachesis.pipeline import run_project, run_project_parallel

        workspace = str(WORKSPACE_FIXTURE)
        with tempfile.TemporaryDirectory() as output:
            pooled, pooled_snaps, pooled_dropped = run_project_parallel(
                workspace, os.path.join(output, "pooled"), enrich=False)
            serial, _, serial_dropped = run_project_parallel(
                workspace, os.path.join(output, "serial"), enrich=False, max_workers=1)

            self.assertEqual(2, len(pooled_snaps))  # it really did split the work
            self.assertEqual(serial, pooled)
            self.assertEqual(serial_dropped, pooled_dropped)

            # the cross-package call survives the union: its callee id is the same id
            # the owning package emitted, so the merge resolves it rather than dropping it
            labels = {node["id"]: node["label"] for node in pooled["nodes"]}
            cross = [edge for edge in pooled["edges"]
                     if edge["kind"] == "CALLS"
                     and labels.get(edge["target"]) == "principalFor"]
            self.assertTrue(cross, "the api -> core call edge must survive the merge")

            # every file is named once, project-relative. Each package compiles from its
            # own root, so the frontend would otherwise report both as `src/index.ts` —
            # one user-facing path for two different files.
            files = sorted(node["label"] for node in pooled["nodes"]
                           if node["kind"] == "file"
                           and not node["label"].startswith(os.sep))
            self.assertEqual(["packages/api/src/index.ts",
                              "packages/core/src/index.ts"], files)

            whole, _ = run_project(workspace, os.path.join(output, "whole"),
                                   enrich=False)
            self.assertEqual(whole["nodes"], pooled["nodes"])
            triples = lambda graph: {(e["kind"], e["source"], e["target"])
                                     for e in graph["edges"]}
            # the gap is one-directional: per-package resolution can *miss* an edge the
            # whole-repo program recovers, but it must never invent one.
            self.assertEqual(set(), triples(pooled) - triples(whole))

    def test_canonical_module_initialization_overlay(self) -> None:
        semantics, _ = run_project(
            str(ROOT / "lachesis" / "frontends" / "typescript" / "fixtures" / "semantics")
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
            str(ROOT / "lachesis" / "frontends" / "typescript" / "fixtures" / "module_cycle")
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
            str(ROOT / "lachesis" / "frontends" / "typescript" / "fixtures" / "control_flow")
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
            str(ROOT / "lachesis" / "frontends" / "typescript" / "fixtures" / "branch_history")
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
            str(ROOT / "lachesis" / "frontends" / "typescript" / "fixtures" / "heap")
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
            str(ROOT / "lachesis" / "frontends" / "typescript" / "fixtures" / "async_events")
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
            str(ROOT / "lachesis" / "frontends" / "typescript" / "fixtures" / "dispatch")
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
            str(ROOT / "lachesis" / "frontends" / "typescript" / "fixtures" / "dynamic")
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
            self.assertEqual({"typescript-compiler-api", "clang-c", "cpython-ast"}, {
                snapshot.frontend_id for snapshot in snapshots
            })
            frontend_ids = {
                node["properties"].get("frontend_id") for node in graph["nodes"]
            }
            self.assertTrue(
                {"typescript-compiler-api", "clang-c", "cpython-ast"}
                .issubset(frontend_ids))
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
                {"c", "typescript", "python"}.issubset(
                    overview["project"]["languages"]),
            )
            self.assertEqual(
                len(graph["nodes"]), overview["node_index"]["count"],
            )

    @requires_corpus
    def test_typescript_compiler_facts_feed_semantic_overlays(self) -> None:
        with tempfile.TemporaryDirectory() as output:
            graph, snapshots = run_project(str(CORPUS), output)
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
            if CORPUS_IS_FIXTURE:
                self.assertEqual(CORPUS_FUNCTIONS, {
                    function["name"]
                    for info in files for function in info["functions"]
                })
                self.assertEqual(CORPUS_FUNCTION_CALLS, totals["function_calls"])
            callee_names = {
                call.get("callee") for info in files
                for call in info["function_calls"]
            }
            self.assertLessEqual(
                {"findById", "principalKey", "decodeSession"}, callee_names,
            )
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
            self.assertFalse((ROOT / "lachesis" / "variable_analysis.py").exists())
            self.assertFalse((ROOT / "lachesis" / "scope_utils.py").exists())
            self.assertFalse((ROOT / "lachesis" / "dynamic_analysis.py").exists())
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

    @requires_corpus
    def test_file_compatibility_view_is_compiler_backed(self) -> None:
        paths = walk(str(CORPUS))
        files = analyze_files(paths)
        principal = read_file(str(CORPUS / "auth" / "principal.ts"))
        if CORPUS_IS_FIXTURE:
            self.assertEqual(CORPUS_FILES, {
                os.path.relpath(info["path"], CORPUS) for info in files
            })
            self.assertEqual(CORPUS_FUNCTIONS, {
                function["name"] for info in files for function in info["functions"]
            })
            self.assertEqual(
                CORPUS_FUNCTION_CALLS,
                sum(len(info["function_calls"]) for info in files),
            )
        self.assertEqual(
            {"decodeSession", "resolvePrincipal", "principalKey"},
            {function["name"] for function in principal["functions"]},
        )


if __name__ == "__main__":
    unittest.main()
