import unittest
from collections import defaultdict

from .reaching_def import ReachingDef


class _Index:
    def __init__(self, edges):
        self._edges = edges

    def outgoing_of_kind(self, source, kind):
        return [edge for edge in self._edges
                if edge["source"] == source and edge["kind"] == kind]


class _Substrate:
    """Small semantic graph fixture, independent of the C oracle and Kuzu."""

    def __init__(self):
        self.nodes = {}
        self.ast_children = defaultdict(list)
        self.ast_parent = {}
        self.refers = {}
        self.edges = []
        self.idx = _Index(self.edges)

    def add(self, node, kind, offset, label=None, operator=None):
        self.nodes[node] = {
            "kind": kind,
            "label": label or node,
            "offset": offset,
            "operator": operator,
        }
        return node

    def child(self, parent, child, role="AST_CHILD"):
        self.ast_children[parent].append(child)
        self.ast_parent[child] = parent
        self.edges.append({
            "source": parent,
            "target": child,
            "kind": "AST_CHILD",
            "properties": {"role": role},
        })

    def _owned(self, _function):
        return list(self.nodes)

    def kind(self, node):
        return self.nodes[node]["kind"]

    def operator(self, node):
        return self.nodes[node]["operator"]

    def label(self, node):
        return self.nodes[node]["label"]

    def offset(self, node):
        return self.nodes[node]["offset"]

    def props(self, node):
        return {"start_offset": self.offset(node)}

    def resolve_base_decl(self, node, depth=0):
        return self.refers.get(node, node)


class ReachingDefCfgTests(unittest.TestCase):
    def fixture(self):
        sub = _Substrate()
        sub.add("entry", "cfg-entry", 0)
        sub.add("root", "CompoundStmt", 1)
        sub.add("exit", "cfg-exit", 100)
        return sub

    def test_if_uses_edge_roles_and_keeps_branches_exclusive(self):
        sub = self.fixture()
        sub.add("if", "IfStmt", 10)
        sub.add("false", "CallExpr", 11)
        sub.add("condition", "CallExpr", 12)
        sub.add("true", "CallExpr", 13)
        sub.child("root", "if")
        # Deliberately put false first and offsets out of semantic order. AST edge
        # roles, not positional guesses, must define the branch structure.
        sub.child("if", "false", "FALSE_BRANCH")
        sub.child("if", "condition", "CONDITION")
        sub.child("if", "true", "TRUE_BRANCH")

        cfg = ReachingDef(sub).analyze("fn")

        self.assertEqual(set(cfg["succ"]["condition"]), {"true", "false"})
        self.assertEqual(cfg["succ"]["true"], ["exit"])
        self.assertEqual(cfg["succ"]["false"], ["exit"])
        self.assertNotIn("false", cfg["succ"]["true"])

    def test_for_loop_has_init_condition_body_increment_and_back_edge(self):
        sub = self.fixture()
        sub.add("param", "ParmVarDecl", 2, "p")
        sub.add("for", "ForStmt", 10)
        sub.add("init", "DeclStmt", 11)
        sub.add("local", "VarDecl", 12, "i")
        sub.add("condition", "BinaryOperator", 13, operator="<")
        sub.add("increment", "UnaryOperator", 14, operator="++")
        sub.add("body", "CompoundStmt", 15)
        sub.add("call", "CallExpr", 16)
        sub.child("root", "for")
        sub.child("for", "init", "LOOP_INIT")
        sub.child("init", "local", "DECLARATION")
        sub.child("for", "condition", "CONDITION")
        sub.child("for", "increment", "LOOP_INCREMENT")
        sub.child("for", "body", "LOOP_BODY")
        sub.child("body", "call")

        cfg = ReachingDef(sub).analyze("fn")

        self.assertEqual(cfg["succ"]["entry"], ["param"])
        self.assertEqual(cfg["succ"]["param"], ["local"])
        self.assertEqual(cfg["succ"]["local"], ["condition"])
        self.assertNotIn("init", cfg["nodes"])
        self.assertEqual(set(cfg["succ"]["condition"]), {"call", "exit"})
        self.assertEqual(cfg["succ"]["call"], ["increment"])
        self.assertEqual(cfg["succ"]["increment"], ["condition"])
        self.assertEqual(cfg["params"], ["param"])

    def test_return_terminates_and_unreachable_tail_is_not_collected(self):
        sub = self.fixture()
        sub.add("return", "ReturnStmt", 10)
        sub.add("after", "CallExpr", 20)
        sub.child("root", "return")
        sub.child("root", "after")

        cfg = ReachingDef(sub).analyze("fn")

        self.assertIn("return", cfg["nodes"])
        self.assertNotIn("after", cfg["nodes"])
        self.assertEqual(cfg["succ"]["return"], [])

    def test_macro_only_declaration_remains_a_placement_node(self):
        sub = self.fixture()
        sub.add("decl", "DeclStmt", 10)
        sub.child("root", "decl")

        cfg = ReachingDef(sub).analyze("fn")

        self.assertEqual(cfg["succ"]["entry"], ["decl"])
        self.assertEqual(cfg["succ"]["decl"], ["exit"])


if __name__ == "__main__":
    unittest.main()
