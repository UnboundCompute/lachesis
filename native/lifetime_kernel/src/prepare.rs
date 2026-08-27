//! Native lifetime-input preparation.
//!
//! This module is deliberately independent from the Python graph adapter.  It
//! accepts function-scoped graph records, builds the local control-flow relation,
//! and emits the same binary operation request consumed by the Rust solver.  The
//! first version covers the language-neutral call/lifecycle facts; expression
//! access-path extraction is added on top of this boundary without changing the
//! ABI.

use hashbrown::{HashMap, HashSet};

use prost::Message;
use rayon::prelude::*;

use crate::{lifetime_proto, Kind, Operation, Path};

#[derive(Clone, Copy, Eq, Hash, PartialEq)]
enum Role {
    Condition,
    TrueBranch,
    FalseBranch,
    LoopBody,
}

fn role(value: &str) -> Option<Role> {
    Some(match value {
        "CONDITION" => Role::Condition,
        "TRUE_BRANCH" => Role::TrueBranch,
        "FALSE_BRANCH" => Role::FalseBranch,
        "LOOP_BODY" => Role::LoopBody,
        _ => return None,
    })
}

fn text_property<'a>(node: &'a lifetime_proto::GraphNode, key: &str) -> Option<&'a str> {
    node.properties.iter().find_map(|item| {
        if item.key != key { return None; }
        match item.value.as_ref()? {
            lifetime_proto::scalar_property::Value::Text(value) => Some(value.as_str()),
            _ => None,
        }
    })
}

fn integer_property(node: &lifetime_proto::GraphNode, key: &str) -> Option<i64> {
    node.properties.iter().find_map(|item| {
        if item.key != key { return None; }
        match item.value.as_ref()? {
            lifetime_proto::scalar_property::Value::Integer(value) => Some(*value),
            lifetime_proto::scalar_property::Value::Text(value) => value.parse().ok(),
            _ => None,
        }
    })
}

fn path(node: Option<&str>) -> Option<Path> {
    node.filter(|value| !value.is_empty())
        .map(|value| Path::root(format!("decl:{value}")))
}

struct GraphView<'a> {
    // The input owns the protobuf nodes for the duration of preparation.  Keep
    // typed borrowed records here instead of cloning every node and its property
    // vector into a second graph-sized allocation.
    nodes: Vec<&'a lifetime_proto::GraphNode>,
    node_index: HashMap<&'a str, usize>,
    child_offsets: Vec<usize>,
    child_targets: Vec<&'a str>,
    roles: HashMap<&'a str, HashMap<Role, Vec<&'a str>>>,
    parent: HashMap<&'a str, &'a str>,
    refers: HashMap<&'a str, &'a str>,
    initializers: HashMap<&'a str, &'a str>,
    control: HashMap<&'a str, Vec<(&'a str, &'a str)>>,
}

impl<'a> GraphView<'a> {
    fn new(nodes_input: &'a [lifetime_proto::GraphNode],
           edges_input: &'a [lifetime_proto::GraphEdge]) -> Self {
        let nodes = nodes_input.iter().collect::<Vec<_>>();
        let node_index: HashMap<&'a str, usize> = nodes_input.iter().enumerate()
            .map(|(index, node)| (node.id.as_str(), index)).collect();
        let mut children_by_node: Vec<Vec<&'a str>> = vec![Vec::new(); nodes_input.len()];
        let mut parent = HashMap::new();
        let mut roles: HashMap<&'a str, HashMap<Role, Vec<&'a str>>> = HashMap::new();
        let mut refers = HashMap::new();
        let mut initializers = HashMap::new();
        let mut control: HashMap<&'a str, Vec<(&'a str, &'a str)>> = HashMap::new();
        for edge in edges_input {
            match edge.kind.as_str() {
                "AST_CHILD" => {
                    if let Some(&source) = node_index.get(edge.source.as_str()) {
                        children_by_node[source].push(edge.target.as_str());
                    }
                    parent.entry(edge.target.as_str()).or_insert(edge.source.as_str());
                    if let Some(role) = role(edge.role.as_str()) {
                        roles.entry(edge.source.as_str()).or_default()
                            .entry(role).or_default().push(edge.target.as_str());
                    }
                }
                "REFERS_TO" => { refers.insert(edge.source.as_str(), edge.target.as_str()); }
                "VALUE_FLOWS_TO" => {
                    initializers.insert(edge.target.as_str(), edge.source.as_str());
                }
                "CONDITION" | "TRUE_BRANCH" | "FALSE_BRANCH" | "LOOP_TRUE" |
                "LOOP_BACK" | "SWITCH_CASE" | "EXCEPTION_BRANCH" | "TRY_BODY" |
                "RUNS_FINALLY" | "BREAKS_TO" | "CONTINUES_TO" | "ITERATES" |
                "SHORT_CIRCUIT_LEFT" | "SHORT_CIRCUIT_RIGHT" => {
                    control.entry(edge.source.as_str()).or_default()
                        .push((edge.kind.as_str(), edge.target.as_str()));
                }
                _ => {}
            }
        }
        for children in &mut children_by_node {
            children.sort_by(|left, right| {
                let left_key = (node_index.get(left).and_then(|index| nodes_input.get(*index))
                    .and_then(|node| integer_property(node, "start_offset"))
                    .unwrap_or(i64::MAX), *left);
                let right_key = (node_index.get(right).and_then(|index| nodes_input.get(*index))
                    .and_then(|node| integer_property(node, "start_offset"))
                    .unwrap_or(i64::MAX), *right);
                left_key.cmp(&right_key)
            });
        }
        for role_map in roles.values_mut() {
            for children in role_map.values_mut() {
                children.sort();
            }
        }
        let mut child_offsets = Vec::with_capacity(children_by_node.len() + 1);
        let mut child_targets = Vec::new();
        child_offsets.push(0);
        for children in children_by_node {
            child_targets.extend(children);
            child_offsets.push(child_targets.len());
        }
        Self { nodes, node_index, child_offsets, child_targets, roles, parent, refers, initializers, control }
    }

    fn node(&self, id: &str) -> Option<&lifetime_proto::GraphNode> {
        self.node_index.get(id).and_then(|index| self.nodes.get(*index).copied())
    }

    fn children_of(&self, id: &str) -> Option<&[&'a str]> {
        let index = *self.node_index.get(id)?;
        Some(&self.child_targets[self.child_offsets[index]..self.child_offsets[index + 1]])
    }

    fn children_owned(&self, id: &str) -> Vec<String> {
        self.children_of(id).into_iter().flatten().map(|child| (*child).to_owned()).collect()
    }

    fn parent_of(&self, id: &str) -> Option<&'a str> { self.parent.get(id).copied() }

    fn role_children(&self, id: &str, role_name: &str) -> Option<&Vec<&'a str>> {
        self.roles.get(id).and_then(|roles| role(role_name).and_then(|role| roles.get(&role)))
    }

    fn role_children_owned(&self, id: &str, role: &str) -> Vec<String> {
        self.role_children(id, role).into_iter().flatten().map(|child| (*child).to_owned()).collect()
    }

    fn initializer_of(&self, id: &str) -> Option<&'a str> { self.initializers.get(id).copied() }

    fn control_targets(&self, id: &str, kind: &str) -> Vec<&'a str> {
        self.control.get(id).into_iter().flatten()
            .filter(|(edge_kind, _)| *edge_kind == kind)
            .map(|(_, target)| *target)
            .collect()
    }

    fn kind(&self, id: &str) -> &str {
        self.node(id).map(|node| text_property(node, "syntax_kind").unwrap_or(node.kind.as_str())).unwrap_or("")
    }

    fn label(&self, id: &str) -> &str { self.node(id).map(|node| node.label.as_str()).unwrap_or("") }

    fn offset(&self, id: &str) -> i64 {
        self.node(id).and_then(|node| integer_property(node, "start_offset")).unwrap_or(i64::MAX)
    }

    fn operator(&self, id: &str) -> &str {
        self.node(id).and_then(|node| text_property(node, "operator")).unwrap_or("")
    }

    fn property(&self, id: &str, key: &str) -> Option<&str> {
        self.node(id).and_then(|node| text_property(node, key))
    }

    fn is_pointer(&self, id: &str) -> bool {
        self.node(id).and_then(|node| text_property(node, "type"))
            .is_some_and(|value| value.contains('*') || value.contains('['))
    }

    fn is_null(&self, id: &str) -> bool {
        let id = self.peel(id.to_owned());
        matches!(self.kind(&id), "GNUNullExpr" | "CXXNullPtrLiteralExpr")
            || (self.kind(&id) == "IntegerLiteral"
                && matches!(self.label(&id).trim(), "0" | "NULL" | "nullptr"))
            || (self.kind(&id) == "value"
                && matches!(self.label(&id).trim(), "None" | "null" | "NULL"))
    }

    fn pointer_arithmetic_source(&self, id: &str) -> Option<Path> {
        let id = self.peel(id.to_owned());
        if self.kind(&id) != "BinaryOperator" || !matches!(self.operator(&id), "+" | "-") {
            return None;
        }
        self.children_of(&id).into_iter().flatten()
            .find_map(|child| self.access_path(child, 0))
    }

    fn conditional_value_source(&self, id: &str) -> Option<Path> {
        let id = self.peel(id.to_owned());
        if self.kind(&id) != "ConditionalOperator" { return None; }
        self.role_children(&id, "TRUE_VALUE").into_iter().flatten()
            .find_map(|child| self.access_path(child, 0))
            .or_else(|| self.children_of(&id).into_iter().flatten().skip(1)
                .find_map(|child| self.access_path(child, 0)))
    }

    fn peel(&self, mut id: String) -> String {
        for _ in 0..12 {
            if matches!(self.kind(&id), "ImplicitCastExpr" | "CStyleCastExpr" | "ParenExpr" |
                "UnexposedExpr" | "CXXBindTemporaryExpr" | "MaterializeTemporaryExpr" |
                "ExprWithCleanups" | "ConstantExpr" | "OpaqueValueExpr" |
                "CXXConstCastExpr" | "CXXStaticCastExpr" | "CXXReinterpretCastExpr" | "CXXFunctionalCastExpr") {
                if let Some(child) = self.children_of(&id).and_then(|items| items.into_iter()
                    .find(|child| **child != id.as_str())) {
                    id = (*child).to_owned();
                    continue;
                }
            }
            break;
        }
        id
    }

    fn access_path(&self, id: &str, depth: usize) -> Option<Path> {
        if depth > 40 { return None; }
        let id = self.peel(id.to_owned());
        match self.kind(&id) {
            "DeclRefExpr" => self.access_path(self.refers.get(id.as_str()).copied().unwrap_or(&id), depth + 1),
            "ParmVarDecl" | "VarDecl" => path(Some(&id)),
            "MemberExpr" => {
                let child = self.children_of(&id)?.first()?;
                let mut base = self.access_path(child, depth + 1)?;
                let label = self.label(&id);
                let arrow = label.rfind("->");
                let dot = label.rfind('.');
                let (index, width, is_arrow) = match (arrow, dot) {
                    (Some(left), Some(right)) if left > right => (left, 2, true),
                    (Some(left), None) => (left, 2, true),
                    (None, Some(right)) => (right, 1, false),
                    _ => return Some(base),
                };
                let field = label[index + width..].split(['[', '(', ' ']).next().unwrap_or("");
                if field.is_empty() { return Some(base); }
                let mut selectors = Vec::with_capacity(base.selectors.len() + 2);
                if is_arrow { selectors.push("*".to_owned()); }
                selectors.push(field.to_owned());
                selectors.extend(base.selectors);
                base.selectors = selectors;
                Some(base)
            }
            "ArraySubscriptExpr" => {
                let children = self.children_of(&id)?;
                let base_id = children.iter().find(|child| {
                    self.node(child).and_then(|node| text_property(node, "type")).map(str::to_owned)
                        .is_some_and(|value| value.contains('*') || value.contains('['))
                }).or_else(|| children.first())?;
                let mut base = self.access_path(base_id, depth + 1)?;
                base.selectors.push("<?>".to_owned());
                base.selectors.push("*".to_owned());
                Some(base)
            }
            "UnaryOperator" => {
                let child = self.children_of(&id)?.first()?;
                let mut base = self.access_path(child, depth + 1)?;
                match self.operator(&id) {
                    "*" => base.selectors.push("*".to_owned()),
                    "&" => base.selectors.push("&".to_owned()),
                    _ => {}
                }
                Some(base)
            }
            // Python and TypeScript frontends publish normalized binding nodes
            // rather than Clang declaration expressions. Treat their stable
            // node identity as the root of the same abstract path domain.
            "parameter" | "variable" | "binding" | "property-path" => path(Some(&id)),
            _ => None,
        }
    }

    fn value_path(&self, id: &str, depth: usize) -> Option<Path> {
        if depth > 24 { return None; }
        if let Some(path) = self.access_path(id, 0) { return Some(path); }
        if let Some(node) = self.node(id) {
            if let Some(target) = text_property(node, "target_id") {
                if let Some(path) = self.access_path(target, depth + 1) { return Some(path); }
            }
        }
        self.initializer_of(id).and_then(|source| self.value_path(source, depth + 1))
    }

    fn value_source(&self, id: &'a str, depth: usize) -> Option<&'a str> {
        if depth > 24 { return None; }
        if self.kind(id) == "allocation" || self.kind(id) == "call" {
            return Some(id);
        }
        let source = self.initializer_of(id)?;
        self.value_source(source, depth + 1)
    }

    fn deref_base(&self, id: &str) -> Option<Path> {
        let children = self.children_of(id)?;
        match self.kind(id) {
            "UnaryOperator" if self.operator(&id) == "*" => self.access_path(children.first()?, 0),
            "MemberExpr" if self.label(&id).contains("->") => self.access_path(children.first()?, 0),
            "ArraySubscriptExpr" => children.iter().find_map(|child| self.access_path(child, 0)),
            _ => None,
        }
    }

    fn is_descendant(&self, node: &str, root: &str) -> bool {
        let mut current = node;
        let mut seen = HashSet::new();
        while seen.insert(current.to_owned()) {
            if current == root { return true; }
            let Some(parent) = self.parent_of(current) else { return false };
            current = parent;
        }
        false
    }
}

fn is_statement(kind: &str) -> bool {
    kind.ends_with("Stmt") || matches!(kind,
        "cfg-entry" | "cfg-exit" | "cfg-merge" | "cfg-condition" |
        "statement" | "Return" | "ReturnStatement" | "return" |
        "Block" | "ExpressionStatement" | "IfStatement" | "ForStatement" |
        "WhileStatement" | "TryStatement" | "WithStatement" |
        "If" | "For" | "AsyncFor" | "While" | "Try" | "Match" |
        "Raise" | "Break" | "Continue" | "Assign" | "AnnAssign" |
        "AugAssign" | "Expr" | "Pass")
}

fn is_return_kind(kind: &str) -> bool {
    matches!(kind, "ReturnStmt" | "Return" | "ReturnStatement" | "return")
}

fn expression_stream(graph: &GraphView, id: &str, owned: &HashSet<String>, out: &mut Vec<String>, seen: &mut HashSet<String>, depth: usize) {
    if depth > 60 || !owned.contains(id) || !seen.insert(id.to_owned()) { return; }
    let peeled = graph.peel(id.to_owned());
    if peeled != id {
        if owned.contains(&peeled) {
            expression_stream(graph, &peeled, owned, out, seen, depth + 1);
        } else {
            out.push(id.to_owned());
        }
        return;
    }
    let mut children = graph.children_owned(id)
        .into_iter().filter(|child| owned.contains(child)).collect::<Vec<_>>();
    if graph.kind(id) == "BinaryOperator" && graph.operator(id) == "=" && children.len() >= 2 {
        children.swap(0, 1);
    }
    for child in children { expression_stream(graph, &child, owned, out, seen, depth + 1); }
    out.push(id.to_owned());
}

fn append_chain(successors: &mut HashMap<String, Vec<String>>, nodes: &[String]) {
    for pair in nodes.windows(2) {
        successors.entry(pair[0].clone()).or_default().push(pair[1].clone());
    }
}

fn guard_value(graph: &GraphView<'_>, node: &str) -> Option<String> {
    let path = graph.access_path(node, 0)?;
    let mut value = path.root.trim_start_matches("decl:").to_owned();
    value.push_str(&path.selectors.join(""));
    (!value.is_empty()).then(|| format!("{value}#g0"))
}

fn branch_guards(graph: &GraphView<'_>, source: &str, branch: &str)
    -> Vec<lifetime_proto::GuardProof>
{
    let children = graph.children_of(source).unwrap_or(&[]);
    let operator = match graph.operator(source) {
        "" => graph.label(source),
        value => value,
    };
    let proof = |kind: &str, value: Option<String>| value.map(|value|
        lifetime_proto::GuardProof { kind: kind.to_owned(), value }).into_iter().collect();
    let invert = branch == "FALSE_BRANCH";
    if matches!(operator, "==" | "!=") {
        let null_child = children.iter().find(|child| graph.is_null(child)).copied();
        let value_child = children.iter().find(|child| Some(**child) != null_child)
            .and_then(|child| guard_value(graph, child));
        if null_child.is_some() {
            let is_null = operator == "==";
            let is_null = if invert { !is_null } else { is_null };
            return proof(if is_null { "ISNULL" } else { "NONNULL" }, value_child);
        }
    }
    if operator == "!" {
        let value = children.first().and_then(|child| guard_value(graph, child));
        return proof(if invert { "NONNULL" } else { "ISNULL" }, value);
    }
    // A bare pointer condition has the same nullability meaning as `p != 0`.
    if children.is_empty() {
        let value = guard_value(graph, source);
        return proof(if invert { "ISNULL" } else { "NONNULL" }, value);
    }
    Vec::new()
}

fn synthesize_cfg(graph: &GraphView, owned: &HashSet<String>) -> Option<(Vec<String>, HashMap<String, Vec<String>>)> {
    let mut roots = owned.iter().filter(|node| graph.kind(node) == "CompoundStmt" &&
        graph.parent_of(node).map(|parent| !owned.contains(parent)).unwrap_or(true)).cloned().collect::<Vec<_>>();
    if roots.is_empty() { roots = owned.iter().filter(|node| graph.kind(node) == "CompoundStmt").cloned().collect(); }
    roots.sort_by(|left, right| (graph.offset(left), left).cmp(&(graph.offset(right), right)));
    let root = if let Some(root) = roots.into_iter().next() {
        root
    } else {
        // Normalized non-C frontends may not publish a CompoundStmt. Their
        // owned body nodes still have stable source offsets, so a linear CFG
        // is the conservative equivalent for the native temporal solver.
        let mut body = owned.iter().filter(|node| {
            !matches!(graph.kind(node), "function" | "method" | "constructor" |
                "FunctionDef" | "AsyncFunctionDef" | "FunctionDeclaration" |
                "ArrowFunction" | "MethodDeclaration" | "MethodDefinition" |
                "Constructor" | "parameter" | "ParmVarDecl")
        }).cloned().collect::<Vec<_>>();
        body.sort_by(|left, right| (graph.offset(left), left).cmp(&(graph.offset(right), right)));
        body.first()?;
        let mut linear = HashMap::new();
        for pair in body.windows(2) {
            linear.entry(pair[0].clone()).or_insert_with(Vec::new).push(pair[1].clone());
        }
        let mut prepared = body.clone();
        prepared.dedup();
        return Some((prepared, linear));
    };
    let mut successors: HashMap<String, Vec<String>> = HashMap::new();
    let mut memo: HashMap<String, (Option<String>, Vec<String>)> = HashMap::new();
    let mut in_progress = HashSet::new();

    fn emit(
        graph: &GraphView, owned: &HashSet<String>, id: &str,
        successors: &mut HashMap<String, Vec<String>>,
        memo: &mut HashMap<String, (Option<String>, Vec<String>)>,
        in_progress: &mut HashSet<String>, depth: usize,
    ) -> (Option<String>, Vec<String>) {
        if depth > 200 { return (None, Vec::new()); }
        if let Some(value) = memo.get(id) { return value.clone(); }
        if !in_progress.insert(id.to_owned()) { return (None, Vec::new()); }
        let kind = graph.kind(id);
        let children = graph.children_owned(id)
            .into_iter().filter(|child| owned.contains(child)).collect::<Vec<_>>();
        let result = if kind == "CompoundStmt" {
            let items = children;
            let mut first = None;
            let mut exits: Vec<String> = Vec::new();
            for child in items {
                let (entry, next_exits) = {
                if is_statement(graph.kind(&child)) {
                    emit(graph, owned, &child, successors, memo, in_progress, depth + 1)
                } else {
                    let mut stream = Vec::new();
                    expression_stream(graph, &child, owned, &mut stream, &mut HashSet::new(), 0);
                    let exits = stream.last().cloned().into_iter().collect();
                    append_chain(successors, &stream);
                    (stream.first().cloned(), exits)
                }
                };
                let Some(entry) = entry else { continue };
                if first.is_none() { first = Some(entry.clone()); }
                for previous in &exits { successors.entry(previous.clone()).or_default().push(entry.clone()); }
                exits = next_exits;
            }
            (first, exits)
        } else if matches!(kind, "IfStmt" | "If") {
            let condition = graph.role_children(id, "CONDITION").and_then(|items| items.first()).map(|child| (*child).to_owned())
                .or_else(|| graph.control_targets(id, "CONDITION").into_iter().next().map(str::to_owned))
                .or_else(|| children.iter().min_by_key(|child| graph.offset(child)).cloned());
            let mut condition_stream = Vec::new();
            if let Some(condition) = condition {
                expression_stream(graph, &condition, owned, &mut condition_stream, &mut HashSet::new(), 0);
                append_chain(successors, &condition_stream);
            }
            let mut branches = Vec::new();
            for role in ["TRUE_BRANCH", "FALSE_BRANCH"] {
                let branch = graph.role_children(id, role).and_then(|items| items.first()).copied()
                    .or_else(|| condition_stream.last().and_then(|condition| {
                        graph.control_targets(condition, role).into_iter().next()
                    }));
                if let Some(branch) = branch {
                    branches.push(emit(graph, owned, branch, successors, memo, in_progress, depth + 1));
                }
            }
            let mut exits = Vec::new();
            for (entry, branch_exits) in branches {
                if let Some(entry) = entry {
                    for condition_exit in condition_stream.iter().rev().take(1) {
                        successors.entry(condition_exit.clone()).or_default().push(entry.clone());
                    }
                    exits.extend(branch_exits);
                }
            }
            if exits.is_empty() { exits = condition_stream.last().cloned().into_iter().collect(); }
            (condition_stream.first().cloned().or_else(|| exits.first().cloned()), exits)
        } else if matches!(kind, "Try" | "TryStatement") {
            // Managed-language frontends publish exception control directly
            // (TRY_BODY/EXCEPTION_BRANCH/RUNS_FINALLY). Preserve those edges
            // instead of flattening a try block into source order.
            let attempted = graph.control_targets(id, "TRY_BODY").into_iter().next()
                .or_else(|| children.iter().find(|child| is_statement(graph.kind(child))).map(String::as_str));
            let body_result = attempted.map(|node| emit(graph, owned, node, successors,
                memo, in_progress, depth + 1)).unwrap_or((None, Vec::new()));
            let attempted_anchor = body_result.0.as_deref().or(attempted).unwrap_or(id);
            let handlers = graph.control_targets(attempted_anchor, "EXCEPTION_BRANCH");
            let handlers = if handlers.is_empty() { graph.control_targets(id, "EXCEPTION_BRANCH") } else { handlers };
            let mut exits = Vec::new();
            for handler in &handlers {
                let result = emit(graph, owned, handler, successors, memo, in_progress, depth + 1);
                if let Some(entry) = result.0 {
                    successors.entry(attempted_anchor.to_owned()).or_default().push(entry);
                }
                exits.extend(result.1);
            }
            exits.extend(body_result.1);
            let finally = graph.control_targets(attempted_anchor, "RUNS_FINALLY");
            let finally = if finally.is_empty() { graph.control_targets(id, "RUNS_FINALLY") } else { finally };
            if let Some(finally) = finally.first() {
                let result = emit(graph, owned, finally, successors, memo, in_progress, depth + 1);
                for exit in &exits { successors.entry(exit.clone()).or_default().push((*finally).to_owned()); }
                exits = result.1;
                if exits.is_empty() { exits.push((*finally).to_owned()); }
            }
            (body_result.0.or_else(|| handlers.first().map(|node| (*node).to_owned())), exits)
        } else if matches!(kind, "SwitchStmt" | "Match") {
            // A switch dispatches to every case/default entry. The generic
            // statement path would serialize all case bodies into one chain,
            // making a large opcode switch look like one giant sequential
            // transfer on every loop iteration.
            let condition = graph.role_children(id, "CONDITION").and_then(|items| items.first()).map(|child| (*child).to_owned())
                .or_else(|| children.iter().find(|child| graph.kind(child) != "CompoundStmt").cloned());
            let body = graph.role_children(id, "LOOP_BODY").and_then(|items| items.first()).map(|child| (*child).to_owned())
                .or_else(|| children.iter().find(|child| graph.kind(child) == "CompoundStmt").cloned());
            let mut condition_stream = Vec::new();
            if let Some(condition) = condition {
                expression_stream(graph, &condition, owned, &mut condition_stream, &mut HashSet::new(), 0);
                append_chain(successors, &condition_stream);
            }
            let body_result = body.as_ref()
                .map(|body| emit(graph, owned, body, successors, memo, in_progress, depth + 1))
                .unwrap_or((None, Vec::new()));
            let mut case_nodes = body.as_ref().map(|body| {
                graph.children_owned(body)
                    .into_iter().filter(|child| owned.contains(child)
                        && matches!(graph.kind(child), "CaseStmt" | "DefaultStmt"))
                    .collect::<Vec<_>>()
            }).unwrap_or_default();
            if case_nodes.is_empty() {
                let source = condition_stream.last().map(String::as_str).unwrap_or(id);
                case_nodes = graph.control_targets(source, "SWITCH_CASE")
                    .into_iter().map(str::to_owned).collect();
            }
            let mut case_entries = Vec::new();
            for case in &case_nodes {
                let (entry, exits) = emit(graph, owned, case, successors, memo, in_progress, depth + 1);
                if let Some(entry) = entry { case_entries.push((entry, exits)); }
            }
            if let Some(condition_exit) = condition_stream.last() {
                for (entry, _) in &case_entries {
                    successors.entry(condition_exit.clone()).or_default().push(entry.clone());
                }
            }
            let has_default = case_nodes.iter().any(|case| graph.kind(case) == "DefaultStmt");
            let mut exits = body_result.1;
            exits.extend(case_entries.into_iter().flat_map(|(_, branch_exits)| branch_exits));
            if !has_default { exits.extend(condition_stream.last().cloned()); }
            (condition_stream.first().cloned().or(body_result.0), exits)
        } else if matches!(kind, "CaseStmt" | "DefaultStmt") {
            // Case bodies contain nested statements, not just expressions.
            // Preserve fallthrough only when the case's final child has an
            // exit; a break/return therefore terminates that case chain.
            let mut units: Vec<(String, Vec<String>)> = Vec::new();
            let sorted = children;
            for child in sorted {
                if is_statement(graph.kind(&child)) {
                    let (entry, exits) = emit(graph, owned, &child, successors, memo, in_progress, depth + 1);
                    if let Some(entry) = entry { units.push((entry, exits)); }
                } else {
                    let mut stream = Vec::new();
                    expression_stream(graph, &child, owned, &mut stream, &mut HashSet::new(), 0);
                    if let Some(entry) = stream.first().cloned() {
                        let exits = stream.last().cloned().into_iter().collect();
                        append_chain(successors, &stream);
                        units.push((entry, exits));
                    }
                }
            }
            let Some((first, mut exits)) = units.first().cloned() else { return (None, Vec::new()) };
            for (entry, next_exits) in units.into_iter().skip(1) {
                for previous in &exits { successors.entry(previous.clone()).or_default().push(entry.clone()); }
                exits = next_exits;
            }
            (Some(first), exits)
        } else if kind == "BreakStmt" || kind == "ContinueStmt" {
            successors.entry(id.to_owned()).or_default();
            (Some(id.to_owned()), Vec::new())
        } else if matches!(kind, "For" | "AsyncFor") {
            // Python's normalized frontend publishes iterator/body control
            // edges rather than a Clang-style CONDITION node. Preserve the
            // same loop topology: iterator -> body -> iterator, with the
            // explicit FALSE_BRANCH/else arm left as the finite exit.
            let iterator = children.iter().find(|child| {
                !matches!(graph.kind(child), "statement" | "expression")
                    || graph.offset(child) <= graph.offset(id)
            }).cloned().or_else(|| children.first().cloned());
            let mut iterator_stream = Vec::new();
            if let Some(iterator) = iterator {
                expression_stream(graph, &iterator, owned, &mut iterator_stream,
                    &mut HashSet::new(), 0);
                append_chain(successors, &iterator_stream);
            }
            let body = iterator_stream.last().and_then(|iterator| {
                graph.control_targets(iterator, "ITERATES").into_iter().next()
            }).or_else(|| graph.control_targets(id, "LOOP_BODY").into_iter().next());
            let body_result = body.map(|node| emit(graph, owned, node, successors,
                memo, in_progress, depth + 1)).unwrap_or((None, Vec::new()));
            if let (Some(iterator), Some(body_entry)) = (iterator_stream.last(), body_result.0.clone()) {
                successors.entry(iterator.clone()).or_default().push(body_entry);
            }
            if let Some(iterator) = iterator_stream.first() {
                for exit in &body_result.1 {
                    successors.entry(exit.clone()).or_default().push(iterator.clone());
                }
            }
            let mut exits = graph.control_targets(
                iterator_stream.last().map(String::as_str).unwrap_or(id), "FALSE_BRANCH")
                .into_iter().map(str::to_owned).collect::<Vec<_>>();
            if exits.is_empty() { exits = iterator_stream.last().cloned().into_iter().collect(); }
            (iterator_stream.first().cloned().or(body_result.0), exits)
        } else if kind == "ForStmt" {
            let body = graph.role_children(id, "LOOP_BODY").and_then(|items| items.first()).map(|child| (*child).to_owned());
            let condition = graph.role_children(id, "CONDITION").and_then(|items| items.first()).map(|child| (*child).to_owned());
            let mut others = children;
            others.retain(|child| Some(child) != body.as_ref() && Some(child) != condition.as_ref());
            let condition_offset = condition.as_ref().map(|node| graph.offset(node)).unwrap_or(i64::MAX);
            let init = others.iter().find(|node| graph.offset(node) < condition_offset).cloned();
            let increment = others.iter().rev().find(|node| graph.offset(node) > condition_offset).cloned();
            let emit_expr = |node: Option<String>, successors: &mut HashMap<String, Vec<String>>| -> (Option<String>, Vec<String>) {
                let Some(node) = node else { return (None, Vec::new()) };
                let mut stream = Vec::new();
                expression_stream(graph, &node, owned, &mut stream, &mut HashSet::new(), 0);
                append_chain(successors, &stream);
                (stream.first().cloned(), stream.last().cloned().into_iter().collect())
            };
            let init_result = emit_expr(init, successors);
            let condition_result = emit_expr(condition, successors);
            let body_result = body.map(|node| emit(graph, owned, &node, successors, memo, in_progress, depth + 1)).unwrap_or((None, Vec::new()));
            let increment_result = emit_expr(increment, successors);
            if let Some(condition_entry) = condition_result.0.clone() {
                for exit in &init_result.1 { successors.entry(exit.clone()).or_default().push(condition_entry.clone()); }
                if let Some(body_entry) = body_result.0.clone() {
                    if let Some(condition_exit) = condition_result.1.first() { successors.entry(condition_exit.clone()).or_default().push(body_entry); }
                }
                let back = increment_result.0.clone().or(condition_result.0.clone());
                for exit in &body_result.1 { if let Some(back) = back.clone() { successors.entry(exit.clone()).or_default().push(back); } }
                if let Some(increment_entry) = increment_result.0.clone() {
                    for exit in &increment_result.1 { successors.entry(exit.clone()).or_default().push(condition_entry.clone()); }
                    let _ = increment_entry;
                }
            }
            let entry = init_result.0.or(condition_result.0).or(body_result.0);
            (entry, condition_result.1.into_iter().chain(body_result.1).collect())
        } else if matches!(kind, "WhileStmt" | "DoStmt" | "While") {
            let condition = graph.role_children(id, "CONDITION").and_then(|items| items.first()).map(|child| (*child).to_owned());
            let condition = condition.or_else(|| graph.control_targets(id, "CONDITION").into_iter().next().map(str::to_owned));
            let body = graph.role_children(id, "LOOP_BODY").and_then(|items| items.first()).map(|child| (*child).to_owned())
                .or_else(|| condition.as_deref().and_then(|condition| graph.control_targets(condition, "LOOP_TRUE").into_iter().next().map(str::to_owned)));
            let mut condition_stream = Vec::new();
            if let Some(condition) = condition.as_ref() { expression_stream(graph, condition, owned, &mut condition_stream, &mut HashSet::new(), 0); append_chain(successors, &condition_stream); }
            let body_result = body.as_ref().map(|body| emit(graph, owned, body, successors, memo, in_progress, depth + 1)).unwrap_or((None, Vec::new()));
            if kind == "WhileStmt" {
                if let Some(body_entry) = body_result.0.clone() {
                    for condition_exit in condition_stream.iter().rev().take(1) { successors.entry(condition_exit.clone()).or_default().push(body_entry.clone()); }
                }
                for body_exit in body_result.1 { if let Some(condition_entry) = condition_stream.first() { successors.entry(body_exit).or_default().push(condition_entry.clone()); } }
                (condition_stream.first().cloned().or(body_result.0), condition_stream.last().cloned().into_iter().collect())
            } else {
                for body_exit in body_result.1 { if let Some(condition_entry) = condition_stream.first() { successors.entry(body_exit).or_default().push(condition_entry.clone()); } }
                (body_result.0.or_else(|| condition_stream.first().cloned()), condition_stream.last().cloned().into_iter().collect())
            }
        } else if kind == "ReturnStmt" {
            let mut stream = Vec::new();
            for child in children { expression_stream(graph, &child, owned, &mut stream, &mut HashSet::new(), 0); }
            append_chain(successors, &stream);
            if let Some(last) = stream.last() { successors.entry(last.clone()).or_default(); }
            (stream.first().cloned().or_else(|| Some(id.to_owned())), Vec::new())
        } else if is_statement(kind) {
            let mut stream = Vec::new();
            let sorted = children;
            for child in sorted { expression_stream(graph, &child, owned, &mut stream, &mut HashSet::new(), 0); }
            append_chain(successors, &stream);
            (stream.first().cloned(), stream.last().cloned().into_iter().collect())
        } else {
            let mut stream = Vec::new();
            expression_stream(graph, id, owned, &mut stream, &mut HashSet::new(), 0);
            append_chain(successors, &stream);
            (stream.first().cloned(), stream.last().cloned().into_iter().collect())
        };
        in_progress.remove(id);
        memo.insert(id.to_owned(), result.clone());
        result
    }

    let (entry, exits) = emit(graph, owned, &root, &mut successors, &mut memo, &mut in_progress, 0);
    let entry = entry?;
    let cfg_entry = owned.iter().filter(|node| graph.kind(node) == "cfg-entry")
        .min_by(|left, right| (graph.offset(left), *left).cmp(&(graph.offset(right), *right))).cloned();
    let cfg_exit = owned.iter().filter(|node| graph.kind(node) == "cfg-exit")
        .min_by(|left, right| (graph.offset(left), *left).cmp(&(graph.offset(right), *right))).cloned();
    let mut params = owned.iter().filter(|node| matches!(graph.kind(node),
        "ParmVarDecl" | "parameter" | "arg")).cloned().collect::<Vec<_>>();
    params.sort_by_key(|node| graph.offset(node));
    if let Some(exit) = cfg_exit.clone() {
        successors.entry(exit.clone()).or_default();
        for item in exits { successors.entry(item).or_default().push(cfg_exit.clone().unwrap()); }
        // Structured loop emission has a back-edge for the true/body arm, but
        // the false/termination arm is not represented by a source AST node.
        // Recover it here so every finite loop has a native CFG exit. Return
        // statements and other terminal fragments are handled by the same
        // empty-successor closure below.
        let mut controls = owned.iter().filter(|node| matches!(graph.kind(node),
            "IfStmt" | "ForStmt" | "WhileStmt" | "DoStmt")).cloned().collect::<Vec<_>>();
        controls.sort_by(|left, right| (graph.offset(left), left).cmp(&(graph.offset(right), right)));
        for control in controls {
            let condition = graph.role_children(&control, "CONDITION")
                .and_then(|items| items.first()).cloned();
            let Some(condition) = condition else { continue };
            let mut stream = Vec::new();
            expression_stream(graph, &condition, owned, &mut stream, &mut HashSet::new(), 0);
            if let Some(last) = stream.last() {
                successors.entry(last.clone()).or_default().push(exit.clone());
            }
        }
        let terminals = successors.iter().filter_map(|(node, targets)| {
            if node != &exit && targets.is_empty() { Some(node.clone()) } else { None }
        }).collect::<Vec<_>>();
        for terminal in terminals {
            successors.entry(terminal).or_default().push(exit.clone());
        }
    }
    let mut chain = Vec::new();
    if let Some(entry_node) = cfg_entry { chain.push(entry_node); }
    chain.extend(params);
    chain.push(entry);
    append_chain(&mut successors, &chain);
    let start = chain.first()?.clone();
    let mut nodes = Vec::new();
    let mut seen = HashSet::new();
    let mut queue = vec![start];
    while let Some(node) = queue.pop() {
        if !seen.insert(node.clone()) { continue; }
        nodes.push(node.clone());
        for successor in successors.get(&node).into_iter().flatten().rev() { queue.push(successor.clone()); }
    }
    Some((nodes, successors))
}

fn operation(kind: Kind, node: &str, target: Option<Path>, source: Option<Path>, call: &lifetime_proto::FunctionCall) -> Operation {
    Operation {
        kind,
        node: node.to_owned(),
        target,
        source,
        site: node.to_owned(),
        line: call.has_line.then_some(call.line),
        is_null: false,
        access: "deref".to_owned(),
        generation: None,
        fresh_generation: None,
        alternatives: Vec::new(),
    }
}

fn raw_operation(kind: Kind, node: &str, target: Option<Path>, source: Option<Path>, line: Option<i64>, is_null: bool, access: &str) -> Operation {
    Operation {
        kind,
        node: node.to_owned(),
        target,
        source,
        site: node.to_owned(),
        line,
        is_null,
        access: access.to_owned(),
        generation: None,
        fresh_generation: None,
        alternatives: Vec::new(),
    }
}

fn cyclic_nodes(nodes: &[String], successors: &HashMap<String, Vec<String>>) -> Vec<String> {
    // Kosaraju is linear in the prepared CFG and avoids handing loop discovery
    // back to the Python semantic emitter.  A singleton with a self edge is a
    // cycle as well; all members of larger SCCs are loop-region nodes.
    let node_set: HashSet<String> = nodes.iter().cloned().collect();
    let mut reverse: HashMap<String, Vec<String>> = HashMap::new();
    for source in nodes {
        for target in successors.get(source).into_iter().flatten() {
            if node_set.contains(target) {
                reverse.entry(target.clone()).or_default().push(source.clone());
            }
        }
    }
    let mut visited = HashSet::new();
    let mut order = Vec::with_capacity(nodes.len());
    fn visit(node: &str, graph: &HashMap<String, Vec<String>>, visited: &mut HashSet<String>, order: &mut Vec<String>) {
        if !visited.insert(node.to_owned()) { return; }
        for next in graph.get(node).into_iter().flatten() {
            visit(next, graph, visited, order);
        }
        order.push(node.to_owned());
    }
    for node in nodes { visit(node, successors, &mut visited, &mut order); }
    visited.clear();
    let mut result = Vec::new();
    fn collect(node: &str, graph: &HashMap<String, Vec<String>>, visited: &mut HashSet<String>, component: &mut Vec<String>) {
        if !visited.insert(node.to_owned()) { return; }
        component.push(node.to_owned());
        for next in graph.get(node).into_iter().flatten() {
            collect(next, graph, visited, component);
        }
    }
    for node in order.into_iter().rev() {
        if visited.contains(&node) { continue; }
        let mut component = Vec::new();
        collect(&node, &reverse, &mut visited, &mut component);
        let cyclic = component.len() > 1 || successors.get(&node).into_iter().flatten().any(|target| target == &node);
        if cyclic { result.extend(component); }
    }
    result.sort();
    result.dedup();
    result
}

fn assign_generations(
    operations: &mut [Operation], nodes: &[String], successors: &HashMap<String, Vec<String>>,
    offsets: &HashMap<String, i64>,
) {
    let node_index: HashMap<&str, usize> = nodes.iter().enumerate()
        .map(|(index, node)| (node.as_str(), index)).collect();
    // Keep the exact iterative dominator equations, but represent each set as
    // packed machine words.  The previous HashSet representation performed a
    // hash lookup for every candidate edge on every fixed-point pass.
    let words = nodes.len().div_ceil(usize::BITS as usize);
    let mut all = vec![usize::MAX; words];
    if let Some(last) = all.last_mut() {
        let used = nodes.len() % usize::BITS as usize;
        if used != 0 { *last = (1usize << used) - 1; }
    }
    let mut predecessors: Vec<Vec<usize>> = vec![Vec::new(); nodes.len()];
    for (source, targets) in successors {
        let Some(&source_index) = node_index.get(source.as_str()) else { continue };
        for target in targets {
            if let Some(&target_index) = node_index.get(target.as_str()) {
                predecessors[target_index].push(source_index);
            }
        }
    }
    let entry = nodes.first().and_then(|node| node_index.get(node.as_str()).copied());
    let mut dominators = vec![all.clone(); nodes.len()];
    if let Some(entry) = entry {
        dominators[entry].fill(0);
        dominators[entry][entry / usize::BITS as usize] |= 1usize << (entry % usize::BITS as usize);
        let mut changed = true;
        while changed {
            changed = false;
            for index in 0..nodes.len() {
                if index == entry { continue; }
                let candidate = if predecessors[index].is_empty() {
                    let mut only = vec![0; words];
                    only[index / usize::BITS as usize] |= 1usize << (index % usize::BITS as usize);
                    only
                } else {
                    let mut meet = all.clone();
                    for parent in &predecessors[index] {
                        for (word, value) in meet.iter_mut().zip(&dominators[*parent]) { *word &= *value; }
                    }
                    meet[index / usize::BITS as usize] |= 1usize << (index % usize::BITS as usize);
                    meet
                };
                if candidate != dominators[index] { dominators[index] = candidate; changed = true; }
            }
        }
    }
    let dominates = |left: &str, right: &str| -> bool {
        if left == right { return true; }
        match (node_index.get(left), node_index.get(right)) {
            (Some(&left), Some(&right)) => dominators[right]
                .get(left / usize::BITS as usize)
                .is_some_and(|word| word & (1usize << (left % usize::BITS as usize)) != 0),
            _ => false,
        }
    };
    let mut order: Vec<usize> = (0..operations.len()).collect();
    order.sort_by_key(|index| {
        let operation = &operations[*index];
        (operation.target.as_ref().and_then(|_| offsets.get(&operation.node).copied()).unwrap_or(i64::MAX),
         operation.line.unwrap_or(i64::MAX), operation.node.clone(), *index)
    });
    let mut history: HashMap<Path, Vec<(usize, String, String)>> = HashMap::new();
    for (position, index) in order.into_iter().enumerate() {
        let Some(target) = operations[index].target.clone() else { continue };
        let key = target.clone();
        let prior = history.get(&key).into_iter().flatten()
            .filter(|(old_position, old_node, _)| *old_position < position && dominates(old_node, &operations[index].node))
            .max_by_key(|(_, _, generation)| generation.strip_prefix('g').and_then(|value| value.parse::<u32>().ok()).unwrap_or(0))
            .map(|(_, _, generation)| generation.clone());
        let current = prior.clone().unwrap_or_else(|| "g0".into());
        let kind = operations[index].kind;
        if matches!(kind, Kind::Alloc) {
            let generation = if prior.is_some() { next_generation(&current) } else { "g0".into() };
            operations[index].generation = Some(generation.clone());
            history.entry(key).or_default().push((position, operations[index].node.clone(), generation));
        } else if matches!(kind, Kind::Realloc) {
            operations[index].generation = Some(current.clone());
            let fresh = next_generation(&current);
            operations[index].fresh_generation = Some(fresh.clone());
            history.entry(key).or_default().push((position, operations[index].node.clone(), fresh));
        } else {
            operations[index].generation = Some(current);
            if matches!(kind, Kind::Clobber) {
                history.entry(key).or_default().push((position, operations[index].node.clone(), operations[index].generation.clone().unwrap()));
            }
        }
    }
}

fn next_generation(value: &str) -> String {
    value.strip_prefix('g').and_then(|item| item.parse::<u32>().ok())
        .map(|number| format!("g{}", number + 1)).unwrap_or_else(|| "g1".into())
}

/// Add only the access-path facts needed by the compact translation ABI. This
/// deliberately avoids CFG synthesis and operation extraction.
pub(crate) fn annotate_request(request: &mut lifetime_proto::PrepareRequest) {
    for input in &mut request.functions {
        let graph = GraphView::new(&input.nodes, &input.edges);
        for call in &mut input.calls {
            for argument in &mut call.arguments {
                argument.expression = graph.label(&argument.node).to_owned();
                if let Some(path) = graph.value_path(&argument.node, 0)
                    .or_else(|| graph.access_path(&argument.node, 0)) {
                    argument.root = path.root;
                    argument.selectors = path.selectors;
                }
            }
            if let Some(path) = graph.value_path(&call.assigned, 0)
                .or_else(|| graph.access_path(&call.assigned, 0)) {
                call.assigned_root = path.root;
                call.assigned_selectors = path.selectors;
            }
        }
        let call_by_node = input.calls.iter()
            .map(|call| (call.node.clone(), call.clone()))
            .collect::<HashMap<_, _>>();
        input.returns.clear();
        for node in &graph.nodes {
            let node_id = node.id.as_str();
            if graph.kind(node_id) != "ReturnStmt" { continue; }
            let line = integer_property(node, "start_line");
            let Some(child) = graph.children_of(node_id).into_iter().flatten()
                .min_by_key(|child| graph.offset(child)) else { continue };
            let peeled = graph.peel((*child).to_owned());
            if let Some(call) = call_by_node.get(&peeled) {
                input.returns.push(lifetime_proto::FunctionReturn {
                    kind: "call".to_owned(), callee: call.callee.clone(),
                    root: String::new(), selectors: Vec::new(),
                    line: line.unwrap_or_default(), has_line: line.is_some(),
                    root_name: String::new(),
                });
            } else if let Some(path) = graph.access_path(child, 0) {
                input.returns.push(lifetime_proto::FunctionReturn {
                    kind: "var".to_owned(), callee: String::new(),
                    root: path.root, selectors: path.selectors,
                    line: line.unwrap_or_default(), has_line: line.is_some(),
                    root_name: String::new(),
                });
            }
        }
    }
}

fn prepare_function(input: lifetime_proto::FunctionInput) -> lifetime_proto::PreparedFunction {
    let mut nodes = input.nodes;
    nodes.sort_by_key(|node| integer_property(node, "start_offset").unwrap_or(i64::MAX));
    let graph = GraphView::new(&nodes, &input.edges);
    let node_ids = nodes.iter().map(|node| node.id.clone()).collect::<Vec<_>>();
    let node_set = node_ids.iter().cloned().collect::<HashSet<_>>();

    let mut successor_map: HashMap<String, Vec<String>> = HashMap::new();
    for edge in &input.edges {
        if edge.kind == "CFG_NEXT" && node_set.contains(&edge.source) && node_set.contains(&edge.target) {
            successor_map.entry(edge.source.clone()).or_default().push(edge.target.clone());
        }
    }
    let mut prepared_from_cfg = None;
    if successor_map.is_empty() {
        if let Some((nodes, successors)) = synthesize_cfg(&graph, &node_set) {
            prepared_from_cfg = Some(nodes);
            successor_map = successors;
        }
    }
    let mut cfg_node_set = successor_map.keys().cloned()
        .chain(successor_map.values().flatten().cloned()).collect::<HashSet<_>>();
    // Pass-1's compact substrate may not contain frontend-generated cfg-exit
    // marker nodes. Keep the native CFG total by adding one synthetic terminal
    // and connecting explicit returns plus the source-order tail to it. This
    // also gives downstream semantic emission a valid fragment exit for loops
    // whose false arm is implicit in the AST.
    if !cfg_node_set.iter().any(|node| graph.kind(node) == "cfg-exit") {
        let synthetic_exit = format!("native-exit:{}", input.id);
        successor_map.entry(synthetic_exit.clone()).or_default();
        cfg_node_set.insert(synthetic_exit.clone());
        let mut terminals = node_ids.iter().filter(|node| is_return_kind(graph.kind(node)))
            .cloned().collect::<Vec<_>>();
        if let Some(last) = node_ids.last() {
            terminals.push(last.clone());
        }
        terminals.sort();
        terminals.dedup();
        for terminal in terminals {
            successor_map.entry(terminal).or_default().push(synthetic_exit.clone());
        }
    }

    let mut operations = Vec::new();
    let call_by_node = input.calls.iter().map(|call| (call.node.clone(), call.clone())).collect::<HashMap<_, _>>();

    // Assignment/declaration and dereference operations are prepared from the
    // raw AST here, before the request reaches the abstract-state solver.
    for node_id in &node_ids {
        let kind = graph.kind(node_id);
        let children = graph.children_owned(node_id);
        if kind == "write" || kind == "definition" {
            let line = graph.node(node_id).and_then(|node| integer_property(node, "start_line"));
            let target = graph.property(node_id, "target_id")
                .and_then(|id| graph.access_path(id, 0));
            let value_id = graph.property(node_id, "value_id");
            let source = value_id.and_then(|id| graph.value_path(id, 0));
            let value_source = value_id.and_then(|id| graph.value_source(id, 0));
            if let Some(target) = target {
                let origin = value_source.and_then(|source| call_by_node.get(source))
                    .map(|call| call.is_alloc || call.is_source)
                    .unwrap_or_else(|| value_source.is_some_and(|source| graph.kind(source) == "allocation"));
                operations.push(raw_operation(
                    if origin { Kind::Alloc } else if source.is_some() { Kind::Copy } else { Kind::Clobber },
                    node_id,
                    Some(target),
                    source,
                    line,
                    false,
                    "deref",
                ));
            }
        } else if kind == "read" {
            let line = graph.node(node_id).and_then(|node| integer_property(node, "start_line"));
            if let Some(target) = graph.property(node_id, "target_id")
                .and_then(|id| graph.access_path(id, 0)) {
                operations.push(raw_operation(Kind::Use, node_id, Some(target), None,
                    line, false, "deref"));
            }
        } else if kind == "release" {
            let line = graph.node(node_id).and_then(|node| integer_property(node, "release_line"))
                .or_else(|| graph.node(node_id).and_then(|node| integer_property(node, "start_line")));
            if let Some(target) = graph.property(node_id, "target_id")
                .and_then(|id| graph.access_path(id, 0)) {
                operations.push(raw_operation(Kind::Free, node_id, Some(target), None,
                    line, false, "release"));
            }
        } else if kind == "BinaryOperator" && matches!(graph.operator(node_id), "==" | "!=" | "<" | "<=" | ">" | ">=") {
            for child in &children {
                if graph.is_pointer(child) {
                    if let Some(target) = graph.access_path(child, 0) {
                        operations.push(raw_operation(
                            Kind::Use,
                            node_id,
                            Some(target),
                            None,
                            graph.node(node_id).and_then(|node| integer_property(node, "start_line")),
                            false,
                            "compare",
                        ));
                    }
                }
            }
        } else if kind == "BinaryOperator" && graph.operator(node_id) == "=" && children.len() >= 2 {
            let mut ordered = children;
            ordered.sort_by_key(|child| graph.offset(child));
            let rhs = ordered.get(1).or_else(|| ordered.first());
            let lhs = ordered.first();
            if let (Some(lhs), Some(rhs)) = (lhs, rhs) {
                let line = graph.node(node_id).and_then(|node| integer_property(node, "start_line"));
                if let Some(target) = graph.deref_base(lhs) {
                    operations.push(raw_operation(Kind::Use, node_id, Some(target), graph.access_path(rhs, 0), line, false, "write"));
                }
                if graph.is_pointer(lhs) {
                    if let Some(target) = graph.access_path(lhs, 0) {
                        let rhs_id = graph.peel(rhs.clone());
                        let (kind, source, is_null) = if let Some(call) = call_by_node.get(&rhs_id) {
                            if call.is_alloc { (Kind::Alloc, None, false) }
                            else if call.is_realloc {
                                let source = call.arguments.iter().find(|arg| arg.position == 0)
                                    .and_then(|arg| graph.access_path(&arg.node, 0));
                                (Kind::Realloc, source, false)
                            }
                            else if call.is_source { (Kind::Clobber, None, false) }
                            else { (Kind::Clobber, graph.access_path(&rhs_id, 0), false) }
                        } else if let Some(source) = graph.conditional_value_source(&rhs_id) {
                            (Kind::Copy, Some(source), false)
                        } else if graph.is_null(&rhs_id) {
                            (Kind::Clobber, None, true)
                        } else if let Some(source) = graph.access_path(&rhs_id, 0) {
                            (Kind::Copy, Some(source), false)
                        } else {
                            (Kind::Clobber, None, false)
                        };
                        operations.push(raw_operation(kind, node_id, Some(target), source, line, is_null, "deref"));
                    }
                }
            }
        } else if kind == "VarDecl" && graph.is_pointer(node_id) {
            let line = graph.node(node_id).and_then(|node| integer_property(node, "start_line"));
            let target = path(Some(node_id));
            if let Some(initializer) = graph.initializer_of(node_id) {
                let initializer = graph.peel(initializer.to_owned());
                let (kind, source, is_null) = if let Some(call) = call_by_node.get(&initializer) {
                    if call.is_alloc { (Kind::Alloc, None, false) }
                    else if call.is_realloc {
                        let source = call.arguments.iter().find(|arg| arg.position == 0)
                            .and_then(|arg| graph.access_path(&arg.node, 0));
                        (Kind::Realloc, source, false)
                    }
                    else if call.is_source { (Kind::Clobber, None, false) }
                    else { (Kind::Copy, graph.access_path(&initializer, 0), false) }
                } else if let Some(source) = graph.conditional_value_source(&initializer) {
                    (Kind::Copy, Some(source), false)
                } else if graph.is_null(&initializer) {
                    (Kind::Clobber, None, true)
                } else if let Some(source) = graph.access_path(&initializer, 0) {
                    (Kind::Copy, Some(source), false)
                } else { (Kind::Clobber, None, false) };
                operations.push(raw_operation(kind, node_id, target, source, line, is_null, "deref"));
                if let Some(source) = graph.pointer_arithmetic_source(&initializer) {
                    operations.push(raw_operation(
                        Kind::Use,
                        node_id,
                        graph.access_path(node_id, 0),
                        Some(source),
                        line,
                        false,
                        "pointer-arithmetic",
                    ));
                }
            } else {
                operations.push(raw_operation(Kind::Clobber, node_id, target, None, line, false, "uninitialized"));
            }
        }

        let assignment_lhs = graph.parent_of(node_id).is_some_and(|parent| {
            graph.kind(parent) == "BinaryOperator" && graph.operator(parent) == "=" &&
            graph.children_of(parent).into_iter().flatten()
                .min_by_key(|child| graph.offset(child))
                .is_some_and(|child| graph.peel((*child).to_owned()) == graph.peel(node_id.clone()))
        });
        if !assignment_lhs {
            if let Some(base) = graph.deref_base(node_id) {
                operations.push(raw_operation(Kind::Use, node_id, Some(base), None,
                    graph.node(node_id).and_then(|node| integer_property(node, "start_line")),
                    false, "deref"));
            }
        }
    }
    let summary_by_callee = input.summaries.iter().map(|summary| (summary.callee.as_str(), summary)).collect::<HashMap<_, _>>();
    let mut calls = input.calls;
    calls.sort_by_key(|call| (if call.has_line { call.line } else { i64::MAX }, call.node.clone()));
    for call in &mut calls {
        for argument in &mut call.arguments {
            argument.expression = graph.label(&argument.node).to_owned();
            if let Some(path) = graph.value_path(&argument.node, 0)
                .or_else(|| graph.access_path(&argument.node, 0)) {
                argument.root = path.root;
                argument.selectors = path.selectors;
            }
        }
        if let Some(path) = graph.value_path(&call.assigned, 0)
            .or_else(|| graph.access_path(&call.assigned, 0)) {
            call.assigned_root = path.root;
            call.assigned_selectors = path.selectors;
        }
    }
    for call in &calls {
        let argument = |position: u32| call.arguments.iter().find(|item| item.position == position)
            .and_then(|item| graph.value_path(&item.node, 0)
                .or_else(|| graph.access_path(&item.node, 0))
                .or_else(|| path(Some(&item.node))));
        let target = path(Some(&call.assigned)).or_else(|| path(Some(&call.receiver)));
        let source = argument(0);
        if call.is_release {
            if let Some(target) = source.or_else(|| target.clone()) {
                operations.push(operation(Kind::Free, &call.node, Some(target), None, call));
            }
        } else if call.is_realloc {
            // Assignment/VarDecl preparation above owns realloc's destination.
            continue;
        } else if call.is_alloc || call.is_source {
            if let Some(target) = target {
                operations.push(operation(
                    if call.is_alloc { Kind::Alloc } else { Kind::Clobber },
                    &call.node, Some(target), None, call,
                ));
            }
        } else if call.is_aggregate_copy {
            if let (Some(destination), Some(source)) = (argument(0), argument(1)) {
                let mut aggregate = operation(
                    Kind::Copy, &call.node, Some(destination), Some(source), call);
                aggregate.access = "aggregate-copy".to_owned();
                operations.push(aggregate);
            }
        } else if let Some(summary) = summary_by_callee.get(call.callee.as_str())
            .filter(|summary| !summary.alternatives.is_empty()) {
            for alternative in &summary.alternatives {
                let mut effects = Vec::new();
                for effect in &alternative.effects {
                    let actual = call.arguments.iter().find(|argument| argument.position == effect.position)
                        .and_then(|argument| graph.value_path(&argument.node, 0)
                            .or_else(|| graph.access_path(&argument.node, 0))
                            .or_else(|| path(Some(&argument.node))));
                    let Some(mut actual) = actual else { continue };
                    actual.selectors.extend(effect.selectors.iter().cloned());
                    if effect.is_return {
                        if let Some(destination) = target.clone() {
                            effects.push(raw_operation(Kind::Copy, &call.node, Some(destination), Some(actual), call.line.checked_add(0), false, "return-alias"));
                        }
                    } else if let Ok(kind) = lifetime_proto::operation::Kind::try_from(effect.kind) {
                        let kind = match kind {
                            lifetime_proto::operation::Kind::Alloc => Kind::Alloc,
                            lifetime_proto::operation::Kind::Clobber => Kind::Clobber,
                            lifetime_proto::operation::Kind::Copy => Kind::Copy,
                            lifetime_proto::operation::Kind::Free => Kind::Free,
                            lifetime_proto::operation::Kind::Realloc => Kind::Realloc,
                            lifetime_proto::operation::Kind::Use => Kind::Use,
                            lifetime_proto::operation::Kind::Summary | lifetime_proto::operation::Kind::Unspecified => continue,
                        };
                        effects.push(raw_operation(kind, &call.node, Some(actual), None, call.has_line.then_some(call.line), false, "summary"));
                    }
                }
                if !effects.is_empty() {
                    let mut summary_operation = operation(Kind::Summary, &call.node, None, None, call);
                    summary_operation.alternatives.push(effects);
                    operations.push(summary_operation);
                }
            }
        } else {
            for argument in &call.arguments {
                if let Some(target) = graph.value_path(&argument.node, 0)
                    .or_else(|| graph.access_path(&argument.node, 0))
                    .or_else(|| path(Some(&argument.node))) {
                    // Match the generic Python operation contract: an
                    // argument to an unknown/ordinary callee is a value pass,
                    // not a proven pointee dereference. The temporal matcher
                    // can still report a dangling value after a release.
                    operations.push(raw_operation(
                        Kind::Use,
                        &call.node,
                        Some(target),
                        None,
                        call.has_line.then_some(call.line),
                        false,
                        "pass",
                    ));
                }
            }
        }
    }
    let mut returns = Vec::new();
    for node in &graph.nodes {
        let node_id = node.id.as_str();
        if !is_return_kind(graph.kind(node_id)) { continue; }
        let line = integer_property(node, "start_line");
        let child = graph.children_of(node_id).into_iter().flatten()
            .min_by_key(|child| graph.offset(child));
        let Some(child) = child else { continue };
        let peeled = graph.peel((*child).to_owned());
        if let Some(call) = call_by_node.get(&peeled) {
            returns.push(lifetime_proto::FunctionReturn {
                kind: "call".to_owned(), callee: call.callee.clone(),
                root: String::new(), selectors: Vec::new(),
                line: line.unwrap_or_default(), has_line: line.is_some(),
                root_name: String::new(),
            });
        } else if let Some(path) = graph.value_path(child, 0)
            .or_else(|| graph.access_path(&child, 0)) {
            let root_id = path.root.strip_prefix("decl:").unwrap_or(path.root.as_str());
            let stack_local = graph.node(root_id)
                .is_some_and(|root| {
                    graph.kind(root_id) == "VarDecl"
                        && text_property(root, "owner_function_id") == Some(input.id.as_str())
                        && (text_property(root, "type").is_some_and(|value| value.contains('['))
                            || path.selectors.iter().any(|selector| selector == "&"))
                });
            operations.push(raw_operation(
                Kind::Use,
                node_id,
                Some(path.clone()),
                None,
                line,
                false,
                if stack_local { "return-stack" } else { "return" },
            ));
            returns.push(lifetime_proto::FunctionReturn {
                kind: "var".to_owned(), callee: String::new(),
                root: path.root, selectors: path.selectors,
                line: line.unwrap_or_default(), has_line: line.is_some(),
                root_name: String::new(),
            });
        } else if graph.is_null(&peeled) {
            operations.push(raw_operation(
                Kind::Clobber,
                node_id,
                Some(Path::root("__return__")),
                None,
                line,
                false,
                "return-null",
            ));
        }
    }
    returns.sort_by_key(|item| (if item.has_line { item.line } else { i64::MAX }, item.root.clone()));

    // Map expression anchors to the nearest CFG node. The solver consumes the
    // synthesized statement CFG, while operation extraction remains expression
    // precise above.
    for item in &mut operations {
        let mut anchor = item.node.clone();
        let mut seen = HashSet::new();
        while !cfg_node_set.contains(&anchor) && seen.insert(anchor.clone()) {
            let Some(parent) = graph.parent_of(&anchor) else { break };
            anchor = parent.to_owned();
        }
        if !cfg_node_set.contains(&anchor) {
            if let Some(initializer) = graph.initializer_of(&item.node) {
                let initializer = graph.peel(initializer.to_owned());
                if cfg_node_set.contains(&initializer) { anchor = initializer; }
            }
        }
        if !cfg_node_set.contains(&anchor) {
            let operation_line = graph.node(&item.node)
                .and_then(|node| integer_property(node, "start_line"));
            if let Some(line) = operation_line {
                if let Some(nearest) = cfg_node_set.iter()
                    .filter(|candidate| graph.node(candidate)
                        .and_then(|node| integer_property(node, "start_line")) == Some(line))
                    .min_by_key(|candidate| graph.offset(candidate).abs_diff(graph.offset(&item.node))) {
                    anchor = nearest.clone();
                }
            }
        }
        if !cfg_node_set.contains(&anchor) {
            // Some compiler ASTs do not persist an AST-parent edge from an
            // expression to the statement CFG. Attach the operation to the
            // closest preceding CFG anchor by source offset so control-flow
            // order remains authoritative without inventing a new path.
            let operation_offset = graph.offset(&item.node);
            if let Some(nearest) = cfg_node_set.iter()
                .filter(|candidate| graph.offset(candidate) <= operation_offset)
                .max_by_key(|candidate| graph.offset(candidate)) {
                anchor = nearest.clone();
            }
        }
        if cfg_node_set.contains(&anchor) { item.node = anchor; }
    }
    operations.retain(|item| node_set.contains(&item.node));
    let mut prepared_nodes = if let Some(nodes) = prepared_from_cfg {
        nodes
    } else if cfg_node_set.is_empty() {
        let operation_nodes = operations.iter().map(|item| item.node.as_str()).collect::<HashSet<_>>();
        let mut values = node_ids.iter().filter(|node| {
            operation_nodes.contains(node.as_str()) || matches!(graph.kind(node),
                "DeclRefExpr" | "CallExpr" | "CXXMemberCallExpr" | "CXXOperatorCallExpr" |
                "BinaryOperator" | "CompoundAssignOperator" | "UnaryOperator" |
                "ConditionalOperator" | "MemberExpr" | "ArraySubscriptExpr" |
                "IntegerLiteral" | "FloatingLiteral" | "StringLiteral" |
                "CharacterLiteral" | "CXXBoolLiteralExpr" | "ImplicitValueInitExpr" |
                "GNUNullExpr" | "CXXNullPtrLiteralExpr" | "VarDecl" | "ParmVarDecl" |
                "function" | "method" | "constructor" | "statement" | "expression" |
                "call" | "Call" | "CallExpression" | "construct" | "NewExpression" |
                "Return" | "ReturnStatement" | "return")
        }).cloned().collect::<Vec<_>>();
        values.sort();
        values.sort_by_key(|node| graph.offset(node));
        values.dedup();
        values
    } else {
        let mut values = node_ids.iter().filter(|node| cfg_node_set.contains(*node)).cloned().collect::<Vec<_>>();
        values.sort_by_key(|node| graph.offset(node));
        values
    };
    let mut extra_cfg_nodes: Vec<_> = cfg_node_set.iter().filter(|node| !prepared_nodes.contains(node))
        .cloned().collect();
    extra_cfg_nodes.sort_by(|left, right| (graph.offset(left), left).cmp(&(graph.offset(right), right)));
    for node in extra_cfg_nodes {
        prepared_nodes.push(node);
    }
    prepared_nodes.sort_by(|left, right| (graph.offset(left), left).cmp(&(graph.offset(right), right)));
    prepared_nodes.dedup();
    let prepared_set = prepared_nodes.iter().cloned().collect::<HashSet<_>>();
    operations.retain(|item| prepared_set.contains(&item.node));

    // A few frontend snapshots contain only AST/CFG marker nodes and no
    // CFG_NEXT edges. In that case chain the compact operation anchors, not
    // every raw graph record; this keeps the fallback bounded and preserves
    // source order until structured AST CFG synthesis handles branches.
    if successor_map.is_empty() {
        for pair in prepared_nodes.windows(2) {
            successor_map.entry(pair[0].clone()).or_default().push(pair[1].clone());
        }
        // Recover the common if/else shape from AST role edges. This keeps
        // path correlation for the native solver even when the persisted graph
        // has statement CFG markers but no CFG_NEXT relation.
            let mut if_nodes = graph.nodes.iter().filter_map(|node| {
                (graph.kind(node.id.as_str()) == "IfStmt").then(|| node.id.clone())
            }).collect::<Vec<_>>();
        if_nodes.sort_by_key(|node| graph.offset(node));
        for if_node in if_nodes {
            let true_roots = graph.role_children_owned(&if_node, "TRUE_BRANCH");
            let false_roots = graph.role_children_owned(&if_node, "FALSE_BRANCH");
            if true_roots.is_empty() { continue; }
            let branch_nodes = |roots: &[String]| prepared_nodes.iter().filter(|node| {
                roots.iter().any(|root| graph.is_descendant(node, root))
            }).cloned().collect::<Vec<_>>();
            let true_nodes = branch_nodes(&true_roots);
            let false_nodes = branch_nodes(&false_roots);
            if true_nodes.is_empty() { continue; }
            let first_branch_offset = true_nodes.iter().chain(false_nodes.iter()).map(|node| graph.offset(node)).min().unwrap_or(i64::MAX);
            let last_branch_offset = true_nodes.iter().chain(false_nodes.iter()).map(|node| graph.offset(node)).max().unwrap_or(i64::MIN);
            let before = prepared_nodes.iter().filter(|node| graph.offset(node) < first_branch_offset).cloned().collect::<Vec<_>>();
            let after = prepared_nodes.iter().filter(|node| graph.offset(node) > last_branch_offset).cloned().collect::<Vec<_>>();
            let continuation = after.first().cloned();
            let entry = before.last().cloned().or_else(|| prepared_nodes.first().cloned());
            if let Some(entry) = entry {
                successor_map.remove(&entry);
                let mut targets = vec![true_nodes[0].clone()];
                if let Some(false_entry) = false_nodes.first() {
                    targets.push(false_entry.clone());
                } else if let Some(next) = continuation.clone() {
                    targets.push(next);
                }
                targets.sort();
                targets.dedup();
                successor_map.insert(entry, targets);
            }
            for branch in [&true_nodes, &false_nodes] {
                if let Some(last) = branch.last() {
                    successor_map.remove(last);
                    if let Some(next) = continuation.clone() {
                        successor_map.insert(last.clone(), vec![next]);
                    }
                }
            }
        }
        // Malformed or macro-expanded ASTs can make a role-derived branch
        // boundary point back into an earlier source interval. Never hand a
        // cyclic approximation to the native worklist: use a conservative
        // source-order chain until structured CFG synthesis can resolve it.
        let mut color: HashMap<String, u8> = HashMap::new();
        fn visit(node: &str, successors: &HashMap<String, Vec<String>>, color: &mut HashMap<String, u8>) -> bool {
            match color.get(node).copied().unwrap_or(0) {
                1 => return true,
                2 => return false,
                _ => {}
            }
            color.insert(node.to_owned(), 1);
            for successor in successors.get(node).into_iter().flatten() {
                if visit(successor, successors, color) { return true; }
            }
            color.insert(node.to_owned(), 2);
            false
        }
        let cyclic = prepared_nodes.iter().any(|node| visit(node, &successor_map, &mut color));
        if cyclic {
            successor_map.clear();
            for pair in prepared_nodes.windows(2) {
                successor_map.entry(pair[0].clone()).or_default().push(pair[1].clone());
            }
        }
    }
    let loop_nodes = cyclic_nodes(&prepared_nodes, &successor_map);
    let offsets: HashMap<String, i64> = nodes.iter().filter_map(|node| {
        integer_property(node, "start_offset")
            .map(|offset| (node.id.clone(), offset))
    }).collect();
    assign_generations(&mut operations, &prepared_nodes, &successor_map, &offsets);
    let mut guard_map: HashMap<(String, String), Vec<lifetime_proto::GuardProof>> = HashMap::new();
    for edge in &input.edges {
        if matches!(edge.kind.as_str(), "TRUE_BRANCH" | "FALSE_BRANCH") {
            let proofs = branch_guards(&graph, &edge.source, &edge.kind);
            if !proofs.is_empty() {
                guard_map.insert((edge.source.clone(), edge.target.clone()), proofs);
            }
        }
    }
    let mut successors = successor_map.into_iter().map(|(node, mut targets)| {
        targets.sort();
        targets.dedup();
        let guarded_targets = targets.iter().filter_map(|target| {
            guard_map.get(&(node.clone(), target.clone())).map(|guards|
                lifetime_proto::GuardedTarget { target: target.clone(), guards: guards.clone() })
        }).collect();
        lifetime_proto::Successors { node, targets, guarded_targets }
    }).collect::<Vec<_>>();
    successors.sort_by(|left, right| left.node.cmp(&right.node));
    operations.sort_by_key(|item| (item.line.unwrap_or(i64::MAX), item.node.clone(), item.kind as u8));

    // Retain only metadata needed by semantic emission: prepared CFG anchors,
    // operation paths, and their declaration roots. This is intentionally
    // bounded by the prepared function rather than the complete substrate.
    let mut metadata_ids: HashSet<String> = prepared_nodes.iter().cloned().collect();
    for operation in &operations {
        metadata_ids.insert(operation.node.clone());
        for path in [operation.target.as_ref(), operation.source.as_ref()].into_iter().flatten() {
            metadata_ids.insert(path.root.trim_start_matches("decl:").to_owned());
        }
    }
    let metadata = nodes.iter().filter(|node| metadata_ids.contains(&node.id)).map(|node| {
        let offset = integer_property(node, "start_offset");
        lifetime_proto::SemanticNodeMetadata {
            id: node.id.clone(), label: node.label.clone(),
            kind: text_property(node, "syntax_kind").map(str::to_owned).unwrap_or_else(|| node.kind.clone()),
            owner: text_property(node, "owner_function_id")
                .or_else(|| text_property(node, "function_id")).unwrap_or_default().to_owned(),
            r#type: text_property(node, "type").unwrap_or_default().to_owned(),
            offset: offset.unwrap_or_default(), has_offset: offset.is_some(),
        }
    }).collect::<Vec<_>>();

    lifetime_proto::PreparedFunction {
        id: input.id,
        nodes: prepared_nodes,
        successors,
        operations: operations.into_iter().map(crate::proto_operation_message).collect(),
        parameters: input.parameters,
        calls,
        returns,
        metadata,
        loop_nodes,
    }
}

pub(crate) fn solve(input: &[u8]) -> Result<Vec<u8>, String> {
    let request = lifetime_proto::PrepareRequest::decode(input)
        .map_err(|error| format!("invalid lifetime preparation protobuf: {error}"))?;
    solve_request(request)
}

pub(crate) fn solve_request(request: lifetime_proto::PrepareRequest) -> Result<Vec<u8>, String> {
    let result = lifetime_proto::PrepareResult {
        functions: request.functions.into_iter().map(prepare_function).collect(),
    };
    let mut output = Vec::new();
    result.encode(&mut output).map_err(|error| error.to_string())?;
    Ok(output)
}

pub(crate) fn prepare_and_solve(input: &[u8]) -> Result<Vec<u8>, String> {
    let request = lifetime_proto::PrepareRequest::decode(input)
        .map_err(|error| format!("invalid lifetime preparation protobuf: {error}"))?;
    prepare_and_solve_request(request)
}

pub(crate) fn prepare_and_solve_request(
    request: lifetime_proto::PrepareRequest,
) -> Result<Vec<u8>, String> {
    let prepared = prepare_functions(request.functions)?;
    solve_prepared_functions(prepared, false)
}

pub(crate) fn prepare_and_solve_request_with_metadata(
    request: lifetime_proto::PrepareRequest,
) -> Result<Vec<u8>, String> {
    let prepared = prepare_functions(request.functions)?;
    solve_prepared_functions(prepared, true)
}

fn semantic_event_kind(kind: crate::Kind, access: &str) -> &'static str {
    match kind {
        crate::Kind::Alloc => "ORIGIN",
        crate::Kind::Free => "RELEASE",
        crate::Kind::Realloc => "INVALIDATE",
        crate::Kind::Copy => "DERIVE",
        crate::Kind::Use => match access {
            "pass" => "PASS_VALUE",
            "compare" => "COMPARE_VALUE",
            "return" | "return-stack" => "RETURN_VALUE",
            "pointer-arithmetic" => "POINTER_ARITHMETIC",
            "write" => "WRITE_STORAGE",
            _ => "READ_STORAGE",
        },
        crate::Kind::Clobber => match access {
            "uninitialized" => "UNINITIALIZED",
            "return-null" => "RETURN_VALUE",
            "source" => "ORIGIN",
            _ => "DERIVE",
        },
        crate::Kind::Summary => "DERIVE",
    }
}

fn semantic_node(id: String, function: &str, kind: &str, operation: &crate::Operation,
                 path: Option<&crate::Path>, generation: &str) -> lifetime_proto::NativeSemanticNode {
    lifetime_proto::NativeSemanticNode {
        id,
        function: function.to_owned(),
        event_kind: kind.to_owned(),
        object_root: path.map(|value| value.root.clone()).unwrap_or_default(),
        object_selectors: path.map(|value| value.selectors.clone()).unwrap_or_default(),
        generation: generation.to_owned(),
        line: operation.line.unwrap_or_default(),
        has_line: operation.line.is_some(),
        anchor: operation.node.clone(),
        stack_local: operation.access == "return-stack",
        is_null: operation.is_null,
        access: operation.access.clone(),
        value_root: operation.source.as_ref().map(|value| value.root.clone()).unwrap_or_default(),
        value_selectors: operation.source.as_ref().map(|value| value.selectors.clone()).unwrap_or_default(),
        source_witness_nodes: Vec::new(),
        source_reachable: None,
    }
}

fn semantic_language(function: &str) -> String {
    if function.contains(":cpython-ast:") || function.contains(":python:") {
        "python".to_owned()
    } else if function.contains(":typescript-compiler-api:")
        || function.contains(":typescript:") {
        "typescript".to_owned()
    } else if function.contains(":javascript:") {
        "javascript".to_owned()
    } else if function.contains(":clang-c:") || function.contains(":clang-c-native:")
        || function.contains(":clang-cpp:") {
        // The native Clang frontend may contain C and C++ roots together;
        // the function ID does not encode the individual source extension.
        "mixed".to_owned()
    } else {
        "mixed".to_owned()
    }
}

/// Emit the compact event graph consumed by the semantic query layer.  This
/// deliberately carries operation-derived events and CFG relations only; the
/// original AST and solver snapshots never cross the native boundary.
pub(crate) fn semantic_request(
    request: lifetime_proto::PrepareRequest,
) -> Result<lifetime_proto::NativeSemanticResult, String> {
    let prepared = prepare_functions(request.functions)?;
    let by_id: HashMap<String, usize> = prepared.iter().enumerate()
        .map(|(index, function)| (function.id.clone(), index)).collect();
    let mut seams = Vec::new();
    for caller in &prepared {
        for call in &caller.calls {
            let Some(&callee_index) = by_id.get(&call.callee) else { continue };
            let callee = &prepared[callee_index];
            let Some(entry_anchor) = callee.nodes.first() else { continue };
            let formal_to_actual = call.arguments.iter().filter_map(|argument| {
                let formal = callee.parameters.get(argument.position as usize)?;
                let actual = if !argument.root_name.is_empty() {
                    format!("{}{}", argument.root_name, argument.selectors.join(""))
                } else if !argument.root.is_empty() {
                    format!("{}{}", argument.root.trim_start_matches("decl:"), argument.selectors.join(""))
                } else if !argument.expression.is_empty() {
                    argument.expression.clone()
                } else {
                    return None;
                };
                Some(format!("{formal}\u{1f}{actual}"))
            }).collect();
            let return_to = if !call.assigned_name.is_empty() {
                format!("{}{}", call.assigned_name, call.assigned_selectors.join(""))
            } else {
                call.assigned.clone()
            };
            seams.push(lifetime_proto::NativeSemanticEdge {
                source: format!("native:{}:anchor:{}", caller.id, call.node),
                target: format!("native:{}:anchor:{}", callee.id, entry_anchor),
                kind: "seam".into(), guards: Vec::new(),
                bindings: vec![lifetime_proto::NativeSeamBinding {
                    caller: caller.id.clone(), callee: callee.id.clone(), call_node: call.node.clone(),
                    formal_to_actual, return_to: return_to.clone(),
                }],
                seam_kind: "call".into(), callee: callee.id.clone(),
                return_to, provenance: "compiler-call".into(),
            });
        }
    }
    let functions = prepared.into_iter().map(|function| {
        let id = function.id.clone();
        let mut nodes = Vec::new();
        let mut by_anchor: HashMap<String, Vec<String>> = HashMap::new();
        let mut realloc_failures: Vec<(String, String, String)> = Vec::new();
        // Preserve the prepared CFG topology even when an anchor has no
        // lifetime operation.  These empty-event nodes are the compact native
        // equivalent of the Python semantic graph's control-flow substrate.
        for anchor in &function.nodes {
            let node_id = format!("native:{}:anchor:{}", id, anchor);
            by_anchor.entry(anchor.clone()).or_default().push(node_id.clone());
            nodes.push(lifetime_proto::NativeSemanticNode {
                id: node_id,
                function: id.clone(),
                event_kind: String::new(),
                object_root: String::new(),
                object_selectors: Vec::new(),
                generation: String::new(),
                line: 0,
                has_line: false,
                anchor: anchor.clone(),
                stack_local: false,
                is_null: false,
                access: String::new(),
                value_root: String::new(),
                value_selectors: Vec::new(),
                source_witness_nodes: Vec::new(),
                source_reachable: None,
            });
        }
        let mut incoming_counts: HashMap<String, usize> = HashMap::new();
        for successor in &function.successors {
            for target in &successor.targets {
                *incoming_counts.entry(target.clone()).or_default() += 1;
            }
        }
        for anchor in &function.nodes {
            let outgoing = function.successors.iter()
                .find(|item| item.node == *anchor)
                .map(|item| item.targets.len()).unwrap_or(0);
            let mut markers = Vec::new();
            if outgoing > 1 { markers.push("BRANCH"); }
            if incoming_counts.get(anchor).copied().unwrap_or(0) > 1 {
                markers.push("MERGE");
            }
            if function.loop_nodes.iter().any(|item| item == anchor) {
                markers.push("LOOP");
            }
            for (ordinal, kind) in markers.into_iter().enumerate() {
                let node_id = format!("native:{}:marker:{}:{}", id, anchor, ordinal);
                by_anchor.entry(anchor.clone()).or_default().push(node_id.clone());
                nodes.push(lifetime_proto::NativeSemanticNode {
                    id: node_id, function: id.clone(), event_kind: kind.into(),
                    object_root: String::new(), object_selectors: Vec::new(),
                    generation: String::new(), line: 0, has_line: false,
                    anchor: anchor.clone(),
                    stack_local: false, is_null: false, access: String::new(),
                    value_root: String::new(), value_selectors: Vec::new(),
                    source_witness_nodes: Vec::new(), source_reachable: None,
                });
            }
        }
        let plain_call_nodes: HashSet<&str> = function.calls.iter()
            .filter(|call| !call.is_alloc && !call.is_release && !call.is_realloc
                && !call.is_source && !call.is_aggregate_copy)
            .map(|call| call.node.as_str()).collect();
        for (index, raw) in function.operations.iter().cloned().enumerate() {
            let operation = crate::proto_operation(raw)?;
            // Passing an argument to an ordinary call is not a dereference
            // event.  The preparation layer uses the same Use operation kind
            // for its conservative value-flow fallback, but the semantic
            // graph must not turn every call argument into a storage read.
            if operation.kind == crate::Kind::Use
                && operation.access == "deref"
                && plain_call_nodes.contains(operation.node.as_str()) {
                continue;
            }
            let path = operation.target.as_ref();
            let generation = operation.generation.as_deref().unwrap_or("g0");
            let kinds: Vec<&str> = match operation.kind {
                crate::Kind::Alloc => vec!["ALLOC_ATTEMPT", "ORIGIN"],
                crate::Kind::Realloc => vec!["REALLOC_ATTEMPT", "INVALIDATE", "ORIGIN"],
                crate::Kind::Clobber if operation.access == "return-null" =>
                    vec!["RETURN_VALUE", "RETURN"],
                crate::Kind::Use if operation.access == "return"
                    || operation.access == "return-stack" =>
                    vec!["RETURN_VALUE", "ESCAPE", "RETURN"],
                _ => vec![semantic_event_kind(operation.kind, &operation.access)],
            };
            let attempt_id = (operation.kind == crate::Kind::Realloc)
                .then(|| format!("native:{}:{}:{}:0", id, operation.node, index));
            for (ordinal, kind) in kinds.into_iter().enumerate() {
                let kind = if operation.is_null { "WRITE_STORAGE_NULL" } else { kind };
                let node_id = format!("native:{}:{}:{}:{}", id, operation.node, index, ordinal);
                let event_generation = if kind == "ORIGIN" && operation.kind == crate::Kind::Realloc {
                    operation.fresh_generation.as_deref().unwrap_or(generation)
                } else { generation };
                let event = semantic_node(node_id.clone(), &id, kind, &operation, path, event_generation);
                by_anchor.entry(operation.node.clone()).or_default().push(node_id);
                nodes.push(event);
            }
            if operation.kind == crate::Kind::Realloc {
                let failure_id = format!("native:{}:{}:{}:failure", id, operation.node, index);
                nodes.push(semantic_node(failure_id.clone(), &id, "REALLOC_FAILED",
                    &operation, path, generation));
                if let Some(attempt_id) = attempt_id {
                    realloc_failures.push((attempt_id, failure_id, operation.node.clone()));
                }
            }
        }
        let mut edges = Vec::new();
        for successor in &function.successors {
            let Some(source_nodes) = by_anchor.get(&successor.node) else { continue };
            let source = source_nodes.last().cloned().unwrap_or_default();
            for target_anchor in &successor.targets {
                if let Some(target_nodes) = by_anchor.get(target_anchor) {
                    if let Some(target) = target_nodes.first() {
                        edges.push(lifetime_proto::NativeSemanticEdge {
                            source: source.clone(), target: target.clone(), kind: "normal".into(),
                            guards: successor.guarded_targets.iter()
                                .find(|item| item.target == *target_anchor)
                                .map(|item| item.guards.clone()).unwrap_or_default(),
                            bindings: Vec::new(), seam_kind: String::new(), callee: String::new(),
                            return_to: String::new(), provenance: String::new(),
                        });
                    }
                }
            }
        }
        for node_ids in by_anchor.values() {
            for pair in node_ids.windows(2) {
                edges.push(lifetime_proto::NativeSemanticEdge {
                    source: pair[0].clone(), target: pair[1].clone(), kind: "normal".into(), guards: Vec::new(),
                    bindings: Vec::new(), seam_kind: String::new(), callee: String::new(),
                    return_to: String::new(), provenance: String::new(),
                });
            }
        }
        // Realloc has two semantic outcomes. Keep the failure node out of the
        // same-anchor linear chain and add an explicit alternate edge; both
        // outcomes then continue through the original CFG successors.
        for (attempt, failure, anchor) in realloc_failures {
            edges.push(lifetime_proto::NativeSemanticEdge {
                source: attempt, target: failure.clone(), kind: "realloc-failure".into(), guards: Vec::new(),
                bindings: Vec::new(), seam_kind: String::new(), callee: String::new(),
                return_to: String::new(), provenance: String::new(),
            });
            if let Some(successors) = function.successors.iter().find(|item| item.node == anchor) {
                for target_anchor in &successors.targets {
                    if let Some(target) = by_anchor.get(target_anchor).and_then(|items| items.first()) {
                        edges.push(lifetime_proto::NativeSemanticEdge {
                            source: failure.clone(), target: target.clone(), kind: "normal".into(), guards: Vec::new(),
                            bindings: Vec::new(), seam_kind: String::new(), callee: String::new(),
                            return_to: String::new(), provenance: String::new(),
                        });
                    }
                }
            }
        }
        let entry = function.nodes.iter().find_map(|node| by_anchor.get(node)
            .and_then(|ids| ids.first()).cloned()).unwrap_or_default();
        let exits = function.nodes.iter().filter(|node|
            function.successors.iter().any(|item| item.node == **node && item.targets.is_empty())
                || function.successors.iter().all(|item| item.node != **node))
            .filter_map(|node| by_anchor.get(node).and_then(|ids| ids.last()).cloned())
            .collect();
        // `by_anchor` is a hash map; canonicalize the resulting edge order so
        // repeated native runs produce byte-identical binary sidecars.
        edges.sort_by(|left, right| {
            (&left.source, &left.target, &left.kind)
                .cmp(&(&right.source, &right.target, &right.kind))
        });
        let language = semantic_language(&id);
        Ok(lifetime_proto::NativeSemanticFunction {
            id, entry, exits, nodes, edges, language,
        })
    }).collect::<Result<Vec<_>, String>>()?;
    seams.sort_by(|left, right| (&left.source, &left.target, &left.callee)
        .cmp(&(&right.source, &right.target, &right.callee)));
    Ok(lifetime_proto::NativeSemanticResult { functions, complete: true, seams })
}

fn prepare_functions(
    functions: Vec<lifetime_proto::FunctionInput>,
) -> Result<Vec<lifetime_proto::PreparedFunction>, String> {
    // Function preparation is independent.  Keep the worker count bounded and
    // explicit because each in-flight function temporarily owns its AST indexes;
    // unbounded parallelism trades CPU time for paging on large substrates.
    let worker_count = std::env::var("LACHESIS_PREPARE_WORKERS")
        .ok()
        .and_then(|value| value.parse::<usize>().ok())
        .filter(|value| *value > 0);
    match worker_count {
        Some(1) => Ok(functions.into_iter().map(prepare_function).collect()),
        Some(count) => Ok(rayon::ThreadPoolBuilder::new()
            .num_threads(count)
            .build()
            .map_err(|error| format!("cannot create preparation worker pool: {error}"))?
            .install(|| functions.into_par_iter().map(prepare_function).collect())),
        None => Ok(functions.into_par_iter().map(prepare_function).collect()),
    }
}

pub(crate) fn solve_prepared(input: &[u8]) -> Result<Vec<u8>, String> {
    let prepared = lifetime_proto::PrepareResult::decode(input)
        .map_err(|error| format!("invalid prepared lifetime protobuf: {error}"))?;
    solve_prepared_functions(prepared.functions, false)
}

fn solve_prepared_functions(
    prepared: Vec<lifetime_proto::PreparedFunction>, include_prepared: bool,
) -> Result<Vec<u8>, String> {
    // Small functions are independent and cheap enough to solve in parallel.
    // Large CFGs can retain many state copies at branch joins; running all of
    // them concurrently multiplies the peak and turns paging into the timer.
    // Keep the large tail serialized while preserving parallel throughput for
    // the common case.
    const LARGE_FUNCTION_NODES: usize = 2_000;
    let (large, small): (Vec<_>, Vec<_>) = prepared.into_iter()
        .partition(|function| function.nodes.len() > LARGE_FUNCTION_NODES);
    let worker_count = std::env::var("LACHESIS_LIFETIME_WORKERS")
        .ok()
        .and_then(|value| value.parse::<usize>().ok())
        .filter(|value| *value > 0);
    let mut results = match worker_count {
        Some(1) => small.into_iter()
            .map(|function| solve_prepared_function(function, include_prepared))
            .collect::<Result<Vec<_>, _>>()?,
        Some(count) => {
            let solve_small = || small.into_par_iter()
                .map(|function| solve_prepared_function(function, include_prepared))
                .collect::<Result<Vec<_>, _>>();
            rayon::ThreadPoolBuilder::new()
                .num_threads(count)
                .build()
                .map_err(|error| format!("cannot create lifetime worker pool: {error}"))?
                .install(solve_small)?
        }
        None => small.into_par_iter()
            .map(|function| solve_prepared_function(function, include_prepared))
            .collect::<Result<Vec<_>, _>>()?,
    };
    for function in large {
        results.push(solve_prepared_function(function, include_prepared)?);
    }
    results.sort_by(|left, right| left.id.cmp(&right.id));
    let result = lifetime_proto::PrepareSolveResult { functions: results };
    let mut output = Vec::new();
    result.encode(&mut output).map_err(|error| error.to_string())?;
    Ok(output)
}

fn solve_prepared_function(
    function: lifetime_proto::PreparedFunction, include_prepared: bool,
) -> Result<lifetime_proto::PreparedFunctionResult, String> {
    let id = function.id.clone();
    // A CFG with no lifetime operations cannot produce a finding or a
    // state transition. Avoid allocating its node/state worklists; keep
    // the prepared CFG in the result so callers retain complete metadata.
    let has_lifetime_transition = function.operations.iter().any(|operation| {
        !matches!(operation.kind,
            x if x == lifetime_proto::operation::Kind::Use as i32 ||
                 x == lifetime_proto::operation::Kind::Clobber as i32)
    });
    if !has_lifetime_transition {
        let prepared = include_prepared.then(|| slim_prepared(function, false));
        return Ok(lifetime_proto::PreparedFunctionResult {
            id,
            result: Some(lifetime_proto::Result {
                exit_state: Some(lifetime_proto::Snapshot::default()),
                ..Default::default()
            }),
            prepared,
        });
    }
    let operations = function.operations.iter().cloned()
        .map(crate::proto_operation).collect::<Result<Vec<_>, _>>()?;
    let successors = function.successors.iter()
        .map(|entry| (entry.node.clone(), entry.targets.clone()))
        .collect::<HashMap<_, _>>();
    let mut initial = crate::State::default();
    for (position, root) in function.parameters.iter().enumerate() {
        initial.seed_parameter(Path::root(format!("decl:{root}")), position as u32);
    }
    let solved = if let Some(order) = crate::linear_cfg_order(&function.nodes, &successors) {
        crate::solve_linear(&order, &operations, initial)
    } else {
        crate::solve_graph(&function.nodes, &successors, &operations, initial, 32)
    };
    let prepared = include_prepared.then(|| slim_prepared(function, true));
    Ok(lifetime_proto::PreparedFunctionResult {
        id,
        result: Some(crate::proto_result(solved)),
        prepared,
    })
}

/// The Python adapter consumes only the prepared CFG and operation stream.
/// Calls/returns/parameters are preparation inputs, not result metadata, and
/// retaining them in every returned function duplicated a large portion of the
/// request while crossing the binary boundary.
fn slim_prepared(mut function: lifetime_proto::PreparedFunction,
                 keep_operations: bool) -> lifetime_proto::PreparedFunction {
    function.calls.clear();
    function.returns.clear();
    function.parameters.clear();
    if !keep_operations {
        function.operations.clear();
    }
    function
}
