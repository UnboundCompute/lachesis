//! Native lifetime-input preparation.
//!
//! This module is deliberately independent from the Python graph adapter.  It
//! accepts function-scoped graph records, builds the local control-flow relation,
//! and emits the same binary operation request consumed by the Rust solver.  The
//! first version covers the language-neutral call/lifecycle facts; expression
//! access-path extraction is added on top of this boundary without changing the
//! ABI.

use std::collections::{HashMap, HashSet};

use prost::Message;

use crate::{lifetime_proto, Kind, Operation, Path};

fn property(node: &lifetime_proto::GraphNode, key: &str) -> Option<String> {
    node.properties.iter().find_map(|item| {
        if item.key != key { return None; }
        item.value.as_ref().map(|value| match value {
            lifetime_proto::scalar_property::Value::Text(value) => value.clone(),
            lifetime_proto::scalar_property::Value::Integer(value) => value.to_string(),
            lifetime_proto::scalar_property::Value::Boolean(value) => value.to_string(),
        })
    })
}

fn path(node: Option<&str>) -> Option<Path> {
    node.filter(|value| !value.is_empty())
        .map(|value| Path::root(format!("decl:{value}")))
}

struct GraphView {
    nodes: HashMap<String, lifetime_proto::GraphNode>,
    children: HashMap<String, Vec<String>>,
    roles: HashMap<(String, String), Vec<String>>,
    parent: HashMap<String, String>,
    refers: HashMap<String, String>,
    initializers: HashMap<String, String>,
}

impl GraphView {
    fn new(input: &lifetime_proto::FunctionInput) -> Self {
        let nodes = input.nodes.iter().cloned().map(|node| (node.id.clone(), node)).collect();
        let mut children = HashMap::new();
        let mut parent = HashMap::new();
        let mut roles = HashMap::new();
        let mut refers = HashMap::new();
        let mut initializers = HashMap::new();
        for edge in &input.edges {
            match edge.kind.as_str() {
                "AST_CHILD" => {
                    children.entry(edge.source.clone()).or_insert_with(Vec::new).push(edge.target.clone());
                    parent.entry(edge.target.clone()).or_insert_with(|| edge.source.clone());
                    roles.entry((edge.source.clone(), edge.role.clone())).or_insert_with(Vec::new).push(edge.target.clone());
                }
                "REFERS_TO" => { refers.insert(edge.source.clone(), edge.target.clone()); }
                "VALUE_FLOWS_TO" => { initializers.insert(edge.target.clone(), edge.source.clone()); }
                _ => {}
            }
        }
        Self { nodes, children, roles, parent, refers, initializers }
    }

    fn node(&self, id: &str) -> Option<&lifetime_proto::GraphNode> { self.nodes.get(id) }

    fn kind(&self, id: &str) -> String {
        self.node(id).map(|node| property(node, "syntax_kind").unwrap_or_else(|| node.kind.clone())).unwrap_or_default()
    }

    fn label(&self, id: &str) -> &str { self.node(id).map(|node| node.label.as_str()).unwrap_or("") }

    fn offset(&self, id: &str) -> i64 {
        self.node(id).and_then(|node| property(node, "start_offset")).and_then(|value| value.parse().ok()).unwrap_or(i64::MAX)
    }

    fn operator(&self, id: &str) -> String {
        self.node(id).and_then(|node| property(node, "operator")).unwrap_or_default()
    }

    fn is_pointer(&self, id: &str) -> bool {
        self.node(id).and_then(|node| property(node, "type"))
            .is_some_and(|value| value.contains('*') || value.contains('['))
    }

    fn peel(&self, mut id: String) -> String {
        for _ in 0..12 {
            if matches!(self.kind(&id).as_str(), "ImplicitCastExpr" | "CStyleCastExpr" | "ParenExpr" |
                "CXXConstCastExpr" | "CXXStaticCastExpr" | "CXXReinterpretCastExpr" | "CXXFunctionalCastExpr") {
                if let Some(child) = self.children.get(&id).and_then(|items| items.first()) {
                    id = child.clone();
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
        match self.kind(&id).as_str() {
            "DeclRefExpr" => self.access_path(self.refers.get(&id).map(String::as_str).unwrap_or(&id), depth + 1),
            "ParmVarDecl" | "VarDecl" => path(Some(&id)),
            "MemberExpr" => {
                let child = self.children.get(&id)?.first()?;
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
                let children = self.children.get(&id)?;
                let base_id = children.iter().find(|child| {
                    self.node(child).and_then(|node| property(node, "type"))
                        .is_some_and(|value| value.contains('*') || value.contains('['))
                }).or_else(|| children.first())?;
                let mut base = self.access_path(base_id, depth + 1)?;
                base.selectors.push("<?>".to_owned());
                base.selectors.push("*".to_owned());
                Some(base)
            }
            "UnaryOperator" => {
                let child = self.children.get(&id)?.first()?;
                let mut base = self.access_path(child, depth + 1)?;
                match self.operator(&id).as_str() {
                    "*" => base.selectors.push("*".to_owned()),
                    "&" => base.selectors.push("&".to_owned()),
                    _ => {}
                }
                Some(base)
            }
            _ => None,
        }
    }

    fn deref_base(&self, id: &str) -> Option<Path> {
        let children = self.children.get(id)?;
        match self.kind(id).as_str() {
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
            let Some(parent) = self.parent.get(current) else { return false };
            current = parent;
        }
        false
    }
}

fn is_statement(kind: &str) -> bool {
    kind.ends_with("Stmt") || matches!(kind, "cfg-entry" | "cfg-exit" | "cfg-merge" | "cfg-condition")
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
    let mut children = graph.children.get(id).cloned().unwrap_or_default()
        .into_iter().filter(|child| owned.contains(child)).collect::<Vec<_>>();
    children.sort_by_key(|child| graph.offset(child));
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

fn synthesize_cfg(graph: &GraphView, owned: &HashSet<String>) -> Option<(Vec<String>, HashMap<String, Vec<String>>)> {
    let mut roots = owned.iter().filter(|node| graph.kind(node) == "CompoundStmt" &&
        graph.parent.get(*node).map(|parent| !owned.contains(parent)).unwrap_or(true)).cloned().collect::<Vec<_>>();
    if roots.is_empty() { roots = owned.iter().filter(|node| graph.kind(node) == "CompoundStmt").cloned().collect(); }
    let root = roots.into_iter().min_by_key(|node| graph.offset(node))?;
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
        let children = graph.children.get(id).cloned().unwrap_or_default()
            .into_iter().filter(|child| owned.contains(child)).collect::<Vec<_>>();
        let result = if kind == "CompoundStmt" {
            let mut items = children;
            items.sort_by_key(|child| graph.offset(child));
            let mut first = None;
            let mut exits: Vec<String> = Vec::new();
            for child in items {
                let (entry, next_exits) = {
                if is_statement(graph.kind(&child).as_str()) {
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
        } else if kind == "IfStmt" {
            let condition = graph.roles.get(&(id.to_owned(), "CONDITION".to_owned())).and_then(|items| items.first()).cloned()
                .or_else(|| children.iter().min_by_key(|child| graph.offset(child)).cloned());
            let mut condition_stream = Vec::new();
            if let Some(condition) = condition {
                expression_stream(graph, &condition, owned, &mut condition_stream, &mut HashSet::new(), 0);
                append_chain(successors, &condition_stream);
            }
            let mut branches = Vec::new();
            for role in ["TRUE_BRANCH", "FALSE_BRANCH"] {
                if let Some(branch) = graph.roles.get(&(id.to_owned(), role.to_owned())).and_then(|items| items.first()) {
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
        } else if kind == "ForStmt" {
            let body = graph.roles.get(&(id.to_owned(), "LOOP_BODY".to_owned())).and_then(|items| items.first()).cloned();
            let condition = graph.roles.get(&(id.to_owned(), "CONDITION".to_owned())).and_then(|items| items.first()).cloned();
            let mut others = children;
            others.retain(|child| Some(child) != body.as_ref() && Some(child) != condition.as_ref());
            others.sort_by_key(|child| graph.offset(child));
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
        } else if matches!(kind.as_str(), "WhileStmt" | "DoStmt") {
            let condition = graph.roles.get(&(id.to_owned(), "CONDITION".to_owned())).and_then(|items| items.first()).cloned();
            let body = graph.roles.get(&(id.to_owned(), "LOOP_BODY".to_owned())).and_then(|items| items.first()).cloned();
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
        } else if is_statement(kind.as_str()) {
            let mut stream = Vec::new();
            let mut sorted = children;
            sorted.sort_by_key(|child| graph.offset(child));
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
    let cfg_entry = owned.iter().find(|node| graph.kind(node) == "cfg-entry").cloned();
    let cfg_exit = owned.iter().find(|node| graph.kind(node) == "cfg-exit").cloned();
    let mut params = owned.iter().filter(|node| graph.kind(node) == "ParmVarDecl").cloned().collect::<Vec<_>>();
    params.sort_by_key(|node| graph.offset(node));
    if let Some(exit) = cfg_exit.clone() {
        successors.entry(exit.clone()).or_default();
        for item in exits { successors.entry(item).or_default().push(cfg_exit.clone().unwrap()); }
        // Structured loop emission has a back-edge for the true/body arm, but
        // the false/termination arm is not represented by a source AST node.
        // Recover it here so every finite loop has a native CFG exit. Return
        // statements and other terminal fragments are handled by the same
        // empty-successor closure below.
        let controls = owned.iter().filter(|node| matches!(graph.kind(node).as_str(),
            "IfStmt" | "ForStmt" | "WhileStmt" | "DoStmt")).cloned().collect::<Vec<_>>();
        for control in controls {
            let condition = graph.roles.get(&(control.clone(), "CONDITION".to_owned()))
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
        alternatives: Vec::new(),
    }
}

fn prepare_function(input: lifetime_proto::FunctionInput) -> lifetime_proto::PreparedFunction {
    let graph = GraphView::new(&input);
    let mut nodes = input.nodes;
    nodes.sort_by_key(|node| property(node, "start_offset").and_then(|value| value.parse::<i64>().ok()).unwrap_or(i64::MAX));
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
        let mut terminals = node_ids.iter().filter(|node| graph.kind(node) == "ReturnStmt")
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
    let call_by_node = input.calls.iter().map(|call| (call.node.clone(), call)).collect::<HashMap<_, _>>();

    // Assignment/declaration and dereference operations are prepared from the
    // raw AST here, before the request reaches the abstract-state solver.
    for node_id in &node_ids {
        let kind = graph.kind(node_id);
        let children = graph.children.get(node_id).cloned().unwrap_or_default();
        if kind == "BinaryOperator" && graph.operator(node_id) == "=" && children.len() >= 2 {
            let mut ordered = children;
            ordered.sort_by_key(|child| graph.offset(child));
            let rhs = ordered.get(1).or_else(|| ordered.first());
            let lhs = ordered.first();
            if let (Some(lhs), Some(rhs)) = (lhs, rhs) {
                let line = graph.node(node_id).and_then(|node| property(node, "start_line")).and_then(|value| value.parse().ok());
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
                        } else if matches!(graph.kind(&rhs_id).as_str(), "GNUNullExpr" | "CXXNullPtrLiteralExpr") {
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
            let line = graph.node(node_id).and_then(|node| property(node, "start_line")).and_then(|value| value.parse().ok());
            let target = path(Some(node_id));
            if let Some(initializer) = graph.initializers.get(node_id) {
                let initializer = graph.peel(initializer.clone());
                let (kind, source, is_null) = if let Some(call) = call_by_node.get(&initializer) {
                    if call.is_alloc { (Kind::Alloc, None, false) }
                    else if call.is_realloc { (Kind::Realloc, None, false) }
                    else if call.is_source { (Kind::Clobber, None, false) }
                    else { (Kind::Copy, graph.access_path(&initializer, 0), false) }
                } else if matches!(graph.kind(&initializer).as_str(), "GNUNullExpr" | "CXXNullPtrLiteralExpr") {
                    (Kind::Clobber, None, true)
                } else if let Some(source) = graph.access_path(&initializer, 0) {
                    (Kind::Copy, Some(source), false)
                } else { (Kind::Clobber, None, false) };
                operations.push(raw_operation(kind, node_id, target, source, line, is_null, "deref"));
            } else {
                operations.push(raw_operation(Kind::Clobber, node_id, target, None, line, false, "uninitialized"));
            }
        }

        let assignment_lhs = graph.parent.get(node_id).is_some_and(|parent| {
            graph.kind(parent) == "BinaryOperator" && graph.operator(parent) == "=" &&
            graph.children.get(parent).into_iter().flatten()
                .min_by_key(|child| graph.offset(child))
                .is_some_and(|child| graph.peel(child.clone()) == graph.peel(node_id.clone()))
        });
        if !assignment_lhs {
            if let Some(base) = graph.deref_base(node_id) {
                operations.push(raw_operation(Kind::Use, node_id, Some(base), None,
                    graph.node(node_id).and_then(|node| property(node, "start_line")).and_then(|value| value.parse().ok()),
                    false, "deref"));
            }
        }
    }
    let summary_by_callee = input.summaries.iter().map(|summary| (summary.callee.as_str(), summary)).collect::<HashMap<_, _>>();
    let mut calls = input.calls;
    calls.sort_by_key(|call| (if call.has_line { call.line } else { i64::MAX }, call.node.clone()));
    for call in &calls {
        let argument = |position: u32| call.arguments.iter().find(|item| item.position == position)
            .and_then(|item| graph.access_path(&item.node, 0).or_else(|| path(Some(&item.node))));
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
                operations.push(operation(Kind::Copy, &call.node, Some(destination), Some(source), call));
            }
        } else if let Some(summary) = summary_by_callee.get(call.callee.as_str()) {
            for alternative in &summary.alternatives {
                let mut effects = Vec::new();
                for effect in &alternative.effects {
                    let actual = call.arguments.iter().find(|argument| argument.position == effect.position)
                        .and_then(|argument| graph.access_path(&argument.node, 0).or_else(|| path(Some(&argument.node))));
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
                if let Some(target) = path(Some(&argument.node)) {
                    operations.push(operation(Kind::Use, &call.node, Some(target), None, call));
                }
            }
        }
    }
    // Map expression anchors to the nearest CFG node. The solver consumes the
    // synthesized statement CFG, while operation extraction remains expression
    // precise above.
    for item in &mut operations {
        let mut anchor = item.node.clone();
        let mut seen = HashSet::new();
        while !cfg_node_set.contains(&anchor) && seen.insert(anchor.clone()) {
            let Some(parent) = graph.parent.get(&anchor) else { break };
            anchor = parent.clone();
        }
        if !cfg_node_set.contains(&anchor) {
            if let Some(initializer) = graph.initializers.get(&item.node) {
                let initializer = graph.peel(initializer.clone());
                if cfg_node_set.contains(&initializer) { anchor = initializer; }
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
            operation_nodes.contains(node.as_str()) || matches!(graph.kind(node).as_str(),
                "DeclRefExpr" | "CallExpr" | "CXXMemberCallExpr" | "CXXOperatorCallExpr" |
                "BinaryOperator" | "CompoundAssignOperator" | "UnaryOperator" |
                "ConditionalOperator" | "MemberExpr" | "ArraySubscriptExpr" |
                "IntegerLiteral" | "FloatingLiteral" | "StringLiteral" |
                "CharacterLiteral" | "CXXBoolLiteralExpr" | "ImplicitValueInitExpr" |
                "GNUNullExpr" | "CXXNullPtrLiteralExpr" | "VarDecl" | "ParmVarDecl")
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
    for node in &cfg_node_set {
        if !prepared_nodes.contains(node) {
            prepared_nodes.push(node.clone());
        }
    }
    prepared_nodes.sort_by_key(|node| graph.offset(node));
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
            let mut if_nodes = graph.nodes.keys().filter(|node| graph.kind(node) == "IfStmt").cloned().collect::<Vec<_>>();
        if_nodes.sort_by_key(|node| graph.offset(node));
        for if_node in if_nodes {
            let true_roots = graph.roles.get(&(if_node.clone(), "TRUE_BRANCH".to_owned())).cloned().unwrap_or_default();
            let false_roots = graph.roles.get(&(if_node.clone(), "FALSE_BRANCH".to_owned())).cloned().unwrap_or_default();
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
    let mut successors = successor_map.into_iter().map(|(node, mut targets)| {
        targets.sort();
        targets.dedup();
        lifetime_proto::Successors { node, targets }
    }).collect::<Vec<_>>();
    successors.sort_by(|left, right| left.node.cmp(&right.node));
    operations.sort_by_key(|item| (item.line.unwrap_or(i64::MAX), item.node.clone(), item.kind as u8));

    lifetime_proto::PreparedFunction {
        id: input.id,
        nodes: prepared_nodes,
        successors,
        operations: operations.into_iter().map(crate::proto_operation_message).collect(),
        parameters: input.parameters,
        calls,
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
    let prepared = request.functions.into_iter().map(prepare_function).collect::<Vec<_>>();
    let mut results = Vec::with_capacity(prepared.len());
    for function in prepared {
        let prepared_for_output = function.clone();
        let operations = function.operations.into_iter().map(crate::proto_operation).collect::<Result<Vec<_>, _>>()?;
        let successors = function.successors.into_iter().map(|entry| (entry.node, entry.targets)).collect::<HashMap<_, _>>();
        let mut initial = crate::State::default();
        for (position, root) in function.parameters.iter().enumerate() {
            initial.seed_parameter(Path::root(format!("decl:{root}")), position as u32);
        }
        let solved = crate::solve_graph(&function.nodes, &successors, &operations, initial, 32);
        results.push(lifetime_proto::PreparedFunctionResult {
            id: function.id,
            result: Some(crate::proto_result(solved)),
            prepared: Some(prepared_for_output),
        });
    }
    let result = lifetime_proto::PrepareSolveResult { functions: results };
    let mut output = Vec::new();
    result.encode(&mut output).map_err(|error| error.to_string())?;
    Ok(output)
}
