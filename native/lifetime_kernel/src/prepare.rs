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
    parent: HashMap<String, String>,
    refers: HashMap<String, String>,
    initializers: HashMap<String, String>,
}

impl GraphView {
    fn new(input: &lifetime_proto::FunctionInput) -> Self {
        let nodes = input.nodes.iter().cloned().map(|node| (node.id.clone(), node)).collect();
        let mut children = HashMap::new();
        let mut parent = HashMap::new();
        let mut refers = HashMap::new();
        let mut initializers = HashMap::new();
        for edge in &input.edges {
            match edge.kind.as_str() {
                "AST_CHILD" => {
                    children.entry(edge.source.clone()).or_insert_with(Vec::new).push(edge.target.clone());
                    parent.entry(edge.target.clone()).or_insert_with(|| edge.source.clone());
                }
                "REFERS_TO" => { refers.insert(edge.source.clone(), edge.target.clone()); }
                "VALUE_FLOWS_TO" => { initializers.insert(edge.target.clone(), edge.source.clone()); }
                _ => {}
            }
        }
        Self { nodes, children, parent, refers, initializers }
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
        let id = self.peel(id.to_owned());
        let children = self.children.get(&id)?;
        match self.kind(&id).as_str() {
            "UnaryOperator" if self.operator(&id) == "*" => self.access_path(children.first()?, 0),
            "MemberExpr" if self.label(&id).contains("->") => self.access_path(children.first()?, 0),
            "ArraySubscriptExpr" => children.iter().find_map(|child| self.access_path(child, 0)),
            _ => None,
        }
    }
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
    // Some frontend fragments have no statement CFG edge. Preserve a useful
    // deterministic local stream until the full AST CFG synthesizer is selected.
    if successor_map.is_empty() {
        for pair in node_ids.windows(2) {
            successor_map.entry(pair[0].clone()).or_default().push(pair[1].clone());
        }
    }
    let cfg_node_set = successor_map.keys().cloned()
        .chain(successor_map.values().flatten().cloned()).collect::<HashSet<_>>();
    let mut successors = successor_map.into_iter().map(|(node, mut targets)| {
        targets.sort();
        targets.dedup();
        lifetime_proto::Successors { node, targets }
    }).collect::<Vec<_>>();
    successors.sort_by(|left, right| left.node.cmp(&right.node));

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

        if let Some(base) = graph.deref_base(node_id) {
            operations.push(raw_operation(Kind::Use, node_id, Some(base), None,
                graph.node(node_id).and_then(|node| property(node, "start_line")).and_then(|value| value.parse().ok()),
                false, "deref"));
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
            if let Some(target) = target {
                operations.push(operation(Kind::Realloc, &call.node, Some(target), source, call));
            }
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
        if cfg_node_set.contains(&anchor) { item.node = anchor; }
    }
    operations.retain(|item| node_set.contains(&item.node));
    let prepared_nodes = if cfg_node_set.is_empty() {
        let mut values = operations.iter().map(|item| item.node.clone()).collect::<Vec<_>>();
        values.sort();
        values.dedup();
        values
    } else {
        let mut values = node_ids.iter().filter(|node| cfg_node_set.contains(*node)).cloned().collect::<Vec<_>>();
        values.sort_by_key(|node| graph.offset(node));
        values
    };
    let prepared_set = prepared_nodes.iter().cloned().collect::<HashSet<_>>();
    operations.retain(|item| prepared_set.contains(&item.node));
    operations.sort_by_key(|item| (item.line.unwrap_or(i64::MAX), item.node.clone(), item.kind as u8));

    lifetime_proto::PreparedFunction {
        id: input.id,
        nodes: prepared_nodes,
        successors,
        operations: operations.into_iter().map(crate::proto_operation_message).collect(),
        parameters: input.parameters,
    }
}

pub(crate) fn solve(input: &[u8]) -> Result<Vec<u8>, String> {
    let request = lifetime_proto::PrepareRequest::decode(input)
        .map_err(|error| format!("invalid lifetime preparation protobuf: {error}"))?;
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
    let prepared = request.functions.into_iter().map(prepare_function).collect::<Vec<_>>();
    let mut results = Vec::with_capacity(prepared.len());
    for function in prepared {
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
        });
    }
    let result = lifetime_proto::PrepareSolveResult { functions: results };
    let mut output = Vec::new();
    result.encode(&mut output).map_err(|error| error.to_string())?;
    Ok(output)
}
