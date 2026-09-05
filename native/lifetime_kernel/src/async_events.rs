//! Native async, callback, and event-flow overlay.

use hashbrown::{HashMap, HashSet};

use crate::graph_proto;
use crate::pass2::{self, Delta, Graph};

fn list_field(key: &str, values: &[String]) -> graph_proto::Field {
    graph_proto::Field { key: key.to_owned(), value: Some(graph_proto::Value {
        kind: Some(graph_proto::value::Kind::List(graph_proto::ListValue {
            values: values.iter().map(|value| graph_proto::Value {
                kind: Some(graph_proto::value::Kind::Text(value.clone())),
            }).collect(),
        })),
    }) }
}

fn fact(evidence: &[String]) -> Vec<graph_proto::Field> {
    vec![pass2::text_field("fact_origin", "core-inference"),
         pass2::text_field("confidence", "high"), list_field("evidence_ids", evidence)]
}

fn edge(kind: &str, source: &str, target: &str, mut properties: Vec<graph_proto::Field>)
    -> graph_proto::EdgeRecord
{
    graph_proto::EdgeRecord { kind: kind.to_owned(), source: source.to_owned(),
        target: target.to_owned(), properties: { properties.shrink_to_fit(); properties },
        source_tier: String::new(), relationship_class: String::new() }
}

fn event_id(category: &str, receiver: Option<&str>, name: &str) -> String {
    pass2::stable_id("core", "async-events", "async-event", &[category,
        receiver.unwrap_or("global"), name])
}

pub(crate) fn enrich(graph: &Graph) -> Delta {
    let mut arguments_by_call: HashMap<u32, Vec<usize>> = HashMap::new();
    let mut ast_parent: HashMap<u32, u32> = HashMap::new();
    let mut cfg_successors: HashMap<u32, Vec<u32>> = HashMap::new();
    let mut effects = Vec::new();
    let mut await_operations = Vec::new();
    let mut has_runtime_effect = false;

    for (index, node) in graph.nodes.iter().enumerate() {
        match graph.kind(node.kind) {
            "argument" => if let Some(call) = graph.node_property_text(node, "callsite_id").and_then(|id| graph.symbol(id)) {
                arguments_by_call.entry(call).or_default().push(index);
            },
            "function-effect" => {
                if graph.node_property_text(node, "effect_kind") == Some("runtime-call") {
                    has_runtime_effect = true;
                    effects.push(index);
                }
            },
            "expression" | "operation" => if graph.node_property_text(node, "operator") == Some("await") {
                await_operations.push(index);
            },
            _ => {}
        }
    }
    for item in &graph.edges {
        match graph.edge_kind(item) {
            "AST_CHILD" => { ast_parent.insert(item.target, item.source); }
            "CFG_NEXT" | "TRUE_BRANCH" | "FALSE_BRANCH" | "SWITCH_CASE" => {
                cfg_successors.entry(item.source).or_default().push(item.target);
            }
            _ => {}
        }
    }
    if !has_runtime_effect && await_operations.is_empty() { return Delta { nodes: vec![], edges: vec![] }; }

    let mut nodes = Vec::new();
    let mut edges = Vec::new();
    let mut emitted_nodes = HashSet::new();
    let mut emitted_edges = HashSet::new();
    let mut add_edge = |kind: &str, source: String, target: String, evidence: Vec<String>, extra: Vec<graph_proto::Field>| {
        if source.is_empty() || target.is_empty() || source == target { return; }
        if emitted_edges.insert((kind.to_owned(), source.clone(), target.clone())) {
            let mut fields = fact(&evidence);
            fields.extend(extra);
            edges.push(edge(kind, &source, &target, fields));
        }
    };
    let mut add_event = |category: &str, receiver: Option<String>, name: String, evidence: &[String]| -> String {
        let id = event_id(category, receiver.as_deref(), &name);
        if emitted_nodes.insert(id.clone()) {
            let mut fields = fact(evidence);
            fields.extend([pass2::text_field("event_kind", category),
                pass2::text_field("event_name", &name)]);
            if let Some(receiver) = receiver.as_deref() {
                fields.push(pass2::text_field("receiver_value_id", receiver));
            }
            nodes.push(graph_proto::NodeRecord { id: id.clone(), kind: "async-event".to_owned(),
                label: format!("{category}:{name}"), properties: fields, tier: String::new() });
        }
        id
    };

    for effect_index in effects {
        let effect = &graph.nodes[effect_index];
        let Some(call_id) = graph.node_property_text(effect, "callsite_id").and_then(|id| graph.symbol(id)) else { continue };
        let Some(call_index) = graph.node_by_id.get(&call_id).copied() else { continue };
        let mut arguments = arguments_by_call.get(&call_id).cloned().unwrap_or_default();
        arguments.sort_by_key(|index| graph.node_property_i64(&graph.nodes[*index], "position").unwrap_or(-1));
        let behaviors = graph.node_property_text_list(effect, "behaviors");
        let callback_position = graph.node_property_i64(effect, "callback_argument").map(|value| if value < 0 { value + arguments.len() as i64 } else { value });
        let callback = callback_position.and_then(|position| usize::try_from(position).ok()).and_then(|position| arguments.get(position)).copied();
        let mut targets = Vec::new();
        if let Some(callback_index) = callback {
            let callback_id = graph.nodes[callback_index].id;
            if let Some(node_index) = graph.node_by_id.get(&callback_id) {
                for edge_index in &graph.outgoing[*node_index] {
                    let item = &graph.edges[*edge_index];
                    if graph.edge_kind(item) == "PASSES_CALLBACK" { targets.push(item.target); }
                }
            }
            if targets.is_empty() { targets.push(callback_id); }
        }
        let effect_id = graph.id(effect.id).to_owned();
        let call_text = graph.id(call_id).to_owned();
        let evidence: Vec<String> = std::iter::once(effect_id.clone()).chain(std::iter::once(call_text.clone()))
            .chain(targets.iter().map(|id| graph.id(*id).to_owned())).collect();
        for target in &targets {
            let target_text = graph.id(*target).to_owned();
            add_edge("REGISTERS_CALLBACK", call_text.clone(), target_text.clone(), evidence.clone(),
                vec![pass2::text_field("effect_id", &effect_id)]);
            if behaviors.iter().any(|value| value == "timer" || value == "microtask") {
                let queue = if behaviors.iter().any(|value| value == "microtask") { "microtask" } else { "timer" };
                add_edge("SCHEDULES", call_text.clone(), target_text.clone(), evidence.clone(), vec![pass2::text_field("queue", queue)]);
            }
            let completion = if behaviors.iter().any(|value| value == "promise-continuation") { Some("fulfilled") }
                else if behaviors.iter().any(|value| value == "promise-rejection") { Some("rejected") }
                else if behaviors.iter().any(|value| value == "promise-finalizer") { Some("finally") } else { None };
            if let Some(completion) = completion {
                let source = graph.node_property_text(&graph.nodes[call_index], "value_id").unwrap_or(&call_text).to_owned();
                add_edge("ASYNC_CONTINUES_AT", source, target_text, evidence.clone(), vec![pass2::text_field("completion", completion)]);
            }
        }
        let receiver = graph.node_property_text(effect, "receiver_value_id").map(str::to_owned);
        let name = graph.node_property_text(effect, "event_name").unwrap_or("*").to_owned();
        if behaviors.iter().any(|value| value == "event-registration" || value == "queue-consumer") && !targets.is_empty() {
            let category = if behaviors.iter().any(|value| value == "queue-consumer") { "message-queue" } else { "event" };
            let event = add_event(category, receiver.clone(), name.clone(), &evidence);
            for target in &targets { add_edge("HANDLED_BY", event.clone(), graph.id(*target).to_owned(), evidence.clone(), vec![pass2::text_field("registration_call_id", &call_text)]); }
        }
        if behaviors.iter().any(|value| value == "emits-event") {
            let category = if behaviors.iter().any(|value| value == "worker-message") { "worker-message" } else if behaviors.iter().any(|value| value == "message-publish") { "message-queue" } else { "event" };
            let event = add_event(category, receiver.clone(), name.clone(), &evidence);
            add_edge("EMITS_EVENT", call_text.clone(), event, evidence.clone(), vec![pass2::text_field("effect_id", &effect_id)]);
        }
        if behaviors.iter().any(|value| value == "message-send" || value == "message-publish") {
            let event = add_event("message-queue", receiver.clone(), name.clone(), &evidence);
            add_edge("SCHEDULES", call_text.clone(), event, evidence.clone(), vec![pass2::text_field("queue", "message")]);
        }
        if behaviors.iter().any(|value| value == "worker-spawn") {
            let event = add_event("worker", Some(call_text.clone()), call_text.clone(), &evidence);
            add_edge("SCHEDULES", call_text.clone(), event, evidence, vec![pass2::text_field("queue", "worker-thread")]);
        }
    }

    for operation_index in await_operations {
        let operation = &graph.nodes[operation_index];
        let mut statement = operation.id;
        while let Some(parent) = ast_parent.get(&statement).copied() {
            if graph.node_index(graph.id(parent)).is_some_and(|index| graph.kind(graph.nodes[index].kind) == "statement") { statement = parent; break; }
            statement = parent;
        }
        let Some(statement_index) = graph.node_by_id.get(&statement).copied() else { continue };
        if graph.kind(graph.nodes[statement_index].kind) != "statement" { continue; }
        let operation_text = graph.id(operation.id).to_owned();
        let statement_text = graph.id(statement).to_owned();
        for successor in cfg_successors.get(&statement).into_iter().flatten() {
            let successor_text = graph.id(*successor).to_owned();
            add_edge("ASYNC_CONTINUES_AT", operation_text.clone(), successor_text.clone(),
                vec![operation_text.clone(), statement_text.clone(), successor_text],
                vec![pass2::text_field("suspension", "await"), pass2::text_field("statement_id", &statement_text)]);
        }
    }
    Delta { nodes, edges }
}
