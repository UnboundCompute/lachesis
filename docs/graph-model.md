# The graph model

This is the reference for what Lachesis actually puts in the graph: the node
kinds, the edge kinds, and the tiers they live in. Everything here is the
canonical contract defined in
[`lachesis/core/schema.py`](../lachesis/core/schema.py), so if this page and the
code ever disagree, the code is right and this page is stale. The contract is
versioned (`CURRENT_CONTRACT_VERSION = 2`).

The one idea to hold onto: a symbol index can tell you where a name appears, and
the first three tiers here do that too. The reason Lachesis exists is the later
tiers, where the edges describe how a value moves rather than where a name is
written. Those are the edges a downstream tool reasons about when it asks what
reaches a sink or which sibling guards an input.

## Tiers

Every node belongs to one or more tiers, T0 through T4. The tiers are a
progressive, drillable view of the same canonical graph: you can load T0 to T1 to
understand shape, then descend into the dataflow tiers only where a question
needs them.

| Tier | What it holds |
|---|---|
| T0 | Project structure: the package, module, and file skeleton, imports and exports, routes and events. |
| T1 | Declarations: functions, methods, classes, interfaces, types, the things a symbol index would list. |
| T2 | Values and def-use: parameters, variables, definitions, reads and writes, property paths, heap objects, and the value-flow overlay. |
| T3 | Executable structure and control flow: statements, expressions, calls, arguments, returns, and the control-flow graph. |
| T4 | Security evidence: sources, sinks, guards, boundaries, and recovered taint-reach paths. |

A few kinds span tiers on purpose. `module` is both T0 and T1. Arguments and
produced or returned values are pulled up into the T2 path tier even though their
syntax nodes also participate in T3 executable structure.

## Node kinds

Node kinds are serialized in lowercase kebab-case. They fall into six families.

### Project structure (T0)

The skeleton of the codebase before any single function is opened.

`project`, `package`, `module`, `file`, `import`, `export`, `external-module`,
`route`, `event`, `registration`, `import-cycle`.

### Declarations (T1)

The named, declared entities. This is the tier that lines up with what other
code-graph tools surface.

`scope`, `symbol`, `declaration`, `function`, `method`, `constructor`, `class`,
`interface`, `type`, `enum`, `record`, `parameter`, `variable`, `binding`,
`property`, `constant`, `value`, `decorator`, `type-parameter`, `macro`.

### Executable (T3)

The statements and expressions inside a body, including the call sites that the
call graph is built from.

`statement`, `expression`, `operation`, `identifier`, `call`, `construct`,
`call-value`, `argument`, `return`, `return-value`, `throw`.

`call-value` is worth naming: it is the value a call produces, so
`findById(documentId)` as a value is a `call-value`, distinct from the `call`
site itself.

### Values (T2)

The def-use and pointer material: where values are defined, read, written, and
what they point at on the heap.

`definition`, `read`, `write`, `literal`, `property-path`, `allocation`,
`heap-object`, `heap-location`, `type-refinement`, `generic-substitution`,
`call-context`, `context-parameter`, `context-return`.

The `call-context`, `context-parameter`, and `context-return` kinds carry
call-context sensitivity, so a value's history can be read per calling context
rather than smeared across all callers.

### Control and runtime (T3)

The control-flow graph and runtime-shaped facts.

`cfg-entry`, `cfg-block`, `cfg-condition`, `cfg-merge`, `cfg-exit`, `phi`,
`async-event`, `dynamic-behavior`, `function-effect`, `module-initializer`,
`static-initializer`, `singleton`, `module-state`, `unreachable-region`.

`phi` is the SSA merge point where a value's version depends on which branch ran.

### Security evidence (T4)

The security model laid over everything below it.

`source`, `sink`, `boundary`, `guard`, `taint-reach`, `diagnostic`,
`source-span`, `token`.

A `taint-reach` node is a recovered source-to-sink fact, the thing the
`security-path` query drills into. In the worked example it reads as
`public parameter:documentId → database:findById(documentId)`.

## Edge kinds

Edge kinds are serialized in UPPER_SNAKE_CASE and fall into five families. The
value and call families are where the differentiator lives.

### Value and dataflow edges

These are the edges that make Lachesis more than a symbol index.

| Edge | Meaning |
|---|---|
| `VALUE_FLOWS_TO` | Def-use value flow: this value flows into that one. |
| `POINTS_TO` | Points-to: this value points at that heap object. |
| `ALIASES`, `ALIASES_VALUE` | Aliasing: two values that refer to the same thing. |
| `DEFINES` | This node defines that value. |
| `READS_FROM`, `WRITES_TO`, `WRITES_PARAMETER_PROPERTY` | Reads and writes against a value or property. |
| `WRITES_HEAP`, `READS_HEAP` | Heap-level reads and writes. |
| `PHI_INPUT`, `PHI_FOR_SYMBOL` | Inputs to an SSA phi merge, and the symbol it merges. |
| `BRANCH_READS_FROM`, `BRANCH_PREVIOUS`, `PREVIOUS_VERSION` | Versioned reads across branches. |
| `NARROWS_TYPE`, `REFINES_SYMBOL`, `SUBSTITUTES_TYPE` | Type narrowing and generic substitution flow. |
| `ALLOCATES`, `CONTEXT_ALLOCATES`, `FUNCTION_VALUE`, `PROPERTY_READ`, `READ_EVIDENCED_BY`, `DYNAMIC_INPUT` | The rest of the value family. |

### Call edges

| Edge | Meaning |
|---|---|
| `CALLS` | A resolved call from one declaration to another. |
| `INVOKES` | A resolved invocation edge. |
| `MAY_INVOKE` | A possible call through indirect dispatch (function pointer, ops-struct, runtime), where the indirection is real but the exact target is not pinned. |
| `HAS_ARGUMENT`, `BINDS_PARAMETER`, `ARGUMENT_BINDS_PARAMETER` | How arguments bind to parameters at a call. |
| `RETURNS_VALUE`, `THROWS_VALUE`, `RETURN_EVIDENCED_BY` | What a call returns or throws. |
| `READS_CALLEE`, `PASSES_CALLBACK` | Reading the callee value, and passing a callback. |
| `HAS_CALL_CONTEXT`, `CONTEXT_CALLS`, `CONTEXTUALIZES`, `CONTEXT_RETURNS` | The call-context-sensitive call edges. |

The `CALLS` / `INVOKES` / `MAY_INVOKE` split is the point of the call tier:
resolved edges and possible-through-dispatch edges are different colors, so a
consumer can reason about the union call graph without mistaking a maybe for a
certainty.

### Runtime and security edges

| Edge | Meaning |
|---|---|
| `TAINT_FLOWS_TO` | Taint propagation from a source toward a sink. This is the edge the security-path walk follows. |
| `GUARDED_BY` | A sink or handler is guarded by a given check. |
| `EVIDENCED_BY` | Links a conclusion to the compiler facts that witness it. |
| `TAINT_SOURCE`, `TAINT_SINK`, `TAINT_REACHES` | The source, sink, and reachability of a taint relation. |
| `ROUTE_HANDLED_BY`, `ENTRY_POINT_OF`, `HANDLED_BY` | Wiring from routes and entry points to their handlers. |
| `CAPTURES`, `MUTATES`, `APPLIES_EFFECT`, `REGISTERS_CALLBACK`, `SCHEDULES`, `EMITS_EVENT`, `ASYNC_CONTINUES_AT` | Runtime effects and async continuation. |
| `OVERRIDES`, `IMPLEMENTS_MEMBER`, `DYNAMIC_BEHAVIOR_AT`, `DUPLICATES`, `SHADOWS` | Override, implementation, and duplication relations. |

### Structure and control edges

The T0/T1 structure family (`CONTAINS`, `DECLARES`, `DEPENDS_ON`, `EXPORTS`,
`HAS_TYPE`, `AST_CHILD`, and the rest) wires the skeleton together, and the
control family (`CFG_NEXT`, `CONDITION`, `TRUE_BRANCH`, `FALSE_BRANCH`,
`LOOP_BACK`, `EXCEPTION_BRANCH`, `SWITCH_CASE`, and the rest) is the control-flow
graph. See `STRUCTURE_EDGE_KINDS` and `CONTROL_EDGE_KINDS` in the schema for the
full members.

## The Python frontend

Python is read by CPython's own compiler front half, `ast` plus `symtable`, with
no third-party parser and no type checker. `ast` gives exact spans, `symtable`
gives the binding classification (local, global, free, parameter, imported) that
decides which declaration a name in a body actually refers to. The frontend id is
`cpython-ast` and every node it emits is namespaced
`v2:frontend:cpython-ast:<kind>:<digest>`.

`ast` reports column offsets as UTF-8 byte offsets into the line while the nav
layer slices decoded text by character, so the frontend converts every offset
before it emits one. Without that, one non-ASCII character anywhere above a
function silently shifts the body every offset-driven tool returns.

How Python constructs land in the model:

| construct | what is emitted |
|---|---|
| `def`, `async def`, `lambda` | `function`, or `method`/`constructor` inside a class, with `owner_function_id` on everything under it |
| `class` | `class` plus `DECLARES`, and `OVERRIDES` to the base's method of the same name |
| `import`, `from ... import`, relative imports | `import` and `external-module` nodes, `DEPENDS_ON`, and `EXPORTS` from `__all__` |
| assignment, walrus, augmented assignment | `definition` plus `VALUE_FLOWS_TO` with reason `initializer` or `assignment`, chained by `PREVIOUS_VERSION` |
| parameter binding | one `definition` per parameter with `origin="parameter"`, which is what the heap overlay keys on |
| `self.x = param` | `property-path`, `write`, `WRITES_TO`, and `WRITES_PARAMETER_PROPERTY` |
| f-strings | `VALUE_FLOWS_TO` with reason `template-substitution`, the edge most Python injection paths run through |
| list, dict, set, tuple displays, comprehensions, `Foo()` | `allocation` with `allocation_kind` and `allocated_type`, which is what makes `points_to` and `aliases` non-trivial |
| `if`, `while`, ternaries, comprehension `if`s, `match` guards | `CONDITION` |
| `and`, `or` | `SHORT_CIRCUIT_LEFT` and `SHORT_CIRCUIT_RIGHT` |
| `raise` | `THROWS_VALUE` |
| `try`, `except`, `finally` | `TRY_BODY` and `EXCEPTION_BRANCH` |
| `getattr`, `setattr`, `eval`, `exec` | a `dynamic-behavior` node and no call edge, because inventing one would be a guess |

Call resolution is lexical, and the encoding says so. A module-level `def` bound
exactly once, or an import resolved to an in-tree declaration, gets `INVOKES` and
`CALLS` at `exact`. `self.m()` found once in the lexical MRO is `high`, not
`exact`, and the dispatch overlay fans it out to every subclass override through
`OVERRIDES`. An attribute call on a value of unknown type gets `MAY_INVOKE` to
each in-tree method of that name while the candidates stay few, and above the cap
gets no edge at all and a `method_candidate_count` on the call site instead.

What Python does not resolve, stated plainly: anything through `**kwargs`,
`getattr`, metaclasses, `functools.partial`, `__getattr__`, C extensions,
monkey-patching, or a star-import from outside the tree. The frontend also never
reads outside the root set and never probes the running interpreter's `sys.path`,
so the graph does not change when the analyst's virtualenv does.

Three deliberate omissions in the control tier. `with` gets a plain statement and
no invented control kind, because the branch it really introduces lives in
`__enter__` and `__exit__`. `assert` is not modelled as an `if`, which would put
a phantom branch in every function that uses one. `yield` folds onto a return
value with `return_kind="yield"`, which loses the resumption point, and is part of
why `control_flow` stays `partial`.

## Contract rules worth knowing

A few properties of the contract shape what you can trust in the graph.

- **Every fact carries an origin.** `FACT_ORIGINS` is one of `compiler`,
  `runtime-model`, `framework-model`, or `core-inference`. A compiler fact and an
  inferred conclusion are labeled differently, so you always know whether the
  graph observed something or derived it.
- **Every fact carries a confidence.** `CONFIDENCE_LEVELS` is one of `exact`,
  `high`, `conservative`, or `unresolved`. The UNGUARDED verdict in the worked
  example is `conservative` for a reason: it is the safe reading when no guard was
  observed, not a claim that one is impossible.
- **Frontends may not invent conclusions.** A language frontend emits syntax,
  symbols, calls, and def-use, but it is forbidden from emitting the security and
  heap kinds (`source`, `sink`, `guard`, `taint-reach`, `POINTS_TO`,
  `TAINT_FLOWS_TO`, and so on, listed in `FRONTEND_FORBIDDEN_NODE_KINDS` and
  `FRONTEND_FORBIDDEN_EDGE_KINDS`). Those are the job of the core and model
  layers. This keeps a new frontend from having to understand security to
  participate.
- **Frontends extend under their own namespace.** Language-specific extras attach
  below `properties.frontend_extensions.<language>` and never create private node
  or edge kinds, so the core never has to learn a language to read the graph.

To see these kinds in a real graph, follow the walkthrough in
[`examples/README.md`](../examples/README.md), which builds a graph and then reads
the taint-reach path and guard verdicts out of it.
