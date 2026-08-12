# Canonical graph contract v2

`lachesis.core` is language-agnostic. It defines graph identities, canonical
node/edge kinds, capability vocabulary, provenance rules, validation and graph
composition. It must not import a language frontend, an ecosystem model or the
compatibility API.

Language-neutral semantic analyses live under `lachesis.core.overlays`. They are
registered and applied sequentially to canonical graphs, returning additive
`GraphDelta` facts with core-owned v2 identities and evidence. An overlay must
not mutate or relabel a compiler fact: alternate dispatch, contextual bindings,
heap locations and other conclusions are represented as separate nodes/edges.

The default direct pipeline currently builds per-function control flow and
branch-sensitive SSA histories, then instantiates call-site contexts,
compiler-emitted parameter/property effects, module singleton/mutable state and
import cycles. Phi nodes retain every incoming definition and branch-correct
reads point to the merged version. Allocation-site heap objects survive aliases,
nested property reads/writes share stable locations, returned allocations are
cloned per call context, and parameter-property effects are applied to the
caller-owned object. After ecosystem models run, a security overlay materializes
compiler/model-tagged sources and sinks and calculates context-stack-aware taint
witnesses. Call entry pushes a call-site context and return flow must pop that
same context, preventing two calls to a shared callee from contaminating each
other. Compiler-seeded dynamic dispatch expands interface/base methods,
function-valued properties, aliases, bound functions, and contextual callbacks
without interpreting language syntax in core. Declarative runtime models add library behavior without parsing source;
the async/event overlay turns those facts and compiler `await` operations into
callback registration, scheduling, continuation, event, queue, stream, and
worker edges. Compiler-identified dynamic constructs retain their exact sites
and inputs; the core also materializes boundaries for them and for calls that
remain unresolved after dispatch expansion. `run_project` and the CLI use this
direct path. The optional `FileInfo` compatibility projection is generated from
the completed graph and never participates in graph construction.

## Ownership

Every v2 ID is ownership-qualified:

```text
v2:<owner>:<namespace>:<kind>:<digest>
```

Valid owners are `frontend`, `core`, `runtime-model` and `framework-model`.
This prevents a compiler fact and an inferred overlay fact from silently sharing
an identity.

## Fact provenance

Every v2 node and edge declares:

- `fact_origin`: `compiler`, `runtime-model`, `framework-model` or `core-inference`.
- `confidence`: `exact`, `high`, `conservative` or `unresolved`.
- `evidence_ids`: required and non-empty for every non-compiler inference.

`fact_origin` is deliberately distinct from domain fields such as a value
definition's `origin=parameter|literal|expression`.

Source-derived nodes additionally carry the complete source interval, content
hash, language, frontend ID and compiler node identity defined in
`provenance.py`.

Language-only data belongs below:

```text
properties.frontend_extensions.<language>
```

The core never interprets this data.

## Contract version

Every registered frontend emits contract v2. Older snapshots are rejected;
there is no parser-era migration path inside the canonical pipeline.

## LLM exposure

The canonical graph remains the source of truth. `lachesis.projections` organizes
it into the T0–T4 layered-v2 artifacts and a complete node locator;
`lachesis.reasoning` returns budgeted, typed slices with evidence and unresolved
boundaries. Neither layer reparses source or feeds presentation facts back into
semantic construction.
