# Compiler-backed layered graph frontends

Language-specific compiler processes live here. The language-neutral contract
and semantic overlays live in `lachesis/core`, project orchestration lives in
`lachesis/pipeline.py`, and optional presentation views live in
`lachesis/compatibility` and `lachesis/projections`.

```sh
node lachesis/frontends/typescript/build_graph.mjs path/to/source graph_out/compiler_layered
```

Run every compiler plugin needed by a mixed-language tree, apply the available
language-neutral semantic/security overlays, and compose the results without
converting them back into parser-specific objects:

```sh
python3 lachesis/cli/analyze.py . graph_out/compiler_project.json
```

The default registry currently contains the official TypeScript Compiler API
frontend (`.ts`, `.tsx`, `.mts`, `.cts`, `.js`, `.jsx`) and a Clang frontend for
C (`.c`, `.h`). The Clang frontend accepts normal include flags through
`LACHESIS_CFLAGS`; `CLANG` may select another compatible compiler command.

The generator prefers a normal local `typescript` dependency. You can point it at
another installation without changing the repository:

```sh
TYPESCRIPT_PATH=/absolute/path/to/typescript \
  node lachesis/frontends/typescript/build_graph.mjs path/to/source graph_out/compiler_layered
```

It emits `manifest.json` and one JSON file per tier:

- `T0 perimeter`: source files and compiler-resolved module dependencies.
- `T1 reachability`: functions, methods, classes, interfaces, types and resolved calls.
- `T2 path`: parameters, variables, call values, arguments, direct value-flow and roles.
- `T3 body`: compiler AST statements/expressions, calls, operators and control edges.
- `T4 proof`: exact source spans and compiler diagnostics.

Each native frontend snapshot stores direct facts only. The composed project
graph additionally contains Lachesis overlays such as bounded taint closure,
context-specific heap effects, framework wiring, and effect-resolved dispatch.
The layered-v2 manifest is the compact LLM entry card; `lachesis.reasoning`
calculates focused slices instead of loading the entire graph into a prompt.

Control flow follows the same ownership boundary. Frontends emit exact AST,
statement-order, condition, branch, loop, switch, exception, and transfer facts.
The language-neutral control-flow overlay composes those facts into per-function
entry, condition, merge, and exit nodes plus explicit unreachable regions.

Cross-tier relationships are split into:

- `expands_to`: structural drill-down links.
- `links`: semantic relationships such as a body identifier referring to a path value.

Compiler frontends replace lexical, declaration, module and type discovery—not
Lachesis's security overlays. Framework wiring, runtime models, heap identity,
taint policy and exploit reasoning are layered over compiler-backed facts.
Frontends therefore do not tag attacker sources or security sinks. The generic
security-role runtime model consumes exported functions, parameters and
compiler-resolved call metadata, while framework models may add stronger entry
facts such as route-handler parameters. The core taint overlay runs only after
those independently registered policies have enriched the graph.

## Libraries and frameworks

Frontends do not stop at application files. Compiler-resolved declarations that
an application actually reaches are included with provenance:

- `application`: project implementation files.
- `workspace-library`: local headers/packages outside the application root.
- `dependency`: installed package declarations or included dependency headers.
- `standard-library`: compiler/runtime declarations such as `lib.dom.d.ts`.

TypeScript dependency files connect to package nodes through
`PACKAGE_CONTAINS`; import edges retain the package specifier, bindings, type-only
status and resolved location. For statically imported packages, the frontend also
follows the reachable runtime JavaScript source without recursively indexing all
of `node_modules`. `RUNTIME_DEPENDS_ON` preserves the executable module target,
`IMPLEMENTED_BY` bridges `.d.ts` API entities to matching implementations, and
calls retain both the compiler-selected declaration and runtime candidates. The
bounded traversal defaults to 500 dependency files and can be changed with
`LACHESIS_MAX_DEPENDENCY_FILES`.

C include edges retain header ownership, and AST declarations from headers
participate in call resolution. Framework semantic wiring (routes, dependency
injection, decorators, ORM metadata) remains an Lachesis overlay over these
compiler-backed declarations and implementation bodies rather than a parser
special case.

Clang also emits parameter/property mutation summaries. The shared canonical
overlay instantiates them at call sites, creates context-specific heap locations,
and can resolve later function-pointer member calls through the recorded write.

## Generic frontend boundary

[`lachesis/core/`](../core/) defines the language-neutral
frontend contract, plugin registry, capability negotiation and snapshot validator.
TypeScript/JavaScript and C are the currently registered command frontends.

Each future frontend may be implemented in its native toolchain, provided it emits
the same manifest and tier files. For example:

- Python: CPython AST plus Pyright/Pylance-compatible symbol and type facts.
- Java/Kotlin: compiler frontend or semantic indexer.
- C/C++: Clang AST, symbols and source locations.
- Go: `go/packages`, `go/types` and SSA.

Capabilities are explicitly marked `complete`, `partial` or `none`. A manual
Lachesis discovery pass is replaceable only when the selected frontend reports the
corresponding frontend-owned capability as `complete`. Heap, context sensitivity,
taint policy, runtime models, framework wiring and security roles remain overlays.
