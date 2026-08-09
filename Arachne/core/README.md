# Canonical graph contract v2

`Arachne.core` is language-agnostic. It defines graph identities, canonical
node/edge kinds, capability vocabulary, provenance rules, validation and graph
composition. It must not import a language frontend, an ecosystem model or the
legacy compatibility API.

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

## Version migration

Contract v1 snapshots remain accepted only as migration inputs. They receive
the old structural and source-span checks, while v2 snapshots receive strict
kind, owner, tier, source provenance and evidence validation. Frontends will be
moved to v2 individually; once both registered frontends emit v2 and the legacy
API reads from the completed canonical graph, v1 support can be deleted.
