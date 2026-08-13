# Deprecated

Things that are still here, still work, and should not be built on. Each entry says
what it was for, why it is inert, and what removing it would cost. Nothing in this
file changes behaviour by default.

## The T0-T4 tier concept

**Status:** deprecated, still enforced by default, not scheduled for removal.

### What it was for

A graph was to be progressively drillable. A reader would take T0 for the perimeter
of a project (files, modules, imports, exports), descend to T1 for the things
reachability is defined over (functions, classes, methods), and keep descending only
as far as the question needed. Tiers would be the unit of that descent: a bundle
would be five files, and a consumer could read one and stop.

Every frontend implements it. Each one carries a table mapping node kind to tier, and
each one writes its payload split five ways.

### Why it is inert

Nothing reads a node's tier back.

* The navigation layer does not select a `tier` property. Not for search, not for
  callers or callees, not for dataflow, not for anything.
* The store keeps the property, so it is queryable in principle, and no query in this
  repository uses it.
* The one consumer is `lachesis/core/validation.py`, which rejects a node whose tier
  is not one of the tiers its kind is allowed to occupy. That check reads a tier the
  frontend was obliged to choose only because the check exists.

The result is a rule that validates its own input. A new node kind cannot be added
without a line in `NODE_KIND_TIERS` and a line in each frontend's tier table, and
getting either wrong fails a build for a reason that has no consequence downstream.

### Why it is staying

Removing it is a format change, not a cleanup.

* `tier` is stamped on every node in every stored graph. Dropping it makes new stores
  and old stores different shapes.
* `source_tier` is stamped on every edge, and it is not the same fact: it records
  which payload an edge arrived in, which is how a cross-tier link keeps its
  direction. That would have to be replaced rather than deleted.
* The bundle layout is five files whose names come from the tier names, so the
  layered projection and every bundle written so far assume them.
* Three frontends would need coordinated changes, one of which is not written in
  Python.

None of that is hard. All of it is a migration, and there is no user waiting for it.

### The knob

`LACHESIS_TIER_VALIDATION` controls the placement check, and only that check:

* `strict` (default) is what has always shipped. A misplaced tier raises
  `ContractError`.
* `warn` reports the first violation in a process and keeps the graph.
* `off` skips the check entirely.

It exists so the cost of retiring the rule can be measured instead of argued about.
Anyone can run a build with `off` and see whether anything downstream notices. It is
not intended for builds whose output is kept: a store built without the check may
contain tier values that a later `strict` build would reject, and nothing will tell
you that until then.

### If you are adding a node kind

Add it to `NODE_KIND_TIERS` in `lachesis/core/schema.py` and to the tier table in each
frontend that emits it. Pick the tier that matches the neighbours it is most like.
Do not spend design attention on the choice, and do not add a consumer that reads it
back.
