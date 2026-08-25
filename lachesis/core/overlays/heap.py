"""Language-neutral allocation-site and property heap identity."""
from __future__ import annotations

from collections import defaultdict, deque

from ..composition import GraphDelta
from ..identities import stable_id
from ..query import GraphIndex


IDENTITY_FLOW_REASONS = frozenset({
    "allocation", "initializer", "assignment", "write", "read", "read-value",
    "argument-value", "context-argument", "context-call-result", "return",
    "call-result", "branch-reaching-definition", "phi-input", "call-argument",
    # A value-preserving expression -- a cast or parenthesization -- does not
    # change what a pointer refers to, so heap identity must survive it. On C the
    # `void *` result of an allocator reaches its typed receiver through exactly
    # such an implicit cast; without this the object never reaches the variable.
    "value-preserving-expression",
})


def _fact(evidence_ids: list[str], confidence: str = "high") -> dict:
    return {
        "fact_origin": "core-inference",
        "confidence": confidence,
        "evidence_ids": list(dict.fromkeys(evidence_ids)),
    }


class HeapIdentity:
    """Propagate allocation identities and collapse alias property locations."""

    overlay_id = "heap-identity"

    def applies(self, graph: dict, index: GraphIndex | None = None) -> bool:
        index = GraphIndex(graph) if index is None else index
        return index.has_kind("allocation")

    def enrich(self, graph: dict, index: GraphIndex | None = None) -> GraphDelta:
        index = GraphIndex(graph) if index is None else index
        nodes: list[dict] = []
        edges: list[dict] = []
        emitted_edges: set[tuple[str, str, str]] = set()
        emitted_nodes: set[str] = set()
        points: dict[str, set[str]] = defaultdict(set)
        object_properties: dict[str, dict] = {}
        parameter_objects: dict[str, str] = {}

        def add_node(node: dict) -> None:
            if node["id"] in emitted_nodes:
                return
            emitted_nodes.add(node["id"])
            nodes.append(node)

        def add_edge(kind: str, source: str, target: str, evidence: list[str], **properties) -> None:
            if not source or not target or source == target:
                return
            key = (kind, source, target)
            if key in emitted_edges:
                return
            emitted_edges.add(key)
            edges.append({
                "kind": kind,
                "source": source,
                "target": target,
                "properties": {**_fact(evidence), **properties},
            })

        def add_points(value_id: str | None, object_ids) -> bool:
            if not value_id:
                return False
            before = len(points[value_id])
            points[value_id].update(object_ids)
            return len(points[value_id]) != before

        # Concrete allocation sites are templates. Context-return handling
        # below clones callee-local templates per call site when needed.
        for allocation in index.nodes_of_kind("allocation"):
            allocation_id = allocation["id"]
            object_id = stable_id(
                "core", self.overlay_id, "heap-object", allocation_id,
            )
            properties = allocation.get("properties", {})
            fact = _fact([allocation_id], "exact")
            object_properties[object_id] = {
                "allocation_id": allocation_id,
                "owner_function_id": properties.get("owner_function_id"),
                "allocation_kind": properties.get("allocation_kind"),
                "allocated_type": properties.get("allocated_type"),
                "context_id": None,
            }
            add_node({
                "id": object_id,
                "kind": "heap-object",
                "label": f"object:{allocation.get('label', allocation_id)}",
                "properties": {**fact, **object_properties[object_id]},
            })
            add_points(allocation_id, {object_id})
            add_edge("POINTS_TO", allocation_id, object_id, [allocation_id])

        # Reference-like parameters receive an abstract object. Generic or
        # unknown categories stay conservative; only compiler-labelled
        # primitive values are excluded.
        for parameter in index.nodes_of_kind("parameter"):
            if parameter.get("properties", {}).get("value_category") == "primitive":
                continue
            definitions = [
                target for target in index.targets(parameter["id"], "DEFINES")
                if target.get("kind") == "definition"
                and target.get("properties", {}).get("origin") == "parameter"
            ]
            if not definitions:
                continue
            object_id = stable_id(
                "core", self.overlay_id, "heap-object", "parameter", parameter["id"],
            )
            evidence = [parameter["id"], *(definition["id"] for definition in definitions)]
            fact = _fact(evidence, "conservative")
            object_properties[object_id] = {
                "allocation_id": None,
                "owner_function_id": parameter.get("properties", {}).get("owner_function_id"),
                "allocation_kind": "parameter",
                "allocated_type": parameter.get("properties", {}).get("type"),
                "parameter_id": parameter["id"],
                "context_id": None,
            }
            add_node({
                "id": object_id, "kind": "heap-object",
                "label": f"parameter-object:{parameter.get('label', parameter['id'])}",
                "properties": {**fact, **object_properties[object_id]},
            })
            parameter_objects[parameter["id"]] = object_id
            add_points(parameter["id"], {object_id})
            add_edge("POINTS_TO", parameter["id"], object_id, evidence, abstract=True)
            for definition in definitions:
                add_points(definition["id"], {object_id})
                add_edge("POINTS_TO", definition["id"], object_id, evidence, abstract=True)

        identity_edges: list[tuple[str, str]] = []
        context_return_sources: dict[str, list[str]] = defaultdict(list)
        for edge in graph.get("edges", []):
            kind = index.semantic_edge_kind(edge)
            properties = edge.get("properties", {})
            if kind in {"ALIASES", "ALIASES_VALUE", "READS_FROM", "PHI_INPUT"}:
                identity_edges.append((edge["source"], edge["target"]))
            elif kind == "VALUE_FLOWS_TO":
                reason = properties.get("reason")
                if reason == "context-return":
                    context_return_sources[edge["target"]].append(edge["source"])
                elif reason in IDENTITY_FLOW_REASONS:
                    identity_edges.append((edge["source"], edge["target"]))

        # A definition is the versioned value of its declared target. Keep the
        # target's flow-insensitive points-to set as the union of its versions.
        for definition in index.nodes_of_kind("definition"):
            target_id = definition.get("properties", {}).get("target_id")
            if target_id:
                identity_edges.append((definition["id"], target_id))

        identity_targets: dict[str, list[str]] = defaultdict(list)
        for source, target in identity_edges:
            identity_targets[source].append(target)

        def propagate_identity(seeds=None) -> set[str]:
            """Push newly discovered points through identity edges once.

            The old fixed-point loop rescanned every identity edge once per
            propagation wave. Large CPGs contain long chains of definitions and
            value-preserving expressions, so a late point could make that loop walk
            the whole edge list hundreds of times. A worklist visits an edge again
            only when its source set actually grew; the resulting union is identical
            because points-to facts are monotone.
            """
            if seeds is None:
                queue = deque(value_id for value_id, object_ids in points.items()
                              if object_ids)
            else:
                queue = deque(value_id for value_id in seeds if points.get(value_id))
            queued = set(queue)
            changed_values: set[str] = set()
            while queue:
                source = queue.popleft()
                queued.discard(source)
                source_objects = points.get(source, ())
                for target in identity_targets.get(source, ()):
                    target_objects = points[target]
                    before = len(target_objects)
                    target_objects.update(source_objects)
                    if len(target_objects) == before:
                        continue
                    changed_values.add(target)
                    if target not in queued:
                        queued.add(target)
                        queue.append(target)
            return changed_values

        propagate_identity()

        # Bind caller objects to the context parameter without contaminating a
        # shared callee parameter definition across unrelated call sites.
        context_parameter_objects: dict[str, dict[str, set[str]]] = defaultdict(dict)
        for binding in index.nodes_of_kind("context-parameter"):
            properties = binding.get("properties", {})
            argument_id = properties.get("argument_id")
            parameter_id = properties.get("parameter_id")
            context_id = properties.get("context_id")
            caller_objects = set(points.get(argument_id, set()))
            add_points(binding["id"], caller_objects)
            if context_id and parameter_id:
                abstract = parameter_objects.get(parameter_id)
                if abstract:
                    context_parameter_objects[context_id][abstract] = caller_objects

        contexts_by_abstract: dict[str, list[tuple[str, set[str], dict[str, set[str]]]]] = \
            defaultdict(list)
        for context_id, substitutions in context_parameter_objects.items():
            for abstract_object, caller_objects in substitutions.items():
                if caller_objects:
                    contexts_by_abstract[abstract_object].append(
                        (context_id, caller_objects, substitutions),
                    )

        # Substitute parameter templates and clone callee-local return
        # allocations separately for every call context.
        for returned in index.nodes_of_kind("context-return"):
            properties = returned.get("properties", {})
            context_id = properties.get("context_id")
            callee_id = properties.get("callee_function_id")
            substitutions = context_parameter_objects.get(context_id, {})
            returned_objects: set[str] = set()
            for source_id in context_return_sources.get(returned["id"], []):
                for object_id in points.get(source_id, set()):
                    if object_id in substitutions:
                        returned_objects.update(substitutions[object_id])
                        continue
                    template = object_properties.get(object_id, {})
                    if callee_id and template.get("owner_function_id") == callee_id:
                        instance_id = stable_id(
                            "core", self.overlay_id, "heap-object",
                            "context", context_id, object_id,
                        )
                        evidence = [returned["id"], context_id, object_id]
                        fact = _fact(evidence, "exact")
                        object_properties[instance_id] = {
                            **template,
                            "context_id": context_id,
                            "allocation_template_id": object_id,
                        }
                        add_node({
                            "id": instance_id, "kind": "heap-object",
                            "label": f"context-object:{index.nodes.get(object_id, {}).get('label', object_id)}",
                            "properties": {**fact, **object_properties[instance_id]},
                        })
                        add_edge("CONTEXT_ALLOCATES", context_id, instance_id, evidence)
                        returned_objects.add(instance_id)
                    else:
                        returned_objects.add(object_id)
            add_points(returned["id"], returned_objects)

        propagate_identity()

        property_paths = list(index.nodes_of_kind("property-path"))
        writes_by_target: dict[str, list[dict]] = defaultdict(list)
        reads_by_target: dict[str, list[dict]] = defaultdict(list)
        for write in index.nodes_of_kind("write"):
            target_id = write.get("properties", {}).get("target_id")
            if target_id:
                writes_by_target[target_id].append(write)
        for read in index.nodes_of_kind("read"):
            target_id = read.get("properties", {}).get("target_id")
            if target_id:
                reads_by_target[target_id].append(read)

        locations: dict[tuple[str, tuple[str, ...]], str] = {}
        location_values: dict[str, set[str]] = defaultdict(set)
        effects: set[str] = set()
        normalized_path_cache: dict[str, tuple[str, ...]] = {}
        target_location_cache: dict[tuple[str, tuple[str, ...]], frozenset[str]] = {}

        # A property path only needs to be revisited when one of its base/value
        # points-to sets grows. Index those dependencies once so the fixed point
        # below schedules affected paths instead of rescanning every property path
        # on every round.
        paths_by_dependency: dict[str, list[dict]] = defaultdict(list)
        for path in property_paths:
            base_id = path.get("properties", {}).get("base_value_id")
            if base_id:
                paths_by_dependency[base_id].append(path)
            for write in writes_by_target.get(path["id"], ()):
                value_id = write.get("properties", {}).get("value_id")
                if value_id:
                    paths_by_dependency[value_id].append(path)

        def normalized_segments(path: dict) -> tuple[str, ...]:
            cached = normalized_path_cache.get(path["id"])
            if cached is not None:
                return cached
            structured = path.get("properties", {}).get("path_segments") or []
            if structured:
                result = tuple(
                    "[*]" if segment.get("dynamic") else str(segment.get("key", "?"))
                    for segment in structured
                )
            else:
                opaque = path.get("properties", {}).get("path")
                result = (str(opaque or "?"),)
            normalized_path_cache[path["id"]] = result
            return result

        def location(object_id: str, segments: tuple[str, ...], evidence: list[str]) -> str:
            key = (object_id, segments)
            if key in locations:
                return locations[key]
            location_id = stable_id(
                "core", self.overlay_id, "heap-location", object_id, segments,
            )
            fact = _fact(evidence)
            locations[key] = location_id
            add_node({
                "id": location_id, "kind": "heap-location",
                "label": f"{index.nodes.get(object_id, {}).get('label', object_id)}.{'.'.join(segments)}",
                "properties": {
                    **fact, "object_id": object_id,
                    "path_segments": list(segments),
                    "path": ".".join(segments),
                },
            })
            add_edge("POINTS_TO", object_id, location_id, evidence, relationship="property")
            return location_id

        def target_locations(
            object_id: str, segments: tuple[str, ...], evidence: list[str],
        ) -> frozenset[str]:
            cache_key = (object_id, segments)
            cached = target_location_cache.get(cache_key)
            if cached is not None:
                return cached
            current_objects = {object_id}
            prefix: tuple[str, ...] = ()
            for segment in segments[:-1]:
                prefix = (*prefix, segment)
                next_objects: set[str] = set()
                for current_object in current_objects:
                    prefix_location = location(current_object, (segment,), evidence)
                    stored = location_values[prefix_location]
                    if not stored:
                        child_id = stable_id(
                            "core", self.overlay_id, "heap-object",
                            "property", current_object, segment,
                        )
                        fact = _fact([*evidence, prefix_location], "conservative")
                        object_properties[child_id] = {
                            "allocation_id": None,
                            "owner_function_id": None,
                            "allocation_kind": "property",
                            "parent_object_id": current_object,
                            "property_segment": segment,
                            "context_id": None,
                        }
                        add_node({
                            "id": child_id, "kind": "heap-object",
                            "label": f"property-object:{segment}",
                            "properties": {**fact, **object_properties[child_id]},
                        })
                        stored.add(child_id)
                        add_edge("POINTS_TO", prefix_location, child_id, evidence)
                    next_objects.update(stored)
                current_objects = next_objects
            result = frozenset({
                location(current_object, (segments[-1],), evidence)
                for current_object in current_objects
            })
            target_location_cache[cache_key] = result
            return result

        def propagate_worklist() -> bool:
            """Reach the property/points-to fixed point without global rescans."""
            pending = deque(property_paths)
            queued = {path["id"] for path in property_paths}
            readers: dict[str, dict[str, dict]] = defaultdict(dict)
            changed_any = False

            def enqueue(value_ids) -> None:
                for value_id in value_ids:
                    for path in paths_by_dependency.get(value_id, ()):
                        if path["id"] not in queued:
                            queued.add(path["id"])
                            pending.append(path)

            def register_reader(location_id: str, read: dict) -> set[str]:
                readers[location_id][read["id"]] = read
                value_ids = location_values.get(location_id, ())
                before = len(points[read["id"]])
                points[read["id"]].update(value_ids)
                return {read["id"]} if len(points[read["id"]]) != before else set()

            def update_location(location_id: str, value_ids) -> set[str]:
                values = location_values[location_id]
                before = len(values)
                values.update(value_ids)
                changed = set()
                if len(values) == before:
                    return changed
                for read in readers.get(location_id, {}).values():
                    read_before = len(points[read["id"]])
                    points[read["id"]].update(values)
                    if len(points[read["id"]]) != read_before:
                        changed.add(read["id"])
                return changed

            while pending:
                path = pending.popleft()
                queued.discard(path["id"])
                properties = path.get("properties", {})
                base_id = properties.get("base_value_id")
                segments = normalized_segments(path)
                if not base_id or not segments:
                    continue
                changed_points: set[str] = set()
                for object_id in list(points.get(base_id, ())):
                    target_ids = target_locations(
                        object_id, segments, [path["id"], base_id, object_id],
                    )
                    reads = reads_by_target.get(path["id"], ())
                    for location_id in target_ids:
                        for read in reads:
                            changed_points.update(register_reader(location_id, read))
                        for write in writes_by_target.get(path["id"], ()):
                            value_id = write.get("properties", {}).get("value_id")
                            changed_points.update(update_location(
                                location_id, points.get(value_id, ()),
                            ))
                            abstract_object = parameter_objects.get(base_id)
                            function_id = write.get("properties", {}).get(
                                "owner_function_id")
                            if not abstract_object or not function_id:
                                continue
                            for context_id, caller_objects, substitutions \
                                    in contexts_by_abstract.get(abstract_object, ()):
                                contextual_values: set[str] = set()
                                for value_object in points.get(value_id, ()):
                                    contextual_values.update(
                                        substitutions.get(value_object, {value_object})
                                    )
                                for caller_object in caller_objects:
                                    caller_locations = target_locations(
                                        caller_object, segments,
                                        [path["id"], context_id, caller_object],
                                    )
                                    for caller_location in caller_locations:
                                        changed_points.update(update_location(
                                            caller_location, contextual_values,
                                        ))
                identity_changed = propagate_identity(changed_points)
                if changed_points or identity_changed:
                    changed_any = True
                    enqueue((*changed_points, *identity_changed))
            return changed_any

        # Property reads and writes can reveal new aliases. Iterate location
        # contents and identity propagation to a fixed point, then emit once over
        # the converged state. Every edge below is a function of that state and of
        # nothing a later round can take away, since points and location_values
        # only grow, so the rounds before convergence were re-deriving edges the
        # dedup set immediately discarded. The propagation itself is unchanged, and
        # so are the nodes and POINTS_TO edges that target_locations creates as a
        # side effect of walking a prefix, which have to keep pace with the rounds.
        def propagate(emit: bool) -> bool:
            if not emit:
                return propagate_worklist()
            changed = False
            changed_points: set[str] = set()
            for path in property_paths:
                properties = path.get("properties", {})
                base_id = properties.get("base_value_id")
                segments = normalized_segments(path)
                if not base_id or not segments:
                    continue
                for object_id in list(points.get(base_id, set())):
                    target_ids = target_locations(
                        object_id, segments, [path["id"], base_id, object_id],
                    )
                    for write in writes_by_target.get(path["id"], []):
                        value_id = write.get("properties", {}).get("value_id")
                        value_objects = set(points.get(value_id, set()))
                        for location_id in target_ids:
                            before = len(location_values[location_id])
                            location_values[location_id].update(value_objects)
                            changed |= len(location_values[location_id]) != before
                            if emit:
                                add_edge(
                                    "WRITES_HEAP", write["id"], location_id,
                                    [write["id"], path["id"], location_id],
                                    property_path_id=path["id"],
                                )
                        abstract_object = parameter_objects.get(base_id)
                        function_id = write.get("properties", {}).get("owner_function_id")
                        if abstract_object and function_id:
                            effect_id = stable_id(
                                "core", self.overlay_id, "function-effect",
                                function_id, base_id, segments, write["id"],
                            )
                            effect_evidence = [function_id, base_id, path["id"], write["id"]]
                            if emit and effect_id not in effects:
                                effects.add(effect_id)
                                add_node({
                                    "id": effect_id, "kind": "function-effect",
                                    "label": f"writes:{path.get('label', path['id'])}",
                                    "properties": {
                                        **_fact(effect_evidence),
                                        "function_id": function_id,
                                        "effect_kind": "parameter-property-write",
                                        "parameter_id": base_id,
                                        "path_segments": list(segments),
                                        "write_id": write["id"],
                                        "value_id": value_id,
                                    },
                                })
                                add_edge("MUTATES", function_id, effect_id, effect_evidence)
                                add_edge("EVIDENCED_BY", effect_id, write["id"], effect_evidence)
                            for context_id, caller_objects, substitutions \
                                    in contexts_by_abstract.get(abstract_object, ()):
                                contextual_values: set[str] = set()
                                for value_object in value_objects:
                                    contextual_values.update(
                                        substitutions.get(value_object, {value_object})
                                    )
                                for caller_object in caller_objects:
                                    caller_locations = target_locations(
                                        caller_object, segments,
                                        [effect_id, context_id, caller_object],
                                    )
                                    for caller_location in caller_locations:
                                        before = len(location_values[caller_location])
                                        location_values[caller_location].update(contextual_values)
                                        changed |= len(location_values[caller_location]) != before
                                        if emit:
                                            add_edge(
                                                "APPLIES_EFFECT", context_id, caller_location,
                                                [effect_id, context_id, caller_location],
                                                effect_id=effect_id,
                                            )
                                            add_edge(
                                                "WRITES_HEAP", write["id"], caller_location,
                                                [effect_id, context_id, write["id"],
                                                 caller_location],
                                                effect_id=effect_id, context_id=context_id,
                                            )
                    for read in reads_by_target.get(path["id"], []):
                        for location_id in target_ids:
                            if add_points(
                                read["id"], location_values.get(location_id, set()),
                            ):
                                changed = True
                                changed_points.add(read["id"])
                            if emit:
                                add_edge(
                                    "READS_HEAP", location_id, read["id"],
                                    [read["id"], path["id"], location_id],
                                    property_path_id=path["id"],
                                )
            changed |= bool(propagate_identity(changed_points))
            return changed

        while propagate(emit=False):
            pass
        propagate(emit=True)

        for value_id, object_ids in sorted(points.items()):
            if value_id not in index.nodes and value_id not in emitted_nodes:
                continue
            for object_id in sorted(object_ids):
                add_edge("POINTS_TO", value_id, object_id, [value_id, object_id])

        return GraphDelta(self.overlay_id, nodes, edges)
