"""Bounded Core Metadata validation, with no network or package imports.

The caller must pass its runtime gate before calling this function. ``packaging``
is intentionally imported only AFTER the raw bytes' expected digest is verified.
Versions passed in known_nodes are nominees, never evidence of child closure.
"""
import hashlib
import json
import re


MAX_RESPONSE_BYTES = 262144
MAX_HEADER_BYTES = 65536
MAX_FIELD_CHARS = 8192
MAX_FIELDS = 512
MAX_DEPENDENCIES = 256
MAX_RESULT_BYTES = 1048576
TARGET_KEYS = frozenset((
    "python_version", "python_full_version", "os_name", "sys_platform",
    "platform_machine", "platform_python_implementation", "implementation_name",
    "implementation_version", "platform_release", "platform_system",
    "platform_version", "extra",
))
REPEATABLE = frozenset((
    "platform", "supported-platform", "classifier", "requires-dist",
    "provides-dist", "obsoletes-dist", "project-url", "provides-extra",
    "dynamic", "license-file", "requires", "provides", "obsoletes",
))


class MetadataError(ValueError):
    """Stable failure code plus bounded, JSON-serializable partial findings."""

    def __init__(self, code, evidence=None):
        self.code = code
        self.evidence = evidence or {}
        super().__init__(code)


def _require(condition, code, evidence=None):
    if not condition:
        raise MetadataError(code, evidence)


def _headers(text):
    """Strict RFC822-style headers; never parse bodies or execute declarations."""
    _require("\r" not in text.replace("\r\n", ""), "metadata_bare_cr")
    text = text.replace("\r\n", "\n")
    head, separator, _body = text.partition("\n\n")
    # Core Metadata may have no body. A final newline terminates its last header.
    _require(separator or text.endswith("\n"), "metadata_header_termination")
    _require(len(head.encode("utf-8")) <= MAX_HEADER_BYTES, "metadata_headers_oversized")
    fields = []
    lines = head.split("\n")
    if not separator and lines[-1] == "":
        lines.pop()
    for line in lines:
        _require(not any(ord(c) < 32 and c != "\t" for c in line), "metadata_header_control")
        _require(not any(ord(c) == 127 for c in line), "metadata_header_control")
        if line.startswith((" ", "\t")):
            _require(bool(fields), "metadata_orphan_continuation")
            fields[-1][1] += " " + line.strip()
            _require(len(fields[-1][1]) <= MAX_FIELD_CHARS, "metadata_field_oversized")
            continue
        _require(":" in line, "metadata_malformed_header")
        key, value = line.split(":", 1)
        _require(re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9-]*", key) is not None,
                 "metadata_malformed_header")
        value = value.strip()
        _require(len(value) <= MAX_FIELD_CHARS, "metadata_field_oversized")
        fields.append([key.lower(), value])
        _require(len(fields) <= MAX_FIELDS, "metadata_too_many_fields")
    result = {}
    for key, value in fields:
        _require(key in REPEATABLE or key not in result, "metadata_duplicate_singleton")
        result.setdefault(key, []).append(value)
    for key in ("metadata-version", "name", "version", "requires-python"):
        _require(key in result and len(result[key]) == 1 and bool(result[key][0]),
                 "metadata_required_field")
    _require(result["metadata-version"][0] in {"1.2", "2.1", "2.2", "2.3", "2.4", "2.5"},
             "metadata_version_unsupported")
    _require(len(result.get("requires-dist", [])) <= MAX_DEPENDENCIES,
             "metadata_too_many_dependencies")
    # Wheel-specific metadata may legitimately retain Dynamic declarations from
    # its source build. They do not erase the exact artifact's declared fields.
    _require(all(re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9-]*", value)
                 for value in result.get("dynamic", [])), "metadata_invalid_dynamic")
    return result


def _marker_variables(marker):
    """Inspect the runtime-pinned packaging AST before any marker evaluation.

    packaging's public evaluate() merges the host defaults. Supplying EVERY
    supported environment key below prevents host fallback; inspecting the AST
    additionally refuses set-valued/new variables and unknown frozen values.
    A future AST shape fails closed and requires fresh parser review.
    """
    variables = set()

    def visit(nodes):
        _require(isinstance(nodes, list), "marker_ast_unsupported")
        for node in nodes:
            if isinstance(node, list):
                visit(node)
            elif isinstance(node, tuple) and len(node) == 3:
                for token in (node[0], node[2]):
                    kind = type(token).__name__
                    _require(kind in ("Variable", "Value") and isinstance(token.value, str),
                             "marker_ast_unsupported")
                    if kind == "Variable":
                        variables.add(token.value)
            else:
                _require(node in ("and", "or"), "marker_ast_unsupported")
    visit(marker._markers)
    _require(variables <= TARGET_KEYS, "marker_variable_unsupported")
    return variables


def _intersection(requirement, root, known, SpecifierSet, Version):
    """Prove only conflicts/witnesses supported by concrete versions or bounds.

    This is deliberately NOT a general PEP440 satisfiability solver. Compatible
    known nominees and exact witnesses do not approve artifacts or close graphs.
    """
    specs = [requirement] + ([root] if root is not None else [])
    if known is not None:
        _require(all(s.contains(known, prereleases=True) for s in specs),
                 "known_version_conflict")
        return "known_nominee_satisfies"
    exacts = [s.version for group in specs for s in group
              if s.operator in ("==", "===") and "*" not in s.version]
    if exacts:
        witnesses = []
        for exact in exacts:
            try:
                Version(exact)
            except ValueError:
                return "intersection_unresolved"
            if all(s.contains(exact, prereleases=True) for s in specs):
                witnesses.append(exact)
        _require(bool(witnesses), "root_constraint_conflict")
        return "exact_constraint_witness_only"
    lowers, uppers = [], []
    for group in specs:
        for spec in group:
            if spec.operator in (">", ">=", "<", "<="):
                bound = (Version(spec.version), spec.operator in (">=", "<="))
                (lowers if spec.operator.startswith(">") else uppers).append(bound)
    if lowers and uppers:
        lower = max(lowers, key=lambda b: (b[0], not b[1]))
        upper = min(uppers, key=lambda b: (b[0], b[1]))
        _require(lower[0] < upper[0] or (lower[0] == upper[0] and lower[1] and upper[1]),
                 "root_constraint_conflict")
    return "intersection_unresolved" if root is not None else "child_version_unselected"


def parse_metadata(raw, request, target, known_nodes, root_constraints):
    """Verify and parse one sidecar; no I/O, imports of nominees, or recursion.

    Input mappings: immutable proposal request/target, canonical-name -> exact
    nominee version, and canonical-name -> PEP440 root specifier. Returned edges
    have activity ``active``, ``inactive`` or ``unresolved``. Unknown target
    platform values never become host values or silently inactive edges.
    """
    _require(type(raw) is bytes, "metadata_bytes_required")
    _require(isinstance(request, dict), "metadata_request_invalid")
    cap = request.get("max_response_bytes")
    _require(type(cap) is int and 0 < cap <= MAX_RESPONSE_BYTES, "metadata_cap_invalid")
    _require(len(raw) <= cap, "metadata_oversized")
    expected = request.get("expected_response_sha256")
    _require(isinstance(expected, str) and re.fullmatch(r"[0-9a-f]{64}", expected),
             "metadata_digest_invalid")
    digest = hashlib.sha256(raw).hexdigest()
    _require(digest == expected, "metadata_digest_mismatch")
    # No metadata decoder, header parser or packaging import precedes this gate.
    try:
        text = raw.decode("utf-8", errors="strict")
    except UnicodeDecodeError as exc:
        raise MetadataError("metadata_invalid_utf8") from exc
    _require(not text.startswith("\ufeff"), "metadata_bom_rejected")
    headers = _headers(text)
    try:
        from packaging.requirements import Requirement, InvalidRequirement
        from packaging.specifiers import SpecifierSet, InvalidSpecifier
        from packaging.utils import canonicalize_name, InvalidName
        from packaging.version import Version, InvalidVersion
    except ImportError as exc:
        raise MetadataError("metadata_parser_unavailable") from exc

    _require(isinstance(target, dict) and set(target) == TARGET_KEYS and
             all(isinstance(value, str) and len(value) <= 256 for value in target.values()),
             "metadata_target_incomplete")
    _require(target["extra"] == "", "metadata_extras_scope_rejected")
    _require(target["python_version"] == "3.12" and target["python_full_version"] == "3.12.15"
             and target["implementation_version"] == "3.12.15", "metadata_target_python_mismatch")
    _require(all(target[key] for key in TARGET_KEYS - {"extra", "platform_release", "platform_version"}),
             "metadata_target_incomplete")
    _require(isinstance(known_nodes, dict) and isinstance(root_constraints, dict) and
             len(known_nodes) <= 512 and len(root_constraints) <= 512, "metadata_constraints_invalid")
    try:
        project = canonicalize_name(request["project"], validate=True)
        name = canonicalize_name(headers["name"][0], validate=True)
        _require(project == name, "metadata_name_mismatch")
        version = headers["version"][0]
        Version(version)
        _require(version == request["version"], "metadata_version_mismatch")
        requires_python_raw = headers["requires-python"][0]
        requires_python = SpecifierSet(requires_python_raw)
        index_python_raw = request["frozen_source"]["requires_python"]
        _require(isinstance(index_python_raw, str) and bool(index_python_raw),
                 "metadata_frozen_python_missing")
        _require(requires_python == SpecifierSet(index_python_raw), "metadata_requires_python_mismatch")
        _require(requires_python.contains(target["python_full_version"], prereleases=True),
                 "metadata_python_incompatible")
        for mapping in (known_nodes, root_constraints):
            for key, value in mapping.items():
                _require(isinstance(key, str) and canonicalize_name(key, validate=True) == key
                         and isinstance(value, str) and len(value) <= MAX_FIELD_CHARS,
                         "metadata_constraints_invalid")
        for value in known_nodes.values():
            Version(value)
        roots = {key: SpecifierSet(value) for key, value in root_constraints.items()}
        _require(name not in known_nodes or known_nodes[name] == version, "known_version_conflict")
        _require(name not in roots or roots[name].contains(version, prereleases=True),
                 "root_constraint_conflict")
    except (KeyError, TypeError, InvalidName, InvalidVersion, InvalidSpecifier) as exc:
        raise MetadataError("metadata_identity_or_constraint_invalid") from exc

    result = {
        "schema": "performance_v2_sidecar_metadata_v1",
        "response_sha256": digest, "response_bytes": len(raw),
        "digest_verified_before_parse": True,
        "metadata_version": headers["metadata-version"][0],
        "dynamic_fields": list(headers.get("dynamic", [])),
        "name_raw": headers["name"][0], "name": name, "version": version,
        "requires_python_raw": requires_python_raw,
        "requires_python": str(requires_python), "frozen_target": dict(target),
        "root_constraint": root_constraints.get(name),
        "scope": "runtime_no_extras", "edges": [], "unresolved_children": [],
        "dependency_closure_complete": False, "install_selection_approved": False,
        "automatic_recursion": False,
    }
    for raw_requirement in headers.get("requires-dist", []):
        _require(bool(raw_requirement), "metadata_empty_requires_dist", result)
        try:
            requirement = Requirement(raw_requirement)
            child = canonicalize_name(requirement.name, validate=True)
        except (InvalidRequirement, InvalidName, RecursionError) as exc:
            raise MetadataError("metadata_invalid_requires_dist", result) from exc
        try:
            variables = _marker_variables(requirement.marker) if requirement.marker else set()
        except RecursionError as exc:
            raise MetadataError("marker_ast_unsupported", result) from exc
        unknown_values = sorted(k for k in variables if k != "extra" and not target[k])
        if unknown_values:
            activity = "unresolved"
        else:
            try:
                activity = "active" if requirement.marker is None or requirement.marker.evaluate(
                    environment=dict(target)) else "inactive"
            except (ValueError, KeyError, TypeError, RecursionError) as exc:
                raise MetadataError("metadata_marker_evaluation_failed", result) from exc
        edge = {
            "name": child, "raw": raw_requirement, "specifier": str(requirement.specifier),
            "marker": str(requirement.marker) if requirement.marker else None,
            "marker_variables": sorted(variables), "requested_extras": sorted(requirement.extras),
            "url": requirement.url, "activity": activity,
            "target_values_unresolved": unknown_values,
            "known_nominee_version": known_nodes.get(child),
            "root_constraint": root_constraints.get(child),
            "constraint_status": "inactive_not_applied" if activity == "inactive" else "unresolved",
            "child_metadata_closed": False,
            "self_cycle": child == name,
        }
        result["edges"].append(edge)
        if activity != "inactive":
            if requirement.url is not None:
                edge["constraint_status"] = "direct_url_not_authorized"
            elif activity == "unresolved":
                edge["constraint_status"] = "target_marker_value_unknown"
            else:
                try:
                    edge["constraint_status"] = _intersection(
                        requirement.specifier, roots.get(child), known_nodes.get(child), SpecifierSet, Version)
                except MetadataError as exc:
                    edge["constraint_status"] = exc.code
                    raise MetadataError(exc.code, result) from exc
            reasons = ["child_metadata_not_bound"]
            if requirement.url is not None:
                reasons.append("direct_url_not_authorized")
            if unknown_values:
                reasons.append("target_marker_value_unknown")
            if requirement.extras:
                reasons.append("child_extras_closure_not_reviewed")
            if child not in known_nodes:
                reasons.append("child_version_not_selected")
            if child == name:
                reasons.append("self_cycle_requires_graph_review")
            result["unresolved_children"].append({
                "edge_index": len(result["edges"]) - 1, "name": child,
                "activity": activity, "reasons": reasons,
            })
    # Also conjoin repeated active declarations within this one sidecar. The
    # collector repeats the same operation over all accumulated response results.
    try:
        result["collection_constraint_summary"] = check_collection_constraints(
            [result], root_constraints, known_nodes, target)
    except MetadataError as exc:
        raise MetadataError(exc.code, {"metadata": result, "conjunction": exc.evidence}) from exc
    _require(len(json.dumps(result, sort_keys=True, ensure_ascii=True).encode("utf-8")) <= MAX_RESULT_BYTES,
             "metadata_result_oversized")
    return result


def check_collection_constraints(results, root_constraints, known_nodes, target):
    """Conjoin active edges across <=7 already validated sidecar results.

    Edges remain in their parent result. This evidence refers to them by response
    digest and edge index and never fetches children. Unknown-marker/direct-URL
    edges remain unresolved; compatible known versions prove no artifact closure.
    Obvious empty intervals or contradictory concrete equalities fail closed;
    other PEP440 satisfiability questions explicitly remain unresolved.
    """
    from packaging.specifiers import SpecifierSet, InvalidSpecifier
    from packaging.utils import canonicalize_name, InvalidName
    from packaging.version import Version, InvalidVersion

    _require(isinstance(results, list) and len(results) <= 7, "collection_results_invalid")
    _require(isinstance(target, dict) and set(target) == TARGET_KEYS,
             "metadata_target_incomplete")
    _require(isinstance(root_constraints, dict) and isinstance(known_nodes, dict)
             and len(root_constraints) <= 512 and len(known_nodes) <= 512,
             "metadata_constraints_invalid")
    try:
        for mapping in (root_constraints, known_nodes):
            for key, value in mapping.items():
                _require(isinstance(key, str) and canonicalize_name(key, validate=True) == key
                         and isinstance(value, str) and len(value) <= MAX_FIELD_CHARS,
                         "metadata_constraints_invalid")
        roots = {key: SpecifierSet(value) for key, value in root_constraints.items()}
        for value in known_nodes.values():
            Version(value)
    except (InvalidName, InvalidSpecifier, InvalidVersion) as exc:
        raise MetadataError("metadata_constraints_invalid") from exc
    summary = {"schema": "performance_v2_sidecar_constraint_conjunction_v1",
               "children": [], "dependency_closure_complete": False,
               "install_selection_approved": False, "automatic_recursion": False,
               "all_intersections_proven": False}
    groups = {}
    for result in results:
        _require(isinstance(result, dict) and result.get("frozen_target") == target
                 and result.get("digest_verified_before_parse") is True
                 and isinstance(result.get("edges"), list)
                 and len(result["edges"]) <= MAX_DEPENDENCIES, "collection_results_invalid")
        for index, edge in enumerate(result["edges"]):
            name = edge["name"]
            group = groups.setdefault(name, {
                "name": name, "active_edges": [], "inactive_edges": [], "unresolved_edges": [],
                "root_constraint": root_constraints.get(name),
                "known_nominee_version": known_nodes.get(name), "conjoined_specifier": "",
                "constraint_status": "unresolved", "child_metadata_closed": False,
            })
            ref = {"parent": result["name"], "response_sha256": result["response_sha256"],
                   "edge_index": index, "specifier": edge["specifier"],
                   "self_cycle": edge.get("self_cycle", False)}
            if edge["activity"] == "inactive":
                group["inactive_edges"].append(ref)
            elif edge["activity"] == "unresolved" or edge["url"] is not None:
                ref["reason"] = ("direct_url_not_authorized" if edge["url"] is not None
                                 else "target_marker_value_unknown")
                group["unresolved_edges"].append(ref)
            elif edge["activity"] == "active":
                group["active_edges"].append(ref)
            else:
                raise MetadataError("collection_results_invalid")
    for name in sorted(groups):
        group = groups[name]
        summary["children"].append(group)
        if group["active_edges"]:
            try:
                combined = SpecifierSet(",".join(ref["specifier"] for ref in group["active_edges"]))
                group["conjoined_specifier"] = str(combined)
                group["constraint_status"] = _intersection(
                    combined, roots.get(name), known_nodes.get(name), SpecifierSet, Version)
            except InvalidSpecifier as exc:
                raise MetadataError("metadata_invalid_requires_dist", summary) from exc
            except MetadataError as exc:
                group["constraint_status"] = exc.code
                raise MetadataError(exc.code, summary) from exc
        elif not group["unresolved_edges"]:
            group["constraint_status"] = "inactive_not_applied"
        group["unresolved_requirements_present"] = bool(group["unresolved_edges"])
    _require(len(json.dumps(summary, sort_keys=True, ensure_ascii=True).encode("utf-8")) <= MAX_RESULT_BYTES,
             "metadata_result_oversized")
    return summary
