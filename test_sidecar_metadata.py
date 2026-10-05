"""Synthetic, offline-only metadata tests; no proposed response is fetched."""
import copy
import hashlib
import json
import unittest
from unittest import mock

import sidecar_metadata as sm


TARGET = {
    "python_version": "3.12", "python_full_version": "3.12.15", "os_name": "posix",
    "sys_platform": "linux", "platform_machine": "x86_64",
    "platform_python_implementation": "CPython", "implementation_name": "cpython",
    "implementation_version": "3.12.15", "platform_release": "",
    "platform_system": "Linux", "platform_version": "", "extra": "",
}


def body(dependencies=(), *, name="sample", version="1.2.0", python=">=3.10", extra=""):
    headers = ["Metadata-Version: 2.4", "Name: " + name, "Version: " + version,
               "Requires-Python: " + python]
    headers.extend("Requires-Dist: " + value for value in dependencies)
    return ("\n".join(headers) + ("\n" + extra if extra else "") + "\n\nDescription.\n").encode()


def request(raw, *, name="sample", version="1.2.0", python=">=3.10"):
    return {"project": name, "version": version, "max_response_bytes": 262144,
            "expected_response_sha256": hashlib.sha256(raw).hexdigest(),
            "frozen_source": {"requires_python": python}}


class MetadataTests(unittest.TestCase):
    def parse(self, raw=None, req=None, target=None, known=None, roots=None):
        raw = body() if raw is None else raw
        return sm.parse_metadata(raw, request(raw) if req is None else req,
                                 copy.deepcopy(TARGET) if target is None else target,
                                 {} if known is None else known, {} if roots is None else roots)

    def assert_code(self, code, *args, **kwargs):
        with self.assertRaises(sm.MetadataError) as raised:
            self.parse(*args, **kwargs)
        self.assertEqual(raised.exception.code, code)
        json.dumps(raised.exception.evidence)
        return raised.exception

    def test_digest_checked_before_any_parser_or_decoder(self):
        raw = b"\xffnot utf8"
        req = request(raw)
        req["expected_response_sha256"] = "0" * 64
        with mock.patch.object(sm, "_headers", side_effect=AssertionError("parser called")):
            self.assert_code("metadata_digest_mismatch", raw, req)

    def test_verified_digest_does_not_authorize_malformed_bytes(self):
        self.assert_code("metadata_invalid_utf8", b"\xff")

    def test_oversize_and_invalid_caps(self):
        self.assert_code("metadata_oversized", b"x" * 262145)
        for cap in (True, 0, 262145, "262144"):
            raw = body()
            req = request(raw)
            req["max_response_bytes"] = cap
            self.assert_code("metadata_cap_invalid", raw, req)

    def test_bad_digest_format_and_bytes_type(self):
        raw = body()
        req = request(raw)
        req["expected_response_sha256"] = "G" * 64
        self.assert_code("metadata_digest_invalid", raw, req)
        self.assert_code("metadata_bytes_required", bytearray(raw), request(raw))

    def test_identity_and_frozen_python_binding(self):
        good = body()
        self.assert_code("metadata_name_mismatch", body(name="other"), request(body(name="other")))
        self.assert_code("metadata_version_mismatch", body(version="1.2"), request(body(version="1.2")))
        self.assert_code("metadata_requires_python_mismatch", body(python=">=3.9"))
        incompatible = body(python=">=3.13")
        self.assert_code("metadata_python_incompatible", incompatible, request(incompatible, python=">=3.13"))
        parsed = self.parse(good)
        self.assertTrue(parsed["digest_verified_before_parse"])
        self.assertFalse(parsed["install_selection_approved"])
        self.assertFalse(parsed["dependency_closure_complete"])

    def test_canonical_name_and_exact_version(self):
        raw = body(name="Typing_Extensions", version="4.16.0")
        parsed = self.parse(raw, request(raw, name="typing-extensions", version="4.16.0"))
        self.assertEqual(parsed["name"], "typing-extensions")
        self.assert_code("metadata_version_mismatch", raw,
                         request(raw, name="typing-extensions", version="4.16"))

    def test_constraint_order_normalized_but_not_relaxed(self):
        raw = body(python=">=3.10, !=3.14.1")
        self.parse(raw, request(raw, python="!=3.14.1,>=3.10"))
        self.assert_code("metadata_requires_python_mismatch", raw, request(raw, python=">=3.10"))

    def test_missing_empty_and_duplicate_singletons_rejected(self):
        for field in ("Metadata-Version", "Name", "Version", "Requires-Python", "Summary"):
            if field == "Summary":
                raw = body(extra="Summary: one\nSummary: two")
            else:
                raw = body(extra=field + ": duplicate")
            self.assert_code("metadata_duplicate_singleton", raw)
        self.assert_code("metadata_required_field", body().replace(b"Requires-Python: >=3.10\n", b""))
        self.assert_code("metadata_required_field", body(python=""))
        self.assert_code("metadata_version_unsupported", body().replace(b"2.4", b"9.9"))

    def test_header_syntax_and_control_fail_closed(self):
        for raw, code in [
            (body(extra="not a header"), "metadata_malformed_header"),
            (b" continuation\n" + body(), "metadata_orphan_continuation"),
            (body(extra="X-Weird: a\x00b"), "metadata_header_control"),
            (body().replace(b"Name:", b"Na me:"), "metadata_malformed_header"),
            (body().replace(b"Name:", b"\rName:"), "metadata_bare_cr"),
            (b"\xef\xbb\xbf" + body(), "metadata_bom_rejected"),
        ]:
            with self.subTest(code=code):
                self.assert_code(code, raw)

    def test_folding_crlf_and_body_remain_data(self):
        raw = body(["child>=1; python_version >=\n  '3.10'"])
        raw = raw.replace(b"\n", b"\r\n") + b"Name: forged\r\n"
        result = self.parse(raw)
        self.assertEqual(result["name"], "sample")
        self.assertEqual(result["edges"][0]["activity"], "active")

    def test_dynamic_wheel_declarations_preserved_without_erasing_fields(self):
        result = self.parse(body(["child>=1"], extra="Dynamic: Requires-Dist\nDynamic: license-file"))
        self.assertEqual(result["dynamic_fields"], ["Requires-Dist", "license-file"])
        self.assertEqual(result["edges"][0]["specifier"], ">=1")
        self.assert_code("metadata_invalid_dynamic", body(extra="Dynamic: bad value"))

    def test_deeply_nested_and_undefined_markers_fail_closed(self):
        deep = "child; " + "(" * 1000 + "extra == 'test'" + ")" * 1000
        self.assert_code("metadata_invalid_requires_dist", body([deep]))
        self.assert_code("metadata_marker_evaluation_failed", body(["child; os_name ~= 'posix'"]))

    def test_only_lf_or_crlf_are_header_line_boundaries(self):
        raw = body().replace(b"Name: sample", "Name: sample\u2028Version: forged".encode())
        self.assert_code("metadata_identity_or_constraint_invalid", raw)

    def test_invalid_and_empty_dependencies_rejected(self):
        for value in ("", "child => 2", "child; unknown_marker == 'yes'", "child; python_version >>> '3'"):
            expected = "metadata_empty_requires_dist" if not value else "metadata_invalid_requires_dist"
            self.assert_code(expected, body([value]))

    def test_all_edges_validated_even_inactive(self):
        self.assert_code("metadata_invalid_requires_dist", body(["ok; extra == 'test'", "broken >==2"]))

    def test_active_inactive_and_no_extras_edges_preserved(self):
        raw = body(["linuxchild>=1; sys_platform == 'linux'",
                    "windowschild>=1; sys_platform == 'win32'",
                    "testchild; extra == 'test'", "other[feature]>=2"])
        result = self.parse(raw)
        self.assertEqual([e["activity"] for e in result["edges"]],
                         ["active", "inactive", "inactive", "active"])
        self.assertEqual(result["edges"][3]["requested_extras"], ["feature"])
        self.assertEqual([c["name"] for c in result["unresolved_children"]], ["linuxchild", "other"])
        self.assertIn("child_extras_closure_not_reviewed", result["unresolved_children"][1]["reasons"])
        self.assertEqual(result["edges"][0]["raw"], "linuxchild>=1; sys_platform == 'linux'")

    def test_complete_target_prevents_host_fallback(self):
        with mock.patch("packaging.markers.default_environment", return_value={"sys_platform": "win32"}):
            result = self.parse(body(["child; sys_platform == 'linux'"]))
        self.assertEqual(result["edges"][0]["activity"], "active")
        target = copy.deepcopy(TARGET)
        del target["sys_platform"]
        self.assert_code("metadata_target_incomplete", target=target)
        target = dict(TARGET, extra="test")
        self.assert_code("metadata_extras_scope_rejected", target=target)
        target = dict(TARGET, python_full_version="3.12.14")
        self.assert_code("metadata_target_python_mismatch", target=target)

    def test_empty_platform_evidence_is_unresolved_never_host_fallback(self):
        result = self.parse(body(["child; platform_release >= '5'",
                                  "other; platform_version == 'elsewhere'"]))
        self.assertEqual([e["activity"] for e in result["edges"]], ["unresolved", "unresolved"])
        self.assertEqual(result["edges"][0]["target_values_unresolved"], ["platform_release"])
        self.assertFalse(result["dependency_closure_complete"])

    def test_new_set_marker_variables_rejected(self):
        from packaging.requirements import Requirement, InvalidRequirement

        dependency = "child; 'test' in dependency_groups"
        # Probe the installed parser; a version string is not a capability test.
        try:
            parsed = Requirement(dependency)
        except InvalidRequirement:
            parser_accepts = False
            expected = "metadata_invalid_requires_dist"
        else:
            self.assertIsNotNone(parsed.marker)
            parser_accepts = True
            expected = "marker_variable_unsupported"

        no_result = object()
        result = no_result
        with mock.patch.object(sm, "_marker_variables",
                               wraps=sm._marker_variables) as validation:
            with self.assertRaises(sm.MetadataError) as raised:
                result = self.parse(body([dependency]))
        self.assertIs(result, no_result, "rejected metadata must not return a result")
        self.assertEqual(raised.exception.code, expected)
        json.dumps(raised.exception.evidence)
        if parser_accepts:
            validation.assert_called_once()
        else:
            validation.assert_not_called()

    def test_unsupported_variables_rejected_at_marker_validation_layer(self):
        from packaging.markers import Marker

        for variable in ("dependency_groups", "extras", "unknown_future_variable"):
            with self.subTest(variable=variable):
                # Synthetic AST injection bypasses only parser syntax admission.
                # Use the installed parser's token types; run the real validator.
                marker = Marker("extra == 'test'")
                left, operator, right = marker._markers[0]
                marker._markers[0] = (type(left)(variable), operator, right)
                no_result = object()
                result = no_result
                with mock.patch.object(Marker, "evaluate",
                                       side_effect=AssertionError("marker evaluated")) as evaluate:
                    with self.assertRaises(sm.MetadataError) as raised:
                        result = sm._marker_variables(marker)
                self.assertEqual(raised.exception.code, "marker_variable_unsupported")
                self.assertIs(result, no_result)
                evaluate.assert_not_called()

    def test_known_nominee_version_and_root_checks(self):
        result = self.parse(body(["child>=2,<3"]), known={"child": "2.5"}, roots={"child": ">=2.1"})
        self.assertEqual(result["edges"][0]["constraint_status"], "known_nominee_satisfies")
        self.assertEqual(result["unresolved_children"][0]["reasons"], ["child_metadata_not_bound"])
        error = self.assert_code("known_version_conflict", body(["child>=2"]), known={"child": "1"})
        self.assertEqual(error.evidence["edges"][0]["constraint_status"], "known_version_conflict")
        self.assert_code("known_version_conflict", body(["child>=2"]), known={"child": "2"}, roots={"child": "<2"})
        self.assert_code("known_version_conflict", known={"sample": "1.2"})
        self.assert_code("root_constraint_conflict", roots={"sample": ">=2"})

    def test_inactive_child_constraint_does_not_conflict(self):
        result = self.parse(body(["child>=2; extra == 'test'"]), known={"child": "1"})
        self.assertEqual(result["edges"][0]["constraint_status"], "inactive_not_applied")
        self.assertEqual(result["unresolved_children"], [])

    def test_exact_intersection_witness_is_not_child_closure(self):
        result = self.parse(body(["child==2.0"]), roots={"child": ">=1,<3"})
        self.assertEqual(result["edges"][0]["constraint_status"], "exact_constraint_witness_only")
        self.assertTrue(result["unresolved_children"])
        self.assert_code("root_constraint_conflict", body(["child==2.0"]), roots={"child": "<2"})
        self.assert_code("root_constraint_conflict", body(["child>=3"]), roots={"child": "<2"})
        self.assert_code("root_constraint_conflict", body(["child>=2"]), roots={"child": "<2"})

    def test_nontrivial_intersection_is_explicitly_unresolved(self):
        result = self.parse(body(["child>=1,!=2.*"]), roots={"child": "~=1.2"})
        self.assertEqual(result["edges"][0]["constraint_status"], "intersection_unresolved")
        self.assertFalse(result["dependency_closure_complete"])

    def test_repeated_active_edges_are_conjoined(self):
        error = self.assert_code("root_constraint_conflict", body(["child>=2", "child<2"]))
        self.assertEqual(len(error.evidence["metadata"]["edges"]), 2)
        self.assertEqual(error.evidence["conjunction"]["children"][0]["constraint_status"],
                         "root_constraint_conflict")
        self.assert_code("root_constraint_conflict", body(["child==1", "child==2"]))

    def test_cross_response_active_constraints_conjoined(self):
        first = self.parse(body(["child>=2"]))
        second_raw = body(["child<2"], name="second")
        second = self.parse(second_raw, request(second_raw, name="second"))
        with self.assertRaises(sm.MetadataError) as raised:
            sm.check_collection_constraints([first, second], {}, {}, TARGET)
        self.assertEqual(raised.exception.code, "root_constraint_conflict")
        self.assertEqual(len(raised.exception.evidence["children"][0]["active_edges"]), 2)

    def test_collection_known_version_intersection_and_inactive_scope(self):
        first = self.parse(body(["child>=2", "child<1; extra == 'test'"]))
        second_raw = body(["child<3"], name="second")
        second = self.parse(second_raw, request(second_raw, name="second"))
        summary = sm.check_collection_constraints([first, second], {"child": ">=2.1"}, {"child": "2.5"}, TARGET)
        child = summary["children"][0]
        self.assertEqual(child["constraint_status"], "known_nominee_satisfies")
        self.assertEqual(len(child["active_edges"]), 2)
        self.assertEqual(len(child["inactive_edges"]), 1)
        self.assertFalse(summary["dependency_closure_complete"])

    def test_collection_unresolved_marker_and_direct_url_cannot_close(self):
        result = self.parse(body(["child>=2; platform_release >= '5'",
                                  "other @ https://example.invalid/other.whl"]))
        summary = sm.check_collection_constraints([result], {}, {}, TARGET)
        self.assertTrue(all(child["unresolved_requirements_present"] for child in summary["children"]))
        self.assertTrue(all(child["constraint_status"] == "unresolved" for child in summary["children"]))

    def test_self_cycle_is_explicit_and_never_traversed(self):
        result = self.parse(body(["sample>=1"]), known={"sample": "1.2.0"})
        self.assertTrue(result["edges"][0]["self_cycle"])
        self.assertIn("self_cycle_requires_graph_review", result["unresolved_children"][0]["reasons"])
        self.assertFalse(result["edges"][0]["child_metadata_closed"])

    def test_collection_rejects_mixed_target_or_unverified_results(self):
        result = self.parse(body(["child>=1"]))
        altered = copy.deepcopy(result)
        altered["frozen_target"]["platform_machine"] = "arm64"
        for results in ([altered], [dict(result, digest_verified_before_parse=False)], [result] * 8):
            with self.assertRaises(sm.MetadataError) as raised:
                sm.check_collection_constraints(results, {}, {}, TARGET)
            self.assertEqual(raised.exception.code, "collection_results_invalid")

    def test_direct_url_is_data_and_never_an_authorized_request(self):
        result = self.parse(body(["child @ https://example.invalid/private.whl"]))
        edge = result["edges"][0]
        self.assertEqual(edge["url"], "https://example.invalid/private.whl")
        self.assertEqual(edge["constraint_status"], "direct_url_not_authorized")
        self.assertFalse(result["automatic_recursion"])
        self.assertIn("direct_url_not_authorized", result["unresolved_children"][0]["reasons"])

    def test_header_and_dependency_counts_bounded(self):
        self.assert_code("metadata_field_oversized", body(extra="Summary: " + "a" * 8193))
        self.assert_code("metadata_too_many_dependencies", body(["child"] * 257))
        raw = body(extra="\n".join("Classifier: " + "a" * 150 for _ in range(450)))
        self.assert_code("metadata_headers_oversized", raw)

    def test_production_proposal_not_mutated_or_fetched(self):
        # Fixtures are synthetic bytes; request hashes bind only those bytes.
        raw = body(["child>=1"])
        req = request(raw)
        before = json.dumps(req, sort_keys=True)
        self.parse(raw, req)
        self.assertEqual(json.dumps(req, sort_keys=True), before)


if __name__ == "__main__":
    unittest.main()
