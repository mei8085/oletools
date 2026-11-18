"""
Tests for embedded-object risk grading and high-risk CLSID identification.

These tests cover the three required observable outcomes:
  1. legitimate objects get an explainable, low-risk verdict;
  2. high-risk CLSIDs are located precisely with reasons;
  3. corrupted/malformed objects are never reported as safe.

They also pin the structural guarantees: mixed-case normalization, repeated
CLSID determinism, malformed/unknown handling, and the rule that CLSID string
similarity is never treated as evidence.
"""

import unittest

from oletools.common import clsid


# A few canonical CLSIDs used across tests, selected from KNOWN_CLSIDS so the
# curated tables stay internally consistent.
CLSID_HIGH_SHELL_EXPLORER = 'EAB22AC3-30C1-11CF-A7EB-0000C05BAE0B'   # CVE-2026-21509
CLSID_HIGH_URL_MONIKER = '79EAC9E0-BAF9-11CE-8C82-00AA004BA90B'
CLSID_HIGH_VBSCRIPT = 'B54F3741-5B07-11CF-A4B0-00AA004A55E8'
CLSID_MEDIUM_PACKAGE = '00020C01-0000-0000-C000-000000000046'
CLSID_MEDIUM_LNK = '00021401-0000-0000-C000-000000000046'
CLSID_BENIGN_WORD = '00020906-0000-0000-C000-000000000046'
CLSID_BENIGN_PDF = 'B801CA65-A1FC-11D0-85AD-444553540000'
# Well-formed but deliberately absent from every table.
CLSID_UNKNOWN = '12345678-1234-1234-1234-123456789ABC'


class TestRiskTableStructure(unittest.TestCase):
    """The curated tables must be structurally sound and self-consistent."""

    def test_tables_reference_valid_known_canonical_clsids(self):
        # Importing clsid already runs _validate_risk_tables(); re-check the
        # invariants explicitly so regressions are localized here.
        for table in (clsid.HIGH_RISK_CLSIDS, clsid.MEDIUM_RISK_CLSIDS):
            for key, (category, reason) in table.items():
                self.assertEqual(key, clsid.parse_clsid(key))
                self.assertIn(key, clsid.KNOWN_CLSIDS)
                self.assertTrue(category)
                self.assertTrue(reason)

    def test_high_and_medium_tables_are_disjoint(self):
        self.assertFalse(
            set(clsid.HIGH_RISK_CLSIDS) & set(clsid.MEDIUM_RISK_CLSIDS))

    def test_known_clsids_remain_uppercase_canonical(self):
        for key in clsid.KNOWN_CLSIDS:
            self.assertEqual(key, key.upper())
            # every known key must parse strictly:
            self.assertEqual(key, clsid.parse_clsid(key))


class TestParseClsid(unittest.TestCase):
    """Strict parsing and normalization."""

    def test_uppercase_canonical_roundtrip(self):
        self.assertEqual(
            clsid.parse_clsid(CLSID_HIGH_SHELL_EXPLORER),
            CLSID_HIGH_SHELL_EXPLORER)

    def test_mixed_case_normalizes_to_uppercase(self):
        lower = CLSID_HIGH_SHELL_EXPLORER.lower()
        self.assertEqual(clsid.parse_clsid(lower), CLSID_HIGH_SHELL_EXPLORER)

    def test_braced_and_padded_forms_normalize(self):
        braced = '{%s}' % CLSID_BENIGN_WORD
        padded = '  %s  ' % CLSID_BENIGN_WORD.lower()
        self.assertEqual(clsid.parse_clsid(braced), CLSID_BENIGN_WORD)
        self.assertEqual(clsid.parse_clsid(padded), CLSID_BENIGN_WORD)

    def test_bytes_accepted(self):
        self.assertEqual(
            clsid.parse_clsid(CLSID_HIGH_URL_MONIKER.encode()),
            CLSID_HIGH_URL_MONIKER)

    def test_malformed_values_raise(self):
        for bad in (None, '', '   ', 'not-a-clsid',
                    '{00020906-0000}',                       # truncated, braced
                    '0002090600000000C000000000000046',      # missing dashes
                    'G0020906-0000-0000-C000-000000000046',  # non-hex char
                    '{00020906-0000-0000-C000-000000000046', # unclosed brace
                    12345,                                   # not a string
                    b'\xff\xfe-bad'):
            with self.assertRaises(clsid.MalformedClsidError):
                clsid.parse_clsid(bad)


class TestLookupClsid(unittest.TestCase):
    """Non-raising lookup: malformed input is explainable, never 'safe'."""

    def test_high_risk_clsid_located(self):
        for value in (CLSID_HIGH_SHELL_EXPLORER,
                      CLSID_HIGH_SHELL_EXPLORER.lower(),
                      '{%s}' % CLSID_HIGH_SHELL_EXPLORER):
            result = clsid.lookup_clsid(value)
            self.assertTrue(result.valid)
            self.assertEqual(result.clsid, CLSID_HIGH_SHELL_EXPLORER)
            self.assertEqual(result.risk, clsid.RISK_HIGH)
            self.assertEqual(result.confidence, clsid.CONFIDENCE_HIGH)
            self.assertTrue(result.reason)
            self.assertEqual(result.category,
                             clsid.CATEGORY_EXPLOITED_CONTROL)

    def test_medium_risk_clsid(self):
        result = clsid.lookup_clsid(CLSID_MEDIUM_PACKAGE)
        self.assertEqual(result.risk, clsid.RISK_MEDIUM)
        self.assertEqual(result.confidence, clsid.CONFIDENCE_HIGH)
        self.assertEqual(result.category, clsid.CATEGORY_PACKAGE_LNK)

    def test_known_benign_clsid_is_low_high_confidence(self):
        result = clsid.lookup_clsid(CLSID_BENIGN_WORD)
        self.assertTrue(result.known)
        self.assertEqual(result.risk, clsid.RISK_LOW)
        self.assertEqual(result.confidence, clsid.CONFIDENCE_HIGH)
        self.assertIn('benign', result.reason)

    def test_well_formed_unknown_clsid_is_low_confidence_unclassified(self):
        result = clsid.lookup_clsid(CLSID_UNKNOWN)
        self.assertTrue(result.valid)
        self.assertFalse(result.known)
        # explicitly NOT safe:
        self.assertEqual(result.risk, clsid.RISK_UNKNOWN)
        self.assertEqual(result.confidence, clsid.CONFIDENCE_LOW)
        self.assertIsNone(result.category)

    def test_malformed_clsid_is_invalid_low_confidence_with_error(self):
        for bad in ('', 'garbage', 'zzzzzzzz-zzzz-zzzz-zzzz-zzzzzzzzzzzz'):
            result = clsid.lookup_clsid(bad)
            self.assertFalse(result.valid)
            self.assertIsNone(result.clsid)
            self.assertEqual(result.risk, clsid.RISK_UNKNOWN)
            self.assertEqual(result.confidence, clsid.CONFIDENCE_LOW)
            self.assertTrue(result.error)
            self.assertIn('not be treated as safe', result.reason)

    def test_none_clsid_reports_absence_without_raising(self):
        result = clsid.lookup_clsid(None)
        self.assertFalse(result.valid)
        self.assertEqual(result.risk, clsid.RISK_UNKNOWN)
        self.assertTrue(result.error)

    def test_similarity_is_not_evidence(self):
        # One hex digit different from a HIGH-risk CLSID must stay unknown:
        near_match = 'EAB22AC4-30C1-11CF-A7EB-0000C05BAE0B'
        self.assertNotEqual(near_match, CLSID_HIGH_SHELL_EXPLORER)
        result = clsid.lookup_clsid(near_match)
        self.assertTrue(result.valid)
        self.assertEqual(result.risk, clsid.RISK_UNKNOWN)
        self.assertEqual(result.confidence, clsid.CONFIDENCE_LOW)

    def test_mixed_case_and_repeated_lookups_are_stable(self):
        variants = (CLSID_HIGH_URL_MONIKER,
                    CLSID_HIGH_URL_MONIKER.lower(),
                    '{%s}' % CLSID_HIGH_URL_MONIKER,
                    ' %s ' % CLSID_HIGH_URL_MONIKER)
        canonical = []
        for value in variants:
            result = clsid.lookup_clsid(value)
            canonical.append((result.clsid, result.risk, result.confidence,
                              result.category, result.reason))
        self.assertEqual(len(set(canonical)), 1)
        # repeated lookups are deterministic and equal:
        again = clsid.lookup_clsid(CLSID_HIGH_URL_MONIKER).as_dict()
        self.assertEqual(again,
                         clsid.lookup_clsid(CLSID_HIGH_URL_MONIKER).as_dict())

    def test_source_is_recorded(self):
        result = clsid.lookup_clsid(
            CLSID_HIGH_VBSCRIPT,
            source=clsid.CLSID_SOURCE_OLE_STORAGE)
        self.assertEqual(result.source,
                         clsid.CLSID_SOURCE_OLE_STORAGE)


class TestSuspiciousIndicators(unittest.TestCase):
    """Exact word-boundary indicator matching."""

    def test_commands_and_scripts_detected(self):
        data = b'run powershell.exe -enc QQ== and cmd /c mshta http://x/a.sct'
        findings = clsid.find_suspicious_indicators(data)
        ids = {item['id'] for item in findings}
        self.assertIn('powershell_exec', ids)
        self.assertIn('encoded_command', ids)
        self.assertIn('cmd_exec', ids)
        self.assertIn('mshta_exec', ids)
        self.assertIn('script_sct', ids)
        for item in findings:
            self.assertIn('offset', item)
            self.assertTrue(item['reason'])

    def test_word_boundary_avoids_false_positives(self):
        # 'cmd' inside another word and an unrelated extension must not match:
        ids = {item['id'] for item in
               clsid.find_suspicious_indicators(b'cmdxyz tool abc.jsx file')}
        self.assertNotIn('cmd_exec', ids)
        self.assertNotIn('script_js', ids)

    def test_benign_content_has_no_indicators(self):
        self.assertEqual(
            clsid.find_suspicious_indicators(
                b'quarterly report, figures 12345 and normal text'), ())

    def test_none_and_unicode_handling(self):
        self.assertEqual(clsid.find_suspicious_indicators(None), ())
        findings = clsid.find_suspicious_indicators(u'Powershell -Enc AA')
        self.assertTrue(findings)

    def test_indicators_never_trigger_high_on_their_own(self):
        assessment = clsid.assess_embedded_object(
            clsid=CLSID_BENIGN_WORD,
            object_type=clsid.OBJECT_TYPE_EMBEDDED,
            indicators_data=b'powershell -enc AA')
        self.assertEqual(assessment.risk, clsid.RISK_MEDIUM)
        self.assertTrue(assessment.indicators)


class TestAssessEmbeddedObject(unittest.TestCase):
    """Combined grading across object type, CLSID and indicators."""

    # --- outcome 1: legitimate object explainable --------------------------
    def test_legit_embedded_known_benign_clsid(self):
        assessment = clsid.assess_embedded_object(
            clsid=CLSID_BENIGN_PDF,
            object_type=clsid.OBJECT_TYPE_EMBEDDED)
        self.assertEqual(assessment.risk, clsid.RISK_LOW)
        self.assertEqual(assessment.confidence, clsid.CONFIDENCE_HIGH)
        self.assertTrue(any('benign' in r for r in assessment.reasons))
        self.assertEqual(assessment.object_type,
                         clsid.OBJECT_TYPE_EMBEDDED)

    def test_legit_object_serializes_to_dict(self):
        assessment = clsid.assess_embedded_object(
            clsid=CLSID_BENIGN_WORD,
            object_type=clsid.OBJECT_TYPE_EMBEDDED)
        serialized = assessment.as_dict()
        self.assertEqual(serialized['risk'], clsid.RISK_LOW)
        self.assertEqual(serialized['clsid']['clsid'], CLSID_BENIGN_WORD)
        self.assertEqual(serialized['indicators'], [])
        self.assertTrue(serialized['reasons'])

    # --- outcome 2: high-risk CLSID locatable ------------------------------
    def test_high_risk_clsid_dominates_other_evidence(self):
        assessment = clsid.assess_embedded_object(
            clsid=CLSID_HIGH_SHELL_EXPLORER.lower(),  # mixed case on purpose
            object_type=clsid.OBJECT_TYPE_LINKED,
            indicators_data=b'benign looking payload')
        self.assertEqual(assessment.risk, clsid.RISK_HIGH)
        self.assertEqual(assessment.confidence, clsid.CONFIDENCE_HIGH)
        self.assertEqual(assessment.clsid, CLSID_HIGH_SHELL_EXPLORER)
        self.assertTrue(any('CVE-2026-21509' in r for r
                            in assessment.reasons))

    def test_high_risk_class_name_ole2link(self):
        assessment = clsid.assess_embedded_object(
            class_name=b'OLE2Link',
            object_type=clsid.OBJECT_TYPE_EMBEDDED,
            indicators_data=b'http://example.com')
        self.assertEqual(assessment.risk, clsid.RISK_HIGH)
        self.assertEqual(assessment.confidence, clsid.CONFIDENCE_MEDIUM)

    def test_equation_prefix_rule_is_explicit(self):
        assessment = clsid.assess_embedded_object(
            class_name='Equation.3',
            object_type=clsid.OBJECT_TYPE_EMBEDDED)
        self.assertEqual(assessment.risk, clsid.RISK_HIGH)
        # an unrelated class name must not benefit from the prefix:
        other = clsid.assess_embedded_object(
            class_name='MyEquation.3000',
            object_type=clsid.OBJECT_TYPE_EMBEDDED)
        self.assertNotEqual(other.risk, clsid.RISK_HIGH)

    # --- outcome 3: corrupted objects never safe ---------------------------
    def test_malformed_object_type_never_low(self):
        assessment = clsid.assess_embedded_object(
            clsid='broken-clsid',
            object_type=clsid.OBJECT_TYPE_MALFORMED)
        self.assertIn(assessment.risk,
                      (clsid.RISK_UNKNOWN, clsid.RISK_MEDIUM,
                       clsid.RISK_HIGH))
        self.assertNotEqual(assessment.risk, clsid.RISK_LOW)
        self.assertEqual(assessment.confidence, clsid.CONFIDENCE_LOW)
        self.assertTrue(assessment.clsid_assessment.error)

    def test_malformed_clsid_in_otherwise_embedded_object_not_safe(self):
        assessment = clsid.assess_embedded_object(
            clsid='{bad',
            object_type=clsid.OBJECT_TYPE_EMBEDDED)
        self.assertNotEqual(assessment.risk, clsid.RISK_LOW)
        self.assertEqual(assessment.confidence, clsid.CONFIDENCE_LOW)

    def test_unknown_clsid_stays_unclassified_not_safe(self):
        assessment = clsid.assess_embedded_object(
            clsid=CLSID_UNKNOWN,
            object_type=clsid.OBJECT_TYPE_EMBEDDED)
        self.assertEqual(assessment.risk, clsid.RISK_UNKNOWN)
        self.assertEqual(assessment.confidence, clsid.CONFIDENCE_LOW)

    def test_malformed_object_with_high_risk_class_keeps_high(self):
        # even on a malformed container, an exact high-risk class rule remains
        # visible (and gains the malformed warning), rather than being hidden:
        assessment = clsid.assess_embedded_object(
            class_name='OLE2Link',
            object_type=clsid.OBJECT_TYPE_MALFORMED)
        self.assertEqual(assessment.risk, clsid.RISK_HIGH)
        self.assertTrue(any('not a well-formed OLE object' in r
                            for r in assessment.reasons))

    # --- type-driven grading ------------------------------------------------
    def test_package_type_is_at_least_medium(self):
        assessment = clsid.assess_embedded_object(
            class_name='Package',
            object_type=clsid.OBJECT_TYPE_PACKAGE)
        self.assertEqual(assessment.risk, clsid.RISK_MEDIUM)

    def test_linked_type_is_at_least_medium(self):
        assessment = clsid.assess_embedded_object(
            clsid=CLSID_BENIGN_WORD,
            object_type=clsid.OBJECT_TYPE_LINKED)
        self.assertEqual(assessment.risk, clsid.RISK_MEDIUM)

    def test_lnk_clsid_medium(self):
        assessment = clsid.assess_embedded_object(
            clsid=CLSID_MEDIUM_LNK,
            object_type=clsid.OBJECT_TYPE_EMBEDDED)
        self.assertEqual(assessment.risk, clsid.RISK_MEDIUM)

    def test_invalid_object_type_raises(self):
        with self.assertRaises(ValueError):
            clsid.assess_embedded_object(object_type='not-a-type')

    def test_determinism_across_repeated_calls(self):
        kwargs = dict(clsid=CLSID_HIGH_VBSCRIPT,
                      class_name='something',
                      object_type=clsid.OBJECT_TYPE_EMBEDDED,
                      indicators_data=b'wscript.shell createobject("x")')
        first = clsid.assess_embedded_object(**kwargs).as_dict()
        for _ in range(4):
            self.assertEqual(
                first, clsid.assess_embedded_object(**kwargs).as_dict())


if __name__ == '__main__':
    unittest.main()
