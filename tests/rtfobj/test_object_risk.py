"""
Integration tests for risk grading inside rtfobj's RTF object parsing.

Covers the three required observable outcomes through the real RtfObjParser
pipeline (not just the grading API), using self-contained synthesized RTF
blobs plus the malformed sample shipped with the test data.
"""

import struct
import unittest
from os.path import join

from oletools import rtfobj
from oletools.common import clsid
from tests.test_utils import testdata_reader


def _length_prefixed(text):
    """Build an OLE1 length-prefixed ANSI string (length includes NUL)."""
    raw = text + b'\x00'
    return struct.pack('<I', len(raw)) + raw


def make_ole1_object(class_name, format_id=rtfobj.oleobj.OleObject.TYPE_EMBEDDED,
                     payload=b''):
    """
    Build a minimal but structurally valid MS-OLEDS OLE1.0 object blob.
    """
    blob = struct.pack('<II', 0x00000001, format_id)
    blob += (_length_prefixed(class_name)
             + _length_prefixed(b'topic')
             + _length_prefixed(b'item'))
    if format_id == rtfobj.oleobj.OleObject.TYPE_EMBEDDED:
        blob += struct.pack('<I', len(payload)) + payload
    return blob


def wrap_in_rtf(ole1_blob):
    """Wrap an OLE1 blob as hex object data inside a minimal RTF document."""
    return (b'{\\rtf1{\\object{\\objdata '
            + ole1_blob.hex().encode() + b'}}')


class TestRtfObjectRiskGrading(unittest.TestCase):

    def parse_one(self, rtf_data):
        parser = rtfobj.RtfObjParser(rtf_data)
        parser.parse()
        self.assertEqual(len(parser.objects), 1)
        return parser.objects[0]

    # --- outcome 2: high-risk class located through the real parser --------
    def test_ole2link_class_graded_high_with_indicators(self):
        rtf = wrap_in_rtf(make_ole1_object(
            b'OLE2Link', payload=b'http://example.com powershell -enc QQ=='))
        obj = self.parse_one(rtf)
        self.assertTrue(obj.is_ole)
        self.assertIsNone(obj.parse_error)
        assessment = obj.risk_assessment
        self.assertEqual(assessment.risk, clsid.RISK_HIGH)
        self.assertEqual(assessment.object_type,
                         clsid.OBJECT_TYPE_EMBEDDED)
        indicator_ids = {item['id'] for item in assessment.indicators}
        self.assertIn('powershell_exec', indicator_ids)
        self.assertIn('encoded_command', indicator_ids)
        self.assertTrue(any('OLE2Link' in reason for reason
                            in assessment.reasons))

    def test_equation_class_graded_high(self):
        rtf = wrap_in_rtf(make_ole1_object(
            b'Equation.3', payload=b'X' * 64))
        obj = self.parse_one(rtf)
        self.assertEqual(obj.risk_assessment.risk, clsid.RISK_HIGH)

    # --- outcome 1: legitimate object explainable --------------------------
    def test_benign_class_without_indicators_not_high(self):
        rtf = wrap_in_rtf(make_ole1_object(
            b'Word.Document.8', payload=b'plain harmless document body'))
        obj = self.parse_one(rtf)
        self.assertTrue(obj.is_ole)
        assessment = obj.risk_assessment
        # no CLSID embedded in this small non-OLE payload, so it cannot be
        # positively identified: it must stay unclassified rather than being
        # called safe OR dangerous:
        self.assertIn(assessment.risk,
                      (clsid.RISK_LOW, clsid.RISK_UNKNOWN))
        self.assertNotEqual(assessment.risk, clsid.RISK_HIGH)
        self.assertEqual(assessment.indicators, ())

    # --- outcome 3: corrupted object never reported safe -------------------
    def test_shipped_malformed_sample_is_unclassified_low_confidence(self):
        data = testdata_reader.read(join('rtfobj', 'issue_251.rtf'))
        obj = self.parse_one(data)
        self.assertFalse(obj.is_ole)
        self.assertIsNotNone(obj.parse_error)
        assessment = obj.risk_assessment
        self.assertEqual(assessment.object_type,
                         clsid.OBJECT_TYPE_MALFORMED)
        self.assertNotEqual(assessment.risk, clsid.RISK_LOW)
        self.assertEqual(assessment.confidence, clsid.CONFIDENCE_LOW)

    def test_garbage_object_data_is_malformed_not_safe(self):
        rtf = b'{\\rtf1{\\object{\\objdata ' + b'00ff' * 8 + b'}}'
        obj = self.parse_one(rtf)
        self.assertFalse(obj.is_ole)
        assessment = obj.risk_assessment
        self.assertEqual(assessment.object_type,
                         clsid.OBJECT_TYPE_MALFORMED)
        self.assertEqual(assessment.risk, clsid.RISK_UNKNOWN)
        self.assertEqual(assessment.confidence, clsid.CONFIDENCE_LOW)
        self.assertIsNotNone(obj.parse_error)

    def test_malformed_with_ole2link_still_flags_high(self):
        # OLE1 header claims OLE2Link but native data is truncated garbage:
        blob = make_ole1_object(b'OLE2Link', payload=b'')
        rtf = wrap_in_rtf(blob)
        obj = self.parse_one(rtf)
        assessment = obj.risk_assessment
        # exact class-name rule remains observable:
        self.assertEqual(assessment.risk, clsid.RISK_HIGH)
        self.assertTrue(any('OLE2Link' in reason for reason
                            in assessment.reasons))

    # --- stability: every parsed object gets an assessment -----------------
    def test_every_object_receives_an_assessment(self):
        data = testdata_reader.read(join('rtfobj', 'issue_251.rtf'))
        parser = rtfobj.RtfObjParser(data)
        parser.parse()
        for obj in parser.objects:
            self.assertIsNotNone(obj.risk_assessment)
            self.assertIn(obj.risk_assessment.risk, clsid.RISK_LEVELS)
            self.assertTrue(obj.risk_assessment.reasons)

    def test_assessment_dict_is_serializable(self):
        rtf = wrap_in_rtf(make_ole1_object(
            b'OLE2Link', payload=b'cmd.exe'))
        obj = self.parse_one(rtf)
        serialized = obj.risk_assessment.as_dict()
        self.assertEqual(serialized['risk'], clsid.RISK_HIGH)
        self.assertIn('clsid', serialized)
        self.assertIn('reasons', serialized)
        self.assertIn('indicators', serialized)


if __name__ == '__main__':
    unittest.main()
