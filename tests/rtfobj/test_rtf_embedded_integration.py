""" Integration tests for RTF embedded-object extraction (rtfobj)

Test data lives in tests/test-data/rtfobj/integration/. The samples were
generated locally from synthetic strings only; no Office application and no
network service is involved. Every sample is a standalone RTF document and
the manifest at the end of this file records its expected results.

The tests follow one object through the decoding layers involved in
extraction:

    layer 'rtf-hex'      RTF groups, destination control words, control words,
                         control symbols, hex digits, whitespace and \\bin data
                         (oletools.rtfobj.RtfParser / RtfObjParser)
    layer 'ole1'         OLE 1.0 object header and inner data length
                         (oletools.oleobj.OleObject)
    layer 'ole-package'  OLE Package native stream, filename and payload
                         (oletools.oleobj.OleNativeStream)

The expected results encode this contract:

* legal hex digit case and whitespace variations decode to exactly the bytes
  of the unobfuscated reference samples;
* tolerant extraction rules already documented in rtfobj/oleobj are applied
  (last nibble dropped before \\'hh when the hex count is odd, trailing odd
  nibble trimmed, \\bin without a length or with a negative length treated as
  empty) and remain distinct from complete OLE object recognition;
* truncated data is never reported as a complete payload;
* content that Word ignores (nested groups, control words inside objdata) does
  not enter the payload, and OLE or Package inner length fields do not move
  the outer RTF object boundary;
* when one object is corrupt, adjacent intact objects keep their own bytes,
  class names and Package file names, and parsing stays within the sample.

For every expected object the manifest records its original RTF boundaries.
group_start/group_end delimit the complete objdata group as found by an
independent brace scan; rtf_start/rtf_end are the positions reported by
rtfobj (the control word delimiter before the data and the closing brace);
content_start is the first encoded byte. Failure messages report the sample,
the object index, its RTF position and the parse layer in which a mismatch
was detected.
"""

import unittest
from hashlib import md5
from os.path import isfile, join
from shutil import rmtree
from tempfile import mkdtemp

from oletools import oleobj, rtfobj
from tests.test_utils import testdata_reader, call_and_capture, DATA_BASE_DIR


SAMPLE_DIR = join('rtfobj', 'integration')

#: samples sharing the reference Word object bytes
WORD_REFERENCE = 'word_plain.rtf'
#: samples sharing the reference Package payload bytes
PACKAGE_REFERENCE = 'package_plain.rtf'

LAYER_HEX = 'rtf-hex'
LAYER_OLE = 'ole1'
LAYER_PACKAGE = 'ole-package'

#: start of an objdata destination group, used for the independent scan
OBJDATA_MARKER = b'{\\*\\objdata '


def read_sample(name):
    """Read an integration sample, independent of the current directory."""
    return testdata_reader.read(join(SAMPLE_DIR, name))


def sample_path(name):
    """Absolute path of an integration sample."""
    return join(DATA_BASE_DIR, SAMPLE_DIR, name)


def digest(value):
    """md5 hexdigest of a bytes value, preserving None."""
    if value is None:
        return None
    return md5(value).hexdigest()


def size_of(value):
    """Length of a bytes value, preserving None."""
    if value is None:
        return None
    return len(value)


def scan_object_groups(data):
    """
    Independently locate objdata groups in the original RTF.

    This deliberately does not use the parser under test: it finds each
    ``{\\*\\objdata `` group by scanning braces, honouring escaped braces,
    hex escape control symbols and the byte count of ``\\bin`` blocks.
    Returns a list of (group_start, group_end) offsets.
    """
    groups = []
    index = 0
    while True:
        start = data.find(OBJDATA_MARKER, index)
        if start == -1:
            return groups
        pos = start
        depth = 0
        end = None
        while pos < len(data):
            char = data[pos:pos + 1]
            if char == b'\\':
                if is_bin_control_word(data, pos):
                    digit_start = pos + 4
                    digit_end = digit_start
                    while (digit_end < len(data)
                           and data[digit_end:digit_end + 1].isdigit()):
                        digit_end += 1
                    count = 0
                    if digit_end > digit_start:
                        count = int(data[digit_start:digit_end])
                    pos = digit_end
                    if data[pos:pos + 1] == b' ':
                        pos += 1
                    pos += max(count, 0)
                    continue
                if data[pos + 1:pos + 2] == b"'":
                    pos += 4          # \'hh: both hex chars are literal
                    continue
                pos += 2              # any other control symbol/word start
                continue
            if char == b'{':
                depth += 1
            elif char == b'}':
                depth -= 1
                if depth == 0:
                    end = pos + 1
                    break
            pos += 1
        if end is None:
            raise ValueError('unbalanced objdata group at RTF byte {0}'
                             .format(start))
        groups.append((start, end))
        index = end


def is_bin_control_word(data, pos):
    """
    Return True if the control word starting at ``pos`` is ``\\bin``.

    ``\\bin`` must be followed by a delimiter, according to the RTF
    specification; a name such as ``\\binary`` is a different control word.
    """
    if not data.startswith(b'\\bin', pos):
        return False
    following = data[pos + 4:pos + 5]
    return following == b'' or not following.isalpha()


def package_declared_size(rtf_object):
    """Payload size declared by the OLE Package native stream itself."""
    if not rtf_object.is_package:
        return None
    native = oleobj.OleNativeStream(bindata=rtf_object.oledata, package=True)
    return native.actual_size


def payload_is_complete(rtf_object):
    """
    Apply the completeness contract to a parsed object.

    Returns None when the object was not recognized as a complete OLE object
    at all, True only when the inner declared length matches the bytes that
    were actually carried, and False for truncated payloads.
    """
    if not rtf_object.is_ole:
        return None
    if rtf_object.is_package:
        declared = package_declared_size(rtf_object)
        return (declared is not None
                and declared == size_of(rtf_object.olepkgdata))
    return rtf_object.oledata_size == size_of(rtf_object.oledata)


class RtfObjIntegrationTestCase(unittest.TestCase):
    """Shared parsing, manifest checking and failure diagnostics."""

    @classmethod
    def setUpClass(cls):
        cls._parsed = {}

    def load(self, sample):
        """Parse a sample once and cache (rtf bytes, RtfObjParser)."""
        if sample not in self._parsed:
            data = read_sample(sample)
            parser = rtfobj.RtfObjParser(data)
            parser.parse()
            self._parsed[sample] = (data, parser)
        return self._parsed[sample]

    def describe(self, sample, index, layer):
        """Build a failure message with object position and parse layer."""
        _, parsed = self.load(sample)
        if index >= len(parsed.objects):
            where = ('object #{0} missing (parser returned {1} object(s))'
                     .format(index, len(parsed.objects)))
        else:
            obj = parsed.objects[index]
            where = ('object #{0} at RTF bytes 0x{1:08X}-0x{2:08X} '
                     '(content starts at 0x{3:08X})'
                     .format(index, obj.start, obj.end, obj.start + 1))
        return ('sample {0!r}: {1}, parse layer {2!r}'
                .format(sample, where, layer))

    def check(self, actual, expected, sample, index, layer, field='value'):
        """Compare one expected value, reporting position and layer."""
        if actual != expected:
            self.fail('{0}\n  field   : {1}\n  actual  : {2!r}\n'
                      '  expected: {3!r}'
                      .format(self.describe(sample, index, layer), field,
                              actual, expected))

    def object_at(self, sample, index):
        """Return a parsed object or fail with position diagnostics."""
        _, parsed = self.load(sample)
        if index >= len(parsed.objects):
            self.fail('{0}\n  expected at least {1} object(s)'
                      .format(self.describe(sample, index, LAYER_HEX),
                              index + 1))
        return parsed.objects[index]

    def check_object(self, sample, index, expected):
        """Check all manifest fields of one object, with layer diagnostics."""
        data, _ = self.load(sample)
        obj = self.object_at(sample, index)
        ole_layer = LAYER_PACKAGE if expected['is_package'] else LAYER_OLE
        checks = (
            ('rtf_start', LAYER_HEX, obj.start, expected['rtf_start']),
            ('rtf_end', LAYER_HEX, obj.end, expected['rtf_end']),
            ('content_start', LAYER_HEX, obj.start + 1,
             expected['content_start']),
            ('span_md5', LAYER_HEX,
             digest(data[obj.start:obj.end]), expected['span_md5']),
            ('raw_len', LAYER_HEX, size_of(obj.rawdata), expected['raw_len']),
            ('raw_md5', LAYER_HEX, digest(obj.rawdata), expected['raw_md5']),
            ('is_ole', LAYER_OLE, obj.is_ole, expected['is_ole']),
            ('class_name', LAYER_OLE, obj.class_name, expected['class_name']),
            ('oledata_size', LAYER_OLE, obj.oledata_size,
             expected['oledata_size']),
            ('oledata_len', ole_layer, size_of(obj.oledata),
             expected['oledata_len']),
            ('oledata_md5', ole_layer, digest(obj.oledata),
             expected['oledata_md5']),
            ('is_package', LAYER_PACKAGE, obj.is_package,
             expected['is_package']),
            ('filename', LAYER_PACKAGE, obj.filename, expected['filename']),
            ('olepkgdata_len', LAYER_PACKAGE, size_of(obj.olepkgdata),
             expected['olepkgdata_len']),
            ('olepkgdata_md5', LAYER_PACKAGE, digest(obj.olepkgdata),
             expected['olepkgdata_md5']),
            ('payload_declared_size', ole_layer,
             package_declared_size(obj), expected['payload_declared_size']),
            ('payload_complete', ole_layer, payload_is_complete(obj),
             expected['payload_complete']),
        )
        for field, layer, actual, wanted in checks:
            self.check(actual, wanted, sample, index, layer, field=field)

    def check_manifest(self, sample):
        """Check every object of a sample against its manifest entry."""
        expected_objects = SAMPLES[sample]['objects']
        _, parsed = self.load(sample)
        self.check(len(parsed.objects), len(expected_objects), sample, 0,
                   LAYER_HEX, field='object count')
        for index, expected in enumerate(expected_objects):
            self.check_object(sample, index, expected)


class TestHexVariantsPreserveBytes(RtfObjIntegrationTestCase):
    """Legal hex case and whitespace variations keep the reference bytes."""

    def test_reference_is_a_complete_word_object(self):
        """the baseline sample must be a complete, well-formed OLE object"""
        obj = self.object_at(WORD_REFERENCE, 0)
        self.check(obj.is_ole, True, WORD_REFERENCE, 0, LAYER_OLE, 'is_ole')
        self.check(obj.class_name, b'Word.Document.8', WORD_REFERENCE, 0,
                   LAYER_OLE, 'class_name')
        self.check(obj.filename, None, WORD_REFERENCE, 0, LAYER_PACKAGE,
                   'filename')
        self.check(payload_is_complete(obj), True, WORD_REFERENCE, 0,
                   LAYER_OLE, 'payload completeness')
        self.check_manifest(WORD_REFERENCE)

    def test_lowercase_hex_decodes_to_reference(self):
        """lowercase hex digits keep every decoded OLE byte"""
        reference = self.object_at(WORD_REFERENCE, 0)
        sample = 'word_lower_hex.rtf'
        obj = self.object_at(sample, 0)
        self.check(digest(obj.rawdata), digest(reference.rawdata), sample, 0,
                   LAYER_HEX, 'decoded raw bytes')
        self.check(size_of(obj.rawdata), size_of(reference.rawdata), sample,
                   0, LAYER_HEX, 'decoded raw length')
        self.check(digest(obj.oledata), digest(reference.oledata), sample, 0,
                   LAYER_OLE, 'OLE payload bytes')
        self.check(obj.class_name, reference.class_name, sample, 0, LAYER_OLE,
                   'class_name')
        self.check(payload_is_complete(obj), True, sample, 0, LAYER_OLE,
                   'payload completeness')
        self.check_manifest(sample)

    def test_whitespace_between_hex_pairs_decodes_to_reference(self):
        """spaces, tabs and CR/LF between hex pairs are ignored"""
        reference = self.object_at(WORD_REFERENCE, 0)
        sample = 'word_whitespace.rtf'
        obj = self.object_at(sample, 0)
        self.check(digest(obj.rawdata), digest(reference.rawdata), sample, 0,
                   LAYER_HEX, 'decoded raw bytes')
        self.check(digest(obj.oledata), digest(reference.oledata), sample, 0,
                   LAYER_OLE, 'OLE payload bytes')
        self.check(obj.class_name, reference.class_name, sample, 0, LAYER_OLE,
                   'class_name')
        self.check(payload_is_complete(obj), True, sample, 0, LAYER_OLE,
                   'payload completeness')
        self.check_manifest(sample)

    def test_trailing_hex_nibble_is_trimmed(self):
        """an odd final hex digit is dropped, as MS Word does"""
        reference = self.object_at(WORD_REFERENCE, 0)
        sample = 'word_trailing_nibble.rtf'
        obj = self.object_at(sample, 0)
        self.check(digest(obj.rawdata), digest(reference.rawdata), sample, 0,
                   LAYER_HEX, 'decoded raw bytes after trimming')
        self.check(obj.is_ole, True, sample, 0, LAYER_OLE, 'is_ole')
        self.check(payload_is_complete(obj), True, sample, 0, LAYER_OLE,
                   'payload completeness')
        self.check_manifest(sample)

    def test_package_encoding_variants_keep_bytes_and_attribution(self):
        """Package payload, filename and completeness survive re-encoding"""
        reference = self.object_at(PACKAGE_REFERENCE, 0)
        for sample in (PACKAGE_REFERENCE, 'package_mixed.rtf'):
            obj = self.object_at(sample, 0)
            self.check(digest(obj.rawdata), digest(reference.rawdata), sample,
                       0, LAYER_HEX, 'decoded raw bytes')
            self.check(obj.is_ole, True, sample, 0, LAYER_OLE, 'is_ole')
            self.check(obj.class_name, reference.class_name, sample, 0,
                       LAYER_OLE, 'class_name')
            self.check(obj.is_package, True, sample, 0, LAYER_PACKAGE,
                       'is_package')
            self.check(obj.filename, reference.filename, sample, 0,
                       LAYER_PACKAGE, 'filename')
            self.check(digest(obj.olepkgdata), digest(reference.olepkgdata),
                       sample, 0, LAYER_PACKAGE, 'Package payload bytes')
            self.check(package_declared_size(obj),
                       package_declared_size(reference), sample, 0,
                       LAYER_PACKAGE, 'Package declared payload size')
            self.check(payload_is_complete(obj), True, sample, 0,
                       LAYER_PACKAGE, 'payload completeness')
            self.check_manifest(sample)


class TestTolerantExtractionRules(RtfObjIntegrationTestCase):
    """Documented tolerance for malformed RTF constructs."""

    TOLERANT_SAMPLES = (
        'word_bin.rtf',
        'word_escapes.rtf',
        'word_nested_groups.rtf',
        'word_mixed.rtf',
        'word_bin_no_length.rtf',
        'word_bin_negative.rtf',
    )

    def test_tolerated_rtf_yields_reference_bytes(self):
        """bin blocks, escapes and nested groups do not alter the payload"""
        reference = self.object_at(WORD_REFERENCE, 0)
        for sample in self.TOLERANT_SAMPLES:
            obj = self.object_at(sample, 0)
            self.check(digest(obj.rawdata), digest(reference.rawdata), sample,
                       0, LAYER_HEX, 'decoded raw bytes')
            self.check(size_of(obj.rawdata), size_of(reference.rawdata),
                       sample, 0, LAYER_HEX, 'decoded raw length')
            self.check(digest(obj.oledata), digest(reference.oledata), sample,
                       0, LAYER_OLE, 'OLE payload bytes')
            self.check(obj.is_ole, True, sample, 0, LAYER_OLE, 'is_ole')
            self.check(obj.class_name, b'Word.Document.8', sample, 0,
                       LAYER_OLE, 'class_name')
            self.check(payload_is_complete(obj), True, sample, 0, LAYER_OLE,
                       'payload completeness')

    def test_tolerated_samples_match_manifest(self):
        """all tolerated samples agree with their recorded results"""
        for sample in self.TOLERANT_SAMPLES:
            self.check_manifest(sample)

    def test_ignored_text_does_not_enter_the_payload(self):
        """markers from ignored groups never leak into decoded bytes"""
        for sample, markers in SAMPLES.items():
            if not markers.get('ignored'):
                continue
            data, parsed = self.load(sample)
            obj = parsed.objects[0]
            payloads = (obj.rawdata, obj.oledata, obj.olepkgdata)
            for marker in markers['ignored']:
                self.assertIn(marker, data,
                              msg='{0}: test marker {1!r} is not present in '
                                  'the RTF, the sample is not meaningful'
                                  .format(sample, marker))
                for number, payload in enumerate(payloads):
                    if payload is None:
                        continue
                    self.assertNotIn(
                        marker, payload,
                        msg='{0}\n  ignored marker {1!r} leaked into payload '
                            'slot {2} at parse layer {3!r}'
                            .format(self.describe(sample, 0, LAYER_HEX),
                                    marker, number, LAYER_HEX))


class TestTruncationIsNotCompleteness(RtfObjIntegrationTestCase):
    """Truncated data must be reported as truncated, never as complete."""

    def test_truncated_ole_has_bytes_but_no_ole_recognition(self):
        """carried bytes stay available, yet the object is not well-formed"""
        sample = 'truncated_ole.rtf'
        obj = self.object_at(sample, 0)
        expected = SAMPLES[sample]['objects'][0]
        self.check(digest(obj.rawdata), expected['raw_md5'], sample, 0,
                   LAYER_HEX, 'decoded raw bytes')
        self.check(size_of(obj.rawdata), expected['raw_len'], sample, 0,
                   LAYER_HEX, 'decoded raw length')
        self.check(obj.is_ole, False, sample, 0, LAYER_OLE, 'is_ole')
        self.check(obj.class_name, None, sample, 0, LAYER_OLE, 'class_name')
        self.check(obj.oledata, None, sample, 0, LAYER_OLE, 'OLE payload')
        self.check(payload_is_complete(obj), None, sample, 0, LAYER_OLE,
                   'payload completeness')
        self.check_manifest(sample)

    def test_truncated_package_payload_is_not_complete(self):
        """Package length field exceeds the bytes actually carried"""
        sample = 'truncated_package.rtf'
        obj = self.object_at(sample, 0)
        reference = self.object_at(PACKAGE_REFERENCE, 0)
        declared = package_declared_size(obj)
        self.check(obj.is_package, True, sample, 0, LAYER_PACKAGE,
                   'is_package')
        self.check(obj.filename, reference.filename, sample, 0, LAYER_PACKAGE,
                   'filename')
        self.check(declared, SAMPLES[sample]['objects'][0]
                   ['payload_declared_size'], sample, 0, LAYER_PACKAGE,
                   'payload declared size')
        self.assertGreater(declared, size_of(obj.olepkgdata),
                           msg='{0}\n  declared size {1} must exceed the {2} '
                               'carried bytes at parse layer {3!r}'
                               .format(self.describe(sample, 0,
                                                     LAYER_PACKAGE),
                                       declared, size_of(obj.olepkgdata),
                                       LAYER_PACKAGE))
        self.check(payload_is_complete(obj), False, sample, 0, LAYER_PACKAGE,
                   'payload completeness')
        self.check_manifest(sample)

    def test_short_package_payload_is_not_complete(self):
        """Package payload ends before its own declared length"""
        sample = 'package_payload_short.rtf'
        obj = self.object_at(sample, 0)
        declared = package_declared_size(obj)
        self.assertIsNotNone(declared,
                             msg='{0} at parse layer {1!r}'
                             .format(self.describe(sample, 0, LAYER_PACKAGE),
                                     LAYER_PACKAGE))
        self.assertGreater(declared, size_of(obj.olepkgdata),
                           msg='{0}\n  declared size {1} must exceed the {2} '
                               'carried bytes at parse layer {3!r}'
                               .format(self.describe(sample, 0,
                                                     LAYER_PACKAGE),
                                       declared, size_of(obj.olepkgdata),
                                       LAYER_PACKAGE))
        self.check(payload_is_complete(obj), False, sample, 0, LAYER_PACKAGE,
                   'payload completeness')
        self.check_manifest(sample)

    def test_complete_references_are_marked_complete(self):
        """the untruncated references are complete payloads"""
        for sample in (WORD_REFERENCE, PACKAGE_REFERENCE):
            obj = self.object_at(sample, 0)
            self.check(payload_is_complete(obj), True, sample, 0,
                       LAYER_PACKAGE if obj.is_package else LAYER_OLE,
                       'payload completeness')


class TestInnerLengthsDoNotMoveOuterBoundary(RtfObjIntegrationTestCase):
    """OLE and Package inner lengths must not change the RTF object span."""

    PAIRS = (
        ('word', 'inner_length_short.rtf', 'inner_length_exact.rtf',
         LAYER_OLE),
        ('package', 'package_inner_short.rtf', 'package_inner_exact.rtf',
         LAYER_PACKAGE),
    )

    def test_pairs_share_the_same_outer_boundaries(self):
        """same RTF group and object extent for both inner lengths"""
        for _, short_sample, exact_sample, _ in self.PAIRS:
            short_obj = self.object_at(short_sample, 0)
            exact_obj = self.object_at(exact_sample, 0)
            for field in ('start', 'end'):
                self.check(getattr(short_obj, field),
                           getattr(exact_obj, field), short_sample, 0,
                           LAYER_HEX, 'outer {0} versus {1}'
                           .format(field, exact_sample))
            self.check(size_of(short_obj.rawdata), size_of(exact_obj.rawdata),
                       short_sample, 0, LAYER_HEX,
                       'decoded extent versus {0}'.format(exact_sample))
            self.check(len(scan_object_groups(read_sample(short_sample))),
                       len(scan_object_groups(read_sample(exact_sample))),
                       short_sample, 0, LAYER_HEX,
                       'group count versus {0}'.format(exact_sample))

    def test_inner_declared_lengths_drive_payload_length(self):
        """inner lengths select payload bytes, not the RTF object end"""
        expected_lengths = {
            'word': (40, 103),
            'package': (24, 68),
        }
        for label, short_sample, exact_sample, layer in self.PAIRS:
            short_obj = self.object_at(short_sample, 0)
            exact_obj = self.object_at(exact_sample, 0)
            short_len, exact_len = expected_lengths[label]
            short_payload = (short_obj.olepkgdata if short_obj.is_package
                             else short_obj.oledata)
            exact_payload = (exact_obj.olepkgdata if exact_obj.is_package
                             else exact_obj.oledata)
            self.check(size_of(short_payload), short_len, short_sample, 0,
                       layer, 'inner payload length')
            self.check(size_of(exact_payload), exact_len, exact_sample, 0,
                       layer, 'inner payload length')
            self.check(digest(short_payload),
                       digest(exact_payload[:short_len]),
                       short_sample, 0, layer,
                       'short payload versus prefix of {0}'
                       .format(exact_sample))
            self.check(payload_is_complete(short_obj), True, short_sample, 0,
                       layer, 'payload completeness')
            self.check(payload_is_complete(exact_obj), True, exact_sample, 0,
                       layer, 'payload completeness')

    def test_boundaries_match_independent_group_scan(self):
        """outer object end is the objdata group end in the original RTF"""
        for _, short_sample, exact_sample, _ in self.PAIRS:
            for sample in (short_sample, exact_sample):
                data, parsed = self.load(sample)
                groups = scan_object_groups(data)
                obj = parsed.objects[0]
                self.check(len(groups), 1, sample, 0, LAYER_HEX,
                           'objdata group count')
                group_start, group_end = groups[0]
                self.check(obj.end, group_end - 1, sample, 0, LAYER_HEX,
                           'object end versus group end')
                self.check(obj.start, group_start + len(OBJDATA_MARKER) - 1,
                           sample, 0, LAYER_HEX,
                           'object start versus group start')


class TestAdjacentObjectAttribution(RtfObjIntegrationTestCase):
    """A corrupt object must not disturb its intact neighbours."""

    SAMPLE = 'adjacent_objects.rtf'

    def test_three_objects_are_found(self):
        """the sample holds exactly the three expected objects"""
        _, parsed = self.load(self.SAMPLE)
        self.check(len(parsed.objects), 3, self.SAMPLE, 0, LAYER_HEX,
                   'object count')
        self.check_manifest(self.SAMPLE)

    def test_neighbours_keep_their_own_bytes_and_metadata(self):
        """bytes, class name and Package filename belong to their object"""
        first = self.object_at(self.SAMPLE, 0)
        middle = self.object_at(self.SAMPLE, 1)
        last = self.object_at(self.SAMPLE, 2)

        self.check(first.is_ole, True, self.SAMPLE, 0, LAYER_OLE, 'is_ole')
        self.check(first.class_name, b'Word.Document.8', self.SAMPLE, 0,
                   LAYER_OLE, 'class_name')
        self.check(digest(first.oledata),
                   SAMPLES[WORD_REFERENCE]['objects'][0]['oledata_md5'],
                   self.SAMPLE, 0, LAYER_OLE,
                   'first object payload versus reference Word payload')

        self.check(middle.is_ole, False, self.SAMPLE, 1, LAYER_OLE, 'is_ole')
        self.check(middle.class_name, None, self.SAMPLE, 1, LAYER_OLE,
                   'class_name')
        self.check(middle.filename, None, self.SAMPLE, 1, LAYER_PACKAGE,
                   'filename')
        self.check(payload_is_complete(middle), None, self.SAMPLE, 1,
                   LAYER_OLE, 'payload completeness')

        self.check(last.is_package, True, self.SAMPLE, 2, LAYER_PACKAGE,
                   'is_package')
        self.check(last.class_name, b'Package', self.SAMPLE, 2, LAYER_OLE,
                   'class_name')
        self.check(last.filename, 'second.txt', self.SAMPLE, 2,
                   LAYER_PACKAGE, 'filename')
        self.check(digest(last.olepkgdata),
                   SAMPLES[self.SAMPLE]['objects'][2]['olepkgdata_md5'],
                   self.SAMPLE, 2, LAYER_PACKAGE,
                   'last object payload versus recorded Package payload')
        self.check(payload_is_complete(last), True, self.SAMPLE, 2,
                   LAYER_PACKAGE, 'payload completeness')

    def test_object_bytes_do_not_bleed_into_neighbours(self):
        """each object's data is neither absorbed nor duplicated elsewhere"""
        objects = [self.object_at(self.SAMPLE, index) for index in range(3)]
        blobs = [obj.rawdata for obj in objects]
        for index, blob in enumerate(blobs):
            for other_index, other in enumerate(blobs):
                if other_index == index:
                    continue
                self.assertNotIn(
                    blob, other,
                    msg='{0}\n  raw bytes of object #{1} also appear in '
                        'object #{2} at parse layer {3!r}'
                        .format(self.describe(self.SAMPLE, index, LAYER_HEX),
                                index, other_index, LAYER_HEX))
        self.assertNotIn(b'second.txt', objects[0].rawdata,
                         msg='{0}\n  Package filename of object #2 leaked '
                             'into object #0 at parse layer {1!r}'
                         .format(self.describe(self.SAMPLE, 0, LAYER_PACKAGE),
                                 LAYER_PACKAGE))

    def test_parsing_stays_inside_the_sample_and_groups_do_not_overlap(self):
        """object spans are ordered, non-overlapping and within bounds"""
        data, parsed = self.load(self.SAMPLE)
        groups = scan_object_groups(data)
        self.check(len(groups), len(parsed.objects), self.SAMPLE, 0,
                   LAYER_HEX, 'objdata group count')
        previous_end = -1
        for index, obj in enumerate(parsed.objects):
            group_start, group_end = groups[index]
            self.check(obj.start, group_start + len(OBJDATA_MARKER) - 1,
                       self.SAMPLE, index, LAYER_HEX,
                       'object start versus group start')
            self.check(obj.end, group_end - 1, self.SAMPLE, index, LAYER_HEX,
                       'object end versus group end')
            self.assertGreaterEqual(group_start, previous_end,
                                    msg='{0}\n  group {1} overlaps or '
                                        'precedes the previous group at '
                                        'parse layer {2!r}'
                                    .format(self.describe(self.SAMPLE, index,
                                                         LAYER_HEX),
                                            index, LAYER_HEX))
            self.assertTrue(0 <= obj.start < obj.end <= len(data),
                            msg='{0}\n  span is outside the {1}-byte '
                                'sample at parse layer {2!r}'
                            .format(self.describe(self.SAMPLE, index,
                                                 LAYER_HEX), len(data),
                                    LAYER_HEX))
            previous_end = group_end


class TestSampleBoundaries(RtfObjIntegrationTestCase):
    """Every sample declares its object boundaries independently."""

    def test_manifest_boundaries_match_independent_scan(self):
        """recorded group and object boundaries equal a fresh brace scan"""
        for sample in sorted(SAMPLES):
            data, parsed = self.load(sample)
            expected_objects = SAMPLES[sample]['objects']
            groups = scan_object_groups(data)
            self.check(size_of(data), SAMPLES[sample]['size'], sample, 0,
                       LAYER_HEX, 'sample size')
            self.check(len(groups), len(expected_objects), sample, 0,
                       LAYER_HEX, 'objdata group count')
            self.check(len(parsed.objects), len(expected_objects), sample, 0,
                       LAYER_HEX, 'parsed object count')
            previous_end = -1
            for index, (obj, expected) in enumerate(zip(parsed.objects,
                                                       expected_objects)):
                group_start, group_end = groups[index]
                self.check(group_start, expected['group_start'], sample,
                           index, LAYER_HEX, 'group_start')
                self.check(group_end, expected['group_end'], sample, index,
                           LAYER_HEX, 'group_end')
                self.check(expected['content_start'],
                           group_start + len(OBJDATA_MARKER), sample, index,
                           LAYER_HEX, 'content_start versus group_start')
                self.check(obj.start, group_start + len(OBJDATA_MARKER) - 1,
                           sample, index, LAYER_HEX,
                           'rtfobj start versus group_start')
                self.check(obj.end, group_end - 1, sample, index, LAYER_HEX,
                           'rtfobj end versus group_end')
                self.assertEqual(obj.end - obj.start,
                                 expected['rtf_end'] - expected['rtf_start'],
                                 msg='{0}'.format(self.describe(sample, index,
                                                                LAYER_HEX)))
                self.assertGreaterEqual(group_start, previous_end,
                                        msg='{0}\n  groups overlap at parse '
                                            'layer {1!r}'
                                        .format(self.describe(sample, index,
                                                             LAYER_HEX),
                                                LAYER_HEX))
                previous_end = group_end

    def test_all_samples_match_manifest(self):
        """every recorded expectation holds for every object"""
        for sample in sorted(SAMPLES):
            self.check_manifest(sample)

    def test_samples_are_rtf_documents(self):
        """each sample is discovered by is_rtf and has no external reference"""
        for sample in sorted(SAMPLES):
            data = read_sample(sample)
            self.assertTrue(rtfobj.is_rtf(data),
                            msg='sample {0!r} is not recognized as RTF'
                            .format(sample))
            self.assertNotIn(b'http://', data,
                             msg='sample {0!r} references an external service'
                             .format(sample))
            self.assertNotIn(b'https://', data,
                             msg='sample {0!r} references an external service'
                             .format(sample))


class TestCommandLineExtraction(RtfObjIntegrationTestCase):
    """End-to-end extraction through the rtfobj command line."""

    def setUp(self):
        self.temp_dir = mkdtemp(prefix='oletools-rtfobj-int-')
        self.addCleanup(rmtree, self.temp_dir)

    def saved_filename(self, sample, index):
        """
        Name rtfobj uses for the object: Packages use the embedded file name,
        other OLE objects use the class-derived extension, raw data uses .raw.
        """
        expected = SAMPLES[sample]['objects'][index]
        prefix = join(self.temp_dir, sample)
        if expected['is_package']:
            return prefix + '_' + expected['filename']
        if expected['is_ole']:
            class_name = (expected['class_name'] or b'').lower()
            extension = 'doc' if class_name.startswith(b'word') else 'bin'
            return '{0}_object_{1:08X}.{2}'.format(prefix,
                                                   expected['rtf_start'],
                                                   extension)
        return '{0}_object_{1:08X}.raw'.format(prefix, expected['rtf_start'])

    def test_saves_each_object_with_its_own_bytes(self):
        """saved files keep per-object attribution around a corrupt object"""
        sample = 'adjacent_objects.rtf'
        output, return_code = call_and_capture(
            'rtfobj', ['-d', self.temp_dir, '-s', 'all',
                       sample_path(sample)])
        self.assertEqual(return_code, 0,
                         msg='rtfobj failed on {0}: {1}'
                         .format(sample, output))
        expectations = (
            (0, 'oledata_md5'),
            (1, 'raw_md5'),
            (2, 'olepkgdata_md5'),
        )
        for index, field in expectations:
            expected_md5 = SAMPLES[sample]['objects'][index][field]
            filename = self.saved_filename(sample, index)
            self.assertTrue(isfile(filename),
                            msg='{0}\n  rtfobj did not save object #{1} as '
                                '{2!r} at parse layer {3!r}; output:\n{4}'
                            .format(self.describe(sample, index, LAYER_HEX),
                                    index, filename, LAYER_HEX, output))
            with open(filename, 'rb') as saved_file:
                self.assertEqual(
                    md5(saved_file.read()).hexdigest(), expected_md5,
                    msg='{0}\n  saved file {1!r} was expected to hold the '
                        'bytes of object #{2} ({3}) at parse layer {4!r}'
                    .format(self.describe(sample, index, LAYER_HEX),
                            filename, index, field, LAYER_HEX))

    def test_saves_package_payload_verbatim(self):
        """the Package payload is extracted without re-encoding"""
        sample = PACKAGE_REFERENCE
        output, return_code = call_and_capture(
            'rtfobj', ['-d', self.temp_dir, '-s', 'all',
                       sample_path(sample)])
        self.assertEqual(return_code, 0,
                         msg='rtfobj failed on {0}: {1}'
                         .format(sample, output))
        filename = self.saved_filename(sample, 0)
        self.assertTrue(isfile(filename),
                        msg='{0}\n  rtfobj did not save the Package payload '
                            'as {1!r} at parse layer {2!r}; output:\n{3}'
                        .format(self.describe(sample, 0, LAYER_PACKAGE),
                                filename, LAYER_PACKAGE, output))
        with open(filename, 'rb') as saved_file:
            self.assertEqual(
                md5(saved_file.read()).hexdigest(),
                SAMPLES[sample]['objects'][0]['olepkgdata_md5'],
                msg='{0}\n  extracted Package payload differs from the parsed '
                    'payload at parse layer {1!r}'
                .format(self.describe(sample, 0, LAYER_PACKAGE),
                        LAYER_PACKAGE))




#: Verified sample manifest.
#:
#: Keys are file names below tests/test-data/rtfobj/integration/. Each
#: instance records the object boundaries in the original RTF (the
#: whole objdata group and the encoded content, both found independently
#: of the parser), the bytes each layer must yield, and whether the
#: payload is complete under the documented size rules.
SAMPLES = {
    'adjacent_objects.rtf': dict(
        note=(
            'Intact Word object, corrupt object (declares 4096 bytes, 84 '
            'present), intact Package object; neighbours must keep their '
            'own attribution.'
        ),
        size=777,
        objects=[
            dict(
                group_start=18, group_end=255,
                rtf_start=29, rtf_end=254,
                content_start=30,
                span_md5='92d8767b32800c89e9004aa08327b0a1',
                raw_len=112,
                raw_md5='303c7539f0c2b461aaf1724871c3e37e',
                is_ole=True, class_name=b'Word.Document.8',
                oledata_size=70,
                oledata_len=70,
                oledata_md5='bcc9f1a40b47ba8b5b3109f0d8dc3484',
                is_package=False, filename=None,
                olepkgdata_len=None,
                olepkgdata_md5=None,
                payload_declared_size=None,
                payload_complete=True,
            ),
            dict(
                group_start=260, group_end=441,
                rtf_start=271, rtf_end=440,
                content_start=272,
                span_md5='fa1dacaad199838a5f5cf83bf02cb896',
                raw_len=84,
                raw_md5='2c8a6f1b2d39f1a30f1b289913671c5f',
                is_ole=False, class_name=None,
                oledata_size=None,
                oledata_len=None,
                oledata_md5=None,
                is_package=False, filename=None,
                olepkgdata_len=None,
                olepkgdata_md5=None,
                payload_declared_size=None,
                payload_complete=None,
            ),
            dict(
                group_start=446, group_end=771,
                rtf_start=457, rtf_end=770,
                content_start=458,
                span_md5='fefb80359b8170be3fb3a37c1752bcf9',
                raw_len=156,
                raw_md5='cc02ea7bd3ab234b83bde921cd8981cb',
                is_ole=True, class_name=b'Package',
                oledata_size=122,
                oledata_len=122,
                oledata_md5='964617d702431e724e125b064c2a8b39',
                is_package=True, filename='second.txt',
                olepkgdata_len=60,
                olepkgdata_md5='c213adbf037d0ffa9c6937c024d8a06e',
                payload_declared_size=60,
                payload_complete=True,
            ),
        ],
    ),
    'inner_length_exact.rtf': dict(
        note=(
            'Same RTF boundaries as inner_length_short.rtf, but the OLE '
            'inner size equals all bytes carried.'
        ),
        size=327,
        objects=[
            dict(
                group_start=18, group_end=321,
                rtf_start=29, rtf_end=320,
                content_start=30,
                span_md5='c98bec7dfc032ccc3e53a6cf69ddfa45',
                raw_len=145,
                raw_md5='175485b1f74760dbc7998ba8e25265b7',
                is_ole=True, class_name=b'Word.Document.8',
                oledata_size=103,
                oledata_len=103,
                oledata_md5='6be96f1e9f428e055fc8e16251258ff9',
                is_package=False, filename=None,
                olepkgdata_len=None,
                olepkgdata_md5=None,
                payload_declared_size=None,
                payload_complete=True,
            ),
        ],
    ),
    'inner_length_short.rtf': dict(
        note=(
            'OLE inner declared data size (40) is smaller than the 103 '
            'bytes carried; inner lengths must not move the outer RTF '
            'object boundary.'
        ),
        size=327,
        objects=[
            dict(
                group_start=18, group_end=321,
                rtf_start=29, rtf_end=320,
                content_start=30,
                span_md5='bf690eaa8479dc4df0805672e983a1dc',
                raw_len=145,
                raw_md5='5e61ddd3b05d21ba59dfce56e2c7f3eb',
                is_ole=True, class_name=b'Word.Document.8',
                oledata_size=40,
                oledata_len=40,
                oledata_md5='448b037b71fc6bf620731a89f2085f06',
                is_package=False, filename=None,
                olepkgdata_len=None,
                olepkgdata_md5=None,
                payload_declared_size=None,
                payload_complete=True,
            ),
        ],
    ),
    'package_inner_exact.rtf': dict(
        note=(
            'Same RTF boundaries as package_inner_short.rtf, but Package '
            'actual_size equals the payload length.'
        ),
        size=367,
        objects=[
            dict(
                group_start=18, group_end=361,
                rtf_start=29, rtf_end=360,
                content_start=30,
                span_md5='bdafaad61b21a4c7f68207148bd7c30a',
                raw_len=165,
                raw_md5='907017f4148f013319196855dba42a1a',
                is_ole=True, class_name=b'Package',
                oledata_size=131,
                oledata_len=131,
                oledata_md5='2cc8bee15f23395c3331583178343fd0',
                is_package=True, filename='report.txt',
                olepkgdata_len=68,
                olepkgdata_md5='68eb1c9be94182b950cdc393944b951f',
                payload_declared_size=68,
                payload_complete=True,
            ),
        ],
    ),
    'package_inner_short.rtf': dict(
        note=(
            'Package actual_size (24) is smaller than the payload bytes '
            'available; outer boundary is unchanged versus '
            'package_inner_exact.rtf.'
        ),
        size=367,
        objects=[
            dict(
                group_start=18, group_end=361,
                rtf_start=29, rtf_end=360,
                content_start=30,
                span_md5='de0a20b4eb02f74d66480eb33b82627c',
                raw_len=165,
                raw_md5='1d79ed809a84c84d35d433da26e59b21',
                is_ole=True, class_name=b'Package',
                oledata_size=131,
                oledata_len=131,
                oledata_md5='769e8397d1600eee2f6c044461b9c191',
                is_package=True, filename='report.txt',
                olepkgdata_len=24,
                olepkgdata_md5='93a57f658cfb51b5c7fbea9e74a8e86b',
                payload_declared_size=24,
                payload_complete=True,
            ),
        ],
    ),
    'package_mixed.rtf': dict(
        note=(
            'OLE Package behind mixed encoding, nested group and ignored '
            'control words; payload must be unchanged.'
        ),
        ignored=(b'CafeBabe0123',),
        size=601,
        objects=[
            dict(
                group_start=18, group_end=595,
                rtf_start=29, rtf_end=594,
                content_start=30,
                span_md5='1e5e003b517d5a15846875f857d9d743',
                raw_len=165,
                raw_md5='907017f4148f013319196855dba42a1a',
                is_ole=True, class_name=b'Package',
                oledata_size=131,
                oledata_len=131,
                oledata_md5='2cc8bee15f23395c3331583178343fd0',
                is_package=True, filename='report.txt',
                olepkgdata_len=68,
                olepkgdata_md5='68eb1c9be94182b950cdc393944b951f',
                payload_declared_size=68,
                payload_complete=True,
            ),
        ],
    ),
    'package_payload_short.rtf': dict(
        note=(
            'Package payload length field (68) exceeds the 50 payload bytes '
            'supplied; payload is truncated, not complete.'
        ),
        size=331,
        objects=[
            dict(
                group_start=18, group_end=325,
                rtf_start=29, rtf_end=324,
                content_start=30,
                span_md5='1850cf54bf9133fffc1d5304538854b7',
                raw_len=147,
                raw_md5='ea870e072f5e9de981dcef50681b53bc',
                is_ole=True, class_name=b'Package',
                oledata_size=113,
                oledata_len=113,
                oledata_md5='81ede084b1c5338c2453fad5b1523b6f',
                is_package=True, filename='report.txt',
                olepkgdata_len=50,
                olepkgdata_md5='23bd107e49ec13cce69cd89c8abd1e26',
                payload_declared_size=68,
                payload_complete=False,
            ),
        ],
    ),
    'package_plain.rtf': dict(
        note=(
            'Unobfuscated OLE Package reference carrying PKG1_PAYLOAD.'
        ),
        size=367,
        objects=[
            dict(
                group_start=18, group_end=361,
                rtf_start=29, rtf_end=360,
                content_start=30,
                span_md5='d086c8ea3e6ec8085107d82ce974f12a',
                raw_len=165,
                raw_md5='907017f4148f013319196855dba42a1a',
                is_ole=True, class_name=b'Package',
                oledata_size=131,
                oledata_len=131,
                oledata_md5='2cc8bee15f23395c3331583178343fd0',
                is_package=True, filename='report.txt',
                olepkgdata_len=68,
                olepkgdata_md5='68eb1c9be94182b950cdc393944b951f',
                payload_declared_size=68,
                payload_complete=True,
            ),
        ],
    ),
    'truncated_ole.rtf': dict(
        note=(
            'OLE 1.0 header declares 40 bytes more than the RTF carries; '
            'bytes are retained but this is not a well-formed OLE object.'
        ),
        size=261,
        objects=[
            dict(
                group_start=18, group_end=255,
                rtf_start=29, rtf_end=254,
                content_start=30,
                span_md5='c810d917ef8d349ae02564904eed75a1',
                raw_len=112,
                raw_md5='62dc6b199d59964c5c6324cae08294a2',
                is_ole=False, class_name=None,
                oledata_size=None,
                oledata_len=None,
                oledata_md5=None,
                is_package=False, filename=None,
                olepkgdata_len=None,
                olepkgdata_md5=None,
                payload_declared_size=None,
                payload_complete=None,
            ),
        ],
    ),
    'truncated_package.rtf': dict(
        note=(
            'Structurally valid OLE object whose Package payload length '
            'field (108) exceeds the 68 bytes available; payload is '
            'truncated, not complete.'
        ),
        size=367,
        objects=[
            dict(
                group_start=18, group_end=361,
                rtf_start=29, rtf_end=360,
                content_start=30,
                span_md5='014224c510f6ca535f8c858c3e38f3c8',
                raw_len=165,
                raw_md5='9de2a0474701c313f6c32adcde27a881',
                is_ole=True, class_name=b'Package',
                oledata_size=131,
                oledata_len=131,
                oledata_md5='91ec7ae8ee5ad67adff267b3f2b0516b',
                is_package=True, filename='report.txt',
                olepkgdata_len=68,
                olepkgdata_md5='68eb1c9be94182b950cdc393944b951f',
                payload_declared_size=108,
                payload_complete=False,
            ),
        ],
    ),
    'word_bin.rtf': dict(
        note=(
            'Raw bin block embedded between hex runs; must decode to the '
            'reference bytes without leaking the raw block.'
        ),
        size=258,
        objects=[
            dict(
                group_start=18, group_end=252,
                rtf_start=29, rtf_end=251,
                content_start=30,
                span_md5='9872673b9b8047b6808e435931e7d0e9',
                raw_len=112,
                raw_md5='303c7539f0c2b461aaf1724871c3e37e',
                is_ole=True, class_name=b'Word.Document.8',
                oledata_size=70,
                oledata_len=70,
                oledata_md5='bcc9f1a40b47ba8b5b3109f0d8dc3484',
                is_package=False, filename=None,
                olepkgdata_len=None,
                olepkgdata_md5=None,
                payload_declared_size=None,
                payload_complete=True,
            ),
        ],
    ),
    'word_bin_negative.rtf': dict(
        note=(
            'bin with a negative length followed by non-hex bytes; treated '
            'as zero-length.'
        ),
        ignored=(b'ZZ',),
        size=270,
        objects=[
            dict(
                group_start=18, group_end=264,
                rtf_start=29, rtf_end=263,
                content_start=30,
                span_md5='d1c206f4119e807d734edc8e37e37749',
                raw_len=112,
                raw_md5='303c7539f0c2b461aaf1724871c3e37e',
                is_ole=True, class_name=b'Word.Document.8',
                oledata_size=70,
                oledata_len=70,
                oledata_md5='bcc9f1a40b47ba8b5b3109f0d8dc3484',
                is_package=False, filename=None,
                olepkgdata_len=None,
                olepkgdata_md5=None,
                payload_declared_size=None,
                payload_complete=True,
            ),
        ],
    ),
    'word_bin_no_length.rtf': dict(
        note=(
            'bin without a length parameter followed by non-hex bytes; '
            'treated as zero-length.'
        ),
        ignored=(b'ZZ',),
        size=268,
        objects=[
            dict(
                group_start=18, group_end=262,
                rtf_start=29, rtf_end=261,
                content_start=30,
                span_md5='ebe4fa404375822fef577eaa7b547ec6',
                raw_len=112,
                raw_md5='303c7539f0c2b461aaf1724871c3e37e',
                is_ole=True, class_name=b'Word.Document.8',
                oledata_size=70,
                oledata_len=70,
                oledata_md5='bcc9f1a40b47ba8b5b3109f0d8dc3484',
                is_package=False, filename=None,
                olepkgdata_len=None,
                olepkgdata_md5=None,
                payload_declared_size=None,
                payload_complete=True,
            ),
        ],
    ),
    'word_escapes.rtf': dict(
        note=(
            'Hex escape control symbols with an odd then an even nibble '
            'count; Word drops the last nibble before the escape when the '
            'count is odd.'
        ),
        ignored=(b'zz',),
        size=270,
        objects=[
            dict(
                group_start=18, group_end=264,
                rtf_start=29, rtf_end=263,
                content_start=30,
                span_md5='7ff841304724948f22e41582fc593b05',
                raw_len=112,
                raw_md5='303c7539f0c2b461aaf1724871c3e37e',
                is_ole=True, class_name=b'Word.Document.8',
                oledata_size=70,
                oledata_len=70,
                oledata_md5='bcc9f1a40b47ba8b5b3109f0d8dc3484',
                is_package=False, filename=None,
                olepkgdata_len=None,
                olepkgdata_md5=None,
                payload_declared_size=None,
                payload_complete=True,
            ),
        ],
    ),
    'word_lower_hex.rtf': dict(
        note=(
            'Legal lowercase hex digits; must decode to exactly the '
            'reference OLE bytes.'
        ),
        size=261,
        objects=[
            dict(
                group_start=18, group_end=255,
                rtf_start=29, rtf_end=254,
                content_start=30,
                span_md5='30b316eb0486e4265ab394eb2479d631',
                raw_len=112,
                raw_md5='303c7539f0c2b461aaf1724871c3e37e',
                is_ole=True, class_name=b'Word.Document.8',
                oledata_size=70,
                oledata_len=70,
                oledata_md5='bcc9f1a40b47ba8b5b3109f0d8dc3484',
                is_package=False, filename=None,
                olepkgdata_len=None,
                olepkgdata_md5=None,
                payload_declared_size=None,
                payload_complete=True,
            ),
        ],
    ),
    'word_mixed.rtf': dict(
        note=(
            'Lowercase hex, whitespace, raw bin block, hex escape and a '
            'nested destination group in one object.'
        ),
        ignored=(b'CafeBabe0123',),
        size=418,
        objects=[
            dict(
                group_start=18, group_end=412,
                rtf_start=29, rtf_end=411,
                content_start=30,
                span_md5='118d673f0257a79a571963c276f74376',
                raw_len=112,
                raw_md5='303c7539f0c2b461aaf1724871c3e37e',
                is_ole=True, class_name=b'Word.Document.8',
                oledata_size=70,
                oledata_len=70,
                oledata_md5='bcc9f1a40b47ba8b5b3109f0d8dc3484',
                is_package=False, filename=None,
                olepkgdata_len=None,
                olepkgdata_md5=None,
                payload_declared_size=None,
                payload_complete=True,
            ),
        ],
    ),
    'word_nested_groups.rtf': dict(
        note=(
            'Nested destination groups and control words inside objdata; '
            'ignored content must not enter the object bytes.'
        ),
        ignored=(b'CafeBabe0123', b'deadbeef'),
        size=325,
        objects=[
            dict(
                group_start=18, group_end=319,
                rtf_start=29, rtf_end=318,
                content_start=30,
                span_md5='469897ec5a283f1ca966c11c5a6d30c1',
                raw_len=112,
                raw_md5='303c7539f0c2b461aaf1724871c3e37e',
                is_ole=True, class_name=b'Word.Document.8',
                oledata_size=70,
                oledata_len=70,
                oledata_md5='bcc9f1a40b47ba8b5b3109f0d8dc3484',
                is_package=False, filename=None,
                olepkgdata_len=None,
                olepkgdata_md5=None,
                payload_declared_size=None,
                payload_complete=True,
            ),
        ],
    ),
    'word_plain.rtf': dict(
        note=(
            'Unobfuscated reference object; baseline bytes for all hex-text '
            'equivalence checks.'
        ),
        size=261,
        objects=[
            dict(
                group_start=18, group_end=255,
                rtf_start=29, rtf_end=254,
                content_start=30,
                span_md5='92d8767b32800c89e9004aa08327b0a1',
                raw_len=112,
                raw_md5='303c7539f0c2b461aaf1724871c3e37e',
                is_ole=True, class_name=b'Word.Document.8',
                oledata_size=70,
                oledata_len=70,
                oledata_md5='bcc9f1a40b47ba8b5b3109f0d8dc3484',
                is_package=False, filename=None,
                olepkgdata_len=None,
                olepkgdata_md5=None,
                payload_declared_size=None,
                payload_complete=True,
            ),
        ],
    ),
    'word_trailing_nibble.rtf': dict(
        note=(
            'Odd total number of hex digits; Word and rtfobj trim the final '
            'nibble.'
        ),
        size=262,
        objects=[
            dict(
                group_start=18, group_end=256,
                rtf_start=29, rtf_end=255,
                content_start=30,
                span_md5='e9d138c57fbe7acdc39264b6f7c52104',
                raw_len=112,
                raw_md5='303c7539f0c2b461aaf1724871c3e37e',
                is_ole=True, class_name=b'Word.Document.8',
                oledata_size=70,
                oledata_len=70,
                oledata_md5='bcc9f1a40b47ba8b5b3109f0d8dc3484',
                is_package=False, filename=None,
                olepkgdata_len=None,
                olepkgdata_md5=None,
                payload_declared_size=None,
                payload_complete=True,
            ),
        ],
    ),
    'word_whitespace.rtf': dict(
        note=(
            'Legal CR/LF/TAB/space separators between hex pairs; must '
            'decode to exactly the reference OLE bytes.'
        ),
        size=456,
        objects=[
            dict(
                group_start=18, group_end=450,
                rtf_start=29, rtf_end=449,
                content_start=30,
                span_md5='e8c111319e50acbf942d4bd323d10fa1',
                raw_len=112,
                raw_md5='303c7539f0c2b461aaf1724871c3e37e',
                is_ole=True, class_name=b'Word.Document.8',
                oledata_size=70,
                oledata_len=70,
                oledata_md5='bcc9f1a40b47ba8b5b3109f0d8dc3484',
                is_package=False, filename=None,
                olepkgdata_len=None,
                olepkgdata_md5=None,
                payload_declared_size=None,
                payload_complete=True,
            ),
        ],
    ),
}


# just in case somebody calls this file as a script
if __name__ == '__main__':
    unittest.main()
