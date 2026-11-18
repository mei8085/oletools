"""
Unit tests for the MS-OVBA 2.4.1 compression container parser
(``oletools.olevba.decompress_stream``), focused on the security boundary of
CopyToken references.

A CopyToken in a VBA compressed chunk may only point at bytes that were already
decoded *within the same DecompressedChunk*: the sliding window restarts at
every chunk.  Historically the parser performed no bounds check here, so a
malformed CopyToken whose offset ran past the start of the current chunk was
silently turned into a negative Python index and copied bytes from an earlier
chunk (or from the end of the output buffer).  A malicious document could thus
be "restored" into data the encoder never wrote.

The assertions below are organised into three outcomes:

1.  :class:`TestLegalReferences` - in-window references keep decoding,
    including references exactly at the window edge and across token groups.
2.  :class:`TestOutOfBoundsReferences` - references crossing the decoded-window
    boundary (one byte past the edge, wrapping into an earlier chunk, running
    past the 4096-byte chunk end) or truncated streams raise a deterministic
    :class:`ValueError` at a precise compressed-stream offset; no partial,
    silently reconstructed output is returned.
3.  :class:`TestChunkCursor` - after a complete legal chunk the parser resumes
    exactly at the next chunk header, so the same payload decoded through
    different chunk splits gives byte-identical results (and malformed input
    fails identically regardless of how it is split).

Every compressed stream used here is built from small, hand-computed byte
sequences (see the hex literals in the failure messages) so that a failing
assertion points straight at the parsing stage that broke, without needing any
binary test fixtures.
"""

import struct
import unittest

from oletools.olevba import copytoken_help, decompress_stream

# MS-OVBA 2.4.1.1.1: every CompressedContainer starts with signature byte 0x01
SIGNATURE = b'\x01'

# A DecompressedChunk holds at most 4096 decompressed bytes (MS-OVBA 2.4.1.1.3)
CHUNK_DECOMPRESSED_LIMIT = 4096


# ---------------------------------------------------------------------------
# Minimal MS-OVBA byte-stream builders
# ---------------------------------------------------------------------------
# These helpers deliberately only implement the few encodings the tests need,
# so the produced streams stay short and auditable.

def compressed_chunk_header(payload):
    """Build a CompressedChunkHeader (MS-OVBA 2.4.1.3.10) for a compressed
    chunk wrapping *payload* (the chunk data without its 2-byte header)."""
    chunk_size = len(payload) + 2          # header counts itself
    header = ((chunk_size - 3) & 0x0FFF)   # CompressedChunkSize field
    header |= 0x3000                       # CompressedChunkSignature == 0b011
    header |= 0x8000                       # CompressedChunkFlag == 1 (compressed)
    return struct.pack('<H', header)


def raw_chunk_header():
    """CompressedChunkHeader for an uncompressed (raw) 4096-byte chunk."""
    # flag bit 15 == 0, size field encodes 4098 - 3 = 4095
    return struct.pack('<H', 0x3000 | (4098 - 3))


def flag_byte(copy_flags):
    """Pack the 8 FlagBits of a TokenSequence (MS-OVBA 2.4.1.3.4).

    :param iterable copy_flags: 8 booleans, bit 0 first; ``True`` marks a
                                CopyToken slot, ``False`` a LiteralToken slot.
    """
    assert len(copy_flags) == 8
    value = 0
    for bit_index, is_copy in enumerate(copy_flags):
        if is_copy:
            value |= 1 << bit_index
    return bytes([value])


def pack_copy_token(offset, length, difference):
    """Inverse of the CopyToken unpacking in ``decompress_stream``.

    :param int offset: 1-based distance back from DecompressedCurrent
                       (1 <= offset <= difference for a legal token)
    :param int length: CopyToken length, always >= 3
    :param int difference: bytes already decoded in the current chunk
    """
    length_mask, offset_mask, bit_count, _ = copytoken_help(difference, 0)
    token = ((offset - 1) << (16 - bit_count)) | ((length - 3) & length_mask)
    return struct.pack('<H', token)


def build_stream(*chunks):
    """Prefix chunk payloads (each already including its own header) with the
    CompressedContainer signature byte."""
    return SIGNATURE + b''.join(chunks)


def compressed_chunk(payload):
    """Convenience wrapper: header + payload of one compressed chunk."""
    return compressed_chunk_header(payload) + payload


def rle_copy_chunk(seed, target):
    """Build a compressed chunk that decodes to *seed* followed by repeated
    self-referential CopyTokens (offset 1, length 3) until exactly *target*
    bytes have been produced.

    Every emitted TokenSequence uses all 8 token slots so the stream contains
    no padding slots that could mask off-by-two cursor bugs in the parser.
    """
    # first group: len(seed) literals + (8 - len(seed)) RLE copies
    first_flags = [False] * len(seed) + [True] * (8 - len(seed))
    group = bytearray(flag_byte(first_flags)) + seed
    difference = len(seed)
    for _ in range(8 - len(seed)):
        group += pack_copy_token(1, 3, difference)
        difference += 3
    groups = [bytes(group)]

    # following full groups of 8 RLE copies
    while difference < target:
        count = min(8, (target - difference) // 3)
        assert count > 0, 'target %d not reachable from difference %d' % (
            target, difference)
        group = bytearray(flag_byte([True] * count + [False] * (8 - count)))
        for _ in range(count):
            group += pack_copy_token(1, 3, difference)
            difference += 3
        groups.append(bytes(group))
    assert difference == target
    return b''.join(groups)


def assert_value_error_with(test_case, stream, keywords, sample_label):
    """Decompress *stream* and assert it fails with a ValueError whose message
    contains every string in *keywords*.

    Also asserts that no output is returned at all: malformed input must never
    be silently reconstructed into partial macro data.
    """
    with test_case.assertRaises(ValueError, msg=sample_label) as context:
        decompress_stream(bytearray(stream))
    message = str(context.exception)
    for keyword in keywords:
        test_case.assertIn(
            keyword, message,
            msg='%s: error message %r does not locate %r'
                % (sample_label, message, keyword))
    return message


# ---------------------------------------------------------------------------
# Outcome 1: legal in-window references keep decoding
# ---------------------------------------------------------------------------
class TestLegalReferences(unittest.TestCase):
    """CopyTokens that stay inside the decoded window must decode normally."""

    def test_edge_reference_at_window_start(self):
        """Offset exactly equal to the decoded size points at the first byte
        of the chunk: the tightest legal in-window reference."""
        # 4 literals ABCD (difference 4), then CopyToken offset=4 length=4
        # which re-reads the whole window -> ABCDABCD
        payload = flag_byte([False, False, False, False, True,
                             False, False, False])
        payload += b'ABCD'
        payload += pack_copy_token(offset=4, length=4, difference=4)
        result = decompress_stream(build_stream(compressed_chunk(payload)))
        self.assertEqual(result, b'ABCDABCD')

    def test_overlapping_run_reference(self):
        """A CopyToken longer than its offset is an overlapping (run-length)
        reference and must be expanded byte by byte."""
        # literals ABC then offset=3 length=6 -> ABC + ABCABC = ABCABCABC
        payload = flag_byte([False, False, False, True,
                             False, False, False, False])
        payload += b'ABC'
        payload += pack_copy_token(offset=3, length=6, difference=3)
        result = decompress_stream(build_stream(compressed_chunk(payload)))
        self.assertEqual(result, b'ABCABCABC')

    def test_references_across_token_groups(self):
        """RLE references spread over several full TokenSequences must keep
        decoding after each FlagByte boundary (regression guard for the
        compressed_end pointer, which previously stopped two bytes early)."""
        # 3 literals + 5 copies in group 1 (all 8 slots used) reach
        # difference 18; further full groups of 8 length-3 copies add 24 each,
        # so 18 + 170 * 24 = 4098 would overflow and 18 + 169 * 24 = 4074 is
        # the largest full-group target below the 4096-byte chunk limit.
        payload = rle_copy_chunk(b'ABC', 4074)
        result = decompress_stream(build_stream(compressed_chunk(payload)))
        self.assertEqual(len(result), 4074)
        self.assertEqual(result[:3], b'ABC')
        self.assertTrue(result[3:] == b'C' * (4074 - 3))

    def test_full_size_raw_chunk(self):
        """An uncompressed chunk of exactly 4096 bytes must be copied verbatim
        and leave the cursor on the following chunk header."""
        data = bytes(range(256)) * 16
        self.assertEqual(len(data), CHUNK_DECOMPRESSED_LIMIT)
        result = decompress_stream(build_stream(raw_chunk_header() + data))
        self.assertEqual(result, data)

    def test_two_legal_chunks_concatenate(self):
        """Two well-formed chunks decode into one continuous buffer in order."""
        first = raw_chunk_header() + b'A' * CHUNK_DECOMPRESSED_LIMIT
        tail_payload = flag_byte([False] * 8) + b'BCDEFGHZ'
        second = compressed_chunk(tail_payload)
        result = decompress_stream(build_stream(first, second))
        self.assertEqual(result, b'A' * 4096 + b'BCDEFGHZ')


# ---------------------------------------------------------------------------
# Outcome 2: out-of-bounds references and truncated streams fail deterministically
# ---------------------------------------------------------------------------
class TestOutOfBoundsReferences(unittest.TestCase):
    """References crossing the decoded-window boundary must raise, not wrap."""

    def test_offset_one_past_window_start(self):
        """The smallest possible violation: offset == difference + 1.

        With three decoded bytes the window covers offsets 1..3; a token
        claiming offset 4 previously indexed output[-1] and silently emitted
        bytes from before the chunk.
        """
        # difference 3 -> bit_count 4: offset 4, length 3 packs to 0x3000
        malformed = flag_byte([False, False, False, True,
                               False, False, False, False])
        malformed += b'ABC'
        malformed += pack_copy_token(offset=4, length=3, difference=3)
        stream = build_stream(compressed_chunk(malformed))
        # minimal sample, kept for failure localisation:
        self.assertEqual(stream.hex(), '0105b0084142430030')
        message = assert_value_error_with(
            self, stream,
            ['out-of-bounds CopyToken', 'offset 4', '0x7'],
            'offset one past window start')
        # the error must name the actual compressed position of the token
        self.assertIn('compressed offset 0x7', message)

    def test_oob_reference_wraps_to_previous_chunk(self):
        """After a complete legal 4096-byte chunk, an OOB token in the next
        chunk must not wrap into bytes decoded by the first chunk."""
        good_first_chunk = raw_chunk_header() + b'A' * CHUNK_DECOMPRESSED_LIMIT
        malformed_tail = flag_byte([False, False, False, True,
                                    False, False, False, False])
        malformed_tail += b'XYZ'
        malformed_tail += pack_copy_token(offset=4, length=3, difference=3)
        stream = build_stream(good_first_chunk,
                              compressed_chunk(malformed_tail))
        # the tail chunk starts at 1 + 4098 = 0x1003; its CopyToken sits at
        # 0x1003 + 2 (header) + 1 (flag byte) + 3 (literals) = 0x1009
        message = assert_value_error_with(
            self, stream,
            ['out-of-bounds CopyToken', 'offset 4', '0x1009',
             '0x1000'],
            'OOB reference after a full raw chunk')
        # the message must make clear the current chunk starts at 4096, i.e.
        # the token is not allowed to reach into the preceding chunk
        self.assertIn('current DecompressedChunk', message)

    def test_length_running_past_chunk_end(self):
        """A CopyToken that would grow the DecompressedChunk beyond 4096 bytes
        must be rejected even though its offset stays in-window."""
        # fill to difference 4074 with aligned RLE groups ...
        first_group = flag_byte([False, False, False, True, True, True,
                                 True, True]) + b'ABC'
        difference = 3
        for _ in range(5):
            first_group += pack_copy_token(1, 3, difference)
            difference += 3
        groups = [first_group]
        for _ in range(169):                # 18 + 169 * 24 == 4074
            group = bytearray(flag_byte([True] * 8))
            for _ in range(8):
                group += pack_copy_token(1, 3, difference)
                difference += 3
            groups.append(bytes(group))
        self.assertEqual(difference, 4074)
        # final group: 7 legal copies reach 4095, the 8th would reach 4098
        final_group = bytearray(flag_byte([True] * 8))
        for _ in range(7):
            final_group += pack_copy_token(1, 3, difference)
            difference += 3
        self.assertEqual(difference, 4095)
        final_group += pack_copy_token(1, 3, difference)   # 4095 + 3 > 4096
        payload = b''.join(groups) + bytes(final_group)

        # control: the same stream with the 8th slot replaced by nothing
        # (7 copies only, padded slot unused) is itself legal up to 4095
        control_payload = b''.join(groups) + bytes(final_group[:-2])
        control = decompress_stream(
            build_stream(compressed_chunk(control_payload)))
        self.assertEqual(len(control), 4095)

        stream = build_stream(compressed_chunk(payload))
        assert_value_error_with(
            self, stream,
            ['out-of-bounds CopyToken', '4096-byte limit', 'length 3'],
            'CopyToken extending past chunk end')

    def test_truncated_chunk_header(self):
        """A container ending in the middle of a chunk header is truncated."""
        stream = SIGNATURE + b'\xff'        # only one byte of the 2-byte header
        assert_value_error_with(
            self, stream, ['truncated', 'CompressedChunkHeader'],
            'truncated chunk header')

    def test_truncated_chunk_body(self):
        """A chunk header declaring more bytes than the container holds must
        fail instead of being silently decoded up to end-of-container."""
        declared_payload = b'\x00' * 20
        stream = (SIGNATURE + compressed_chunk_header(declared_payload)
                  + b'\x00' * 5)
        message = assert_value_error_with(
            self, stream, ['truncated', '0x1'], 'truncated chunk body')
        self.assertIn('declares size', message)

    def test_truncated_copy_token(self):
        """A CopyToken with only one of its two bytes present must raise a
        ValueError naming the token position, not a low-level struct.error."""
        payload = flag_byte([True, False, False, False,
                             False, False, False, False]) + b'Z'
        stream = build_stream(compressed_chunk(payload))
        message = assert_value_error_with(
            self, stream, ['truncated', 'CopyToken', '0x4'],
            'truncated CopyToken')
        self.assertIn('needs 2 bytes', message)

    def test_copy_token_as_first_token(self):
        """A CopyToken in the very first token slot has an empty window: it
        must fail with a clear bounds error instead of a math-domain crash."""
        # flag byte says the first token is a copy; token bytes are zero
        payload = flag_byte([True, False, False, False,
                             False, False, False, False]) + b'\x00\x00'
        stream = build_stream(compressed_chunk(payload))
        assert_value_error_with(
            self, stream, ['out-of-bounds CopyToken', 'no decoded byte'],
            'CopyToken as first token of chunk')

    def test_no_partial_output_on_failure(self):
        """All malformed samples must raise before returning any data."""
        malformed = flag_byte([False, False, False, True,
                               False, False, False, False])
        malformed += b'ABC'
        malformed += pack_copy_token(offset=4, length=3, difference=3)
        with self.assertRaises(ValueError):
            decompress_stream(
                build_stream(compressed_chunk(malformed)))


# ---------------------------------------------------------------------------
# Outcome 3: later chunks continue from the correct position
# ---------------------------------------------------------------------------
class TestChunkCursor(unittest.TestCase):
    """Chunk boundaries and split consistency."""

    # payload used by every split test: one full chunk plus a 104-byte tail
    TAIL_TEXT = b'BCDEFGHZ' + b'Z' * 96
    PAYLOAD = b'A' * CHUNK_DECOMPRESSED_LIMIT + TAIL_TEXT

    def _tail_chunk(self):
        """Compressed encoding of TAIL_TEXT using only full token groups."""
        # first group: 8 literals
        payload = bytearray(flag_byte([False] * 8)) + self.TAIL_TEXT[:8]
        difference = 8
        # remaining 96 'Z' bytes as RLE copies (32 length-3 copies, i.e. four
        # complete groups of 8)
        self.assertEqual((len(self.TAIL_TEXT) - 8) % 3, 0)
        while difference < len(self.TAIL_TEXT):
            count = min(8, (len(self.TAIL_TEXT) - difference) // 3)
            payload += flag_byte([True] * count + [False] * (8 - count))
            for _ in range(count):
                payload += pack_copy_token(1, 3, difference)
                difference += 3
        self.assertEqual(difference, len(self.TAIL_TEXT))
        return compressed_chunk(bytes(payload))

    def _compressed_first_chunk(self):
        """Compressed encoding of 4096 'A' bytes using only full groups."""
        # group 1: 2 literals + 6 RLE copies -> difference 20
        group = bytearray(flag_byte([False, False, True, True, True, True,
                                     True, True])) + b'AA'
        difference = 2
        for _ in range(6):
            group += pack_copy_token(1, 3, difference)
            difference += 3
        groups = [bytes(group)]
        # 169 full groups of 8 copies -> 20 + 169 * 24 == 4076
        for _ in range(169):
            group = bytearray(flag_byte([True] * 8))
            for _ in range(8):
                group += pack_copy_token(1, 3, difference)
                difference += 3
            groups.append(bytes(group))
        self.assertEqual(difference, 4076)
        # last group: 6 copies (+18 -> 4094) + 2 literals (->4096)
        group = bytearray(flag_byte([True] * 6 + [False, False]))
        for _ in range(6):
            group += pack_copy_token(1, 3, difference)
            difference += 3
        group += b'AA'
        groups.append(bytes(group))
        payload = b''.join(groups)
        result = decompress_stream(
            build_stream(compressed_chunk(payload)))
        self.assertEqual(result, b'A' * CHUNK_DECOMPRESSED_LIMIT)
        return compressed_chunk(payload)

    def test_same_payload_different_splits_decode_identically(self):
        """The same 4200-byte payload must decode identically whether its first
        chunk is stored raw or compressed: chunk splitting must not change the
        parsing result."""
        tail = self._tail_chunk()

        raw_first = raw_chunk_header() + b'A' * CHUNK_DECOMPRESSED_LIMIT
        compressed_first = self._compressed_first_chunk()
        self.assertNotEqual(len(raw_first), len(compressed_first))

        raw_split = decompress_stream(
            bytearray(build_stream(raw_first, tail)))
        compressed_split = decompress_stream(
            bytearray(build_stream(compressed_first, tail)))

        self.assertEqual(len(raw_split), len(self.PAYLOAD))
        self.assertEqual(raw_split, self.PAYLOAD)
        self.assertEqual(compressed_split, raw_split)

    def test_cursor_lands_on_next_chunk_header(self):
        """After a full raw chunk (4098 container bytes) the tail chunk starts
        at offset 0x1003 and its tokens are decoded from decompressed offset
        0x1000, proving the window was correctly reset."""
        tail_payload = flag_byte([False] * 8) + self.TAIL_TEXT[:8]
        tail = compressed_chunk(tail_payload)
        first = raw_chunk_header() + b'A' * CHUNK_DECOMPRESSED_LIMIT
        result = decompress_stream(bytearray(build_stream(first, tail)))
        self.assertEqual(result[:4096], b'A' * 4096)
        self.assertEqual(result[4096:4104], self.TAIL_TEXT[:8])

    def test_malformed_tail_fails_under_both_splits(self):
        """An OOB CopyToken in the tail must be rejected regardless of how the
        preceding chunk was encoded: the error class and the offending token
        semantics are identical, only the absolute offset differs."""
        malformed_tail_payload = flag_byte(
            [False, False, False, True, False, False, False, False])
        malformed_tail_payload += b'XYZ'
        malformed_tail_payload += pack_copy_token(
            offset=4, length=3, difference=3)
        malformed_tail = compressed_chunk(malformed_tail_payload)

        raw_first = raw_chunk_header() + b'A' * CHUNK_DECOMPRESSED_LIMIT
        compressed_first = self._compressed_first_chunk()

        for label, first_chunk, expected_token_offset in (
                ('raw split', raw_first, '0x1009'),
                ('compressed split', compressed_first, None)):
            stream = build_stream(first_chunk, malformed_tail)
            with self.assertRaises(ValueError) as context:
                decompress_stream(bytearray(stream))
            message = str(context.exception)
            # identical, split-independent conclusion ...
            self.assertIn('out-of-bounds CopyToken', message, msg=label)
            self.assertIn('offset 4 exceeds the 3 decoded byte', message,
                          msg=label)
            # ... while the absolute cursor matches each split's real layout
            if expected_token_offset is not None:
                self.assertIn(expected_token_offset, message, msg=label)
            else:
                # tail starts right after the (smaller) compressed first chunk
                tail_start = 1 + len(compressed_first)
                token_offset = tail_start + 2 + 1 + 3
                # error messages use upper-case hex, compare case-insensitively
                self.assertIn(hex(token_offset).upper(), message.upper(),
                              msg=label)

    def test_legal_then_malformed_chunk_does_not_leak_first_chunk(self):
        """Even though the first chunk decodes fine, an OOB token in the second
        must abort the whole call: callers never receive the good prefix."""
        first = raw_chunk_header() + b'A' * CHUNK_DECOMPRESSED_LIMIT
        malformed = flag_byte([False, False, False, True,
                               False, False, False, False])
        malformed += b'XYZ'
        malformed += pack_copy_token(offset=4, length=3, difference=3)
        stream = build_stream(first, compressed_chunk(malformed))
        with self.assertRaises(ValueError):
            decompress_stream(bytearray(stream))


if __name__ == '__main__':
    unittest.main()
