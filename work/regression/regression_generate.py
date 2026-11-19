#!/usr/bin/env python3
"""
Regression samples + expectations for DDE detection across the three
document containers supported by oletools.msodde:

  1. OOXML   (.docx, zip + XML)          -> process_docx()
  2. OLE     (.doc, compound file)       -> process_doc()/process_doc_stream()
  3. RTF     (.rtf, text + control words)-> process_rtf()

The script is fully local (stdlib + olefile only) and regenerates every
sample into OUT_DIR from declarative specs. It then runs msodde on each and
compares against documented expected results.

Each spec row:
  (sample_id, container, builder, dde_only_expected, blacklist_expected)
where an expected value is either:
  a string  -> exact process_* output (unicode)
  ('raises', ExceptionSubclass) -> scan must raise this exception

Run:
  python3 -I regression_generate.py            # build + verify
  python3 -I regression_generate.py --build    # only write samples
"""
import io
import os
import sys
import zipfile

HERE = os.path.dirname(os.path.abspath(__file__))
REPO_ROOT = os.path.normpath(os.path.join(HERE, '..', '..'))
sys.path.insert(0, REPO_ROOT)
sys.path.insert(0, os.path.join(HERE, '..', 'probes'))

from oletools import msodde          # noqa: E402
import docx_builder as B             # noqa: E402

OUT_DIR = os.path.join(HERE, 'generated')

DDE = 'DDEAUTO cmd /c calc'

# ---------------------------------------------------------------------------
# OOXML builders
# ---------------------------------------------------------------------------

def docx_baseline():
    return B.build_docx(B.para(B.complex_field(DDE)))

def docx_simple():
    return B.build_docx(B.para(B.simple_field(DDE)))

def docx_split_runs():
    body = (B.fldchar('begin') + B.instr('DDE') + B.instr('AUTO cmd /c calc')
            + B.fldchar('separate') + B.fldchar('end'))
    return B.build_docx(B.para(body))

def docx_two_instr_one_run():
    # Word-valid: two instrText in one w:r; parser keeps only the first
    body = ('<w:r><w:fldChar w:fldCharType="begin"/></w:r>'
            '<w:r><w:instrText>HYPERLINK benign</w:instrText>'
            '<w:instrText>DDEAUTO hidden-second</w:instrText></w:r>'
            '<w:r><w:fldChar w:fldCharType="end"/></w:r>')
    return B.build_docx(B.para(body))

def docx_orphan_begin():
    # begin + instrText, no matching end -> buffer discarded at EOF
    return B.build_docx(B.para(B.fldchar('begin') +
                               B.instr('DDEAUTO orphan-no-end')))

def docx_bad_namespace():
    # same XML but namespace URI Word/oletools do not know -> invisible
    return B.build_docx(B.para(B.complex_field(DDE)),
                        ns='http://schemas.openxmlformats.org/wordprocessingml/'
                           '2006/mainX')

def docx_quote_obfuscated():
    # QUOTE 68 68 69 -> "DDE"; unquote() expands it in OOXML only
    return B.build_docx(B.para(B.complex_field('QUOTE 68 68 69 32 65')))

def docx_malformed_part():
    # broken extra XML part: ParseError is swallowed but leaves depth != 0,
    # tripping ooxml.iter_xml's bare `assert(depth == 0)` -> whole scan aborts
    return B.build_docx(
        B.para(B.complex_field(DDE)),
        extra_parts={'word/bad.xml': '<?xml version="1.0"?><doc><unclosed>'})

# ---------------------------------------------------------------------------
# RTF builders (msodde prepends "{\rt" itself; here we write full files)
# ---------------------------------------------------------------------------

def rtf_wrap(inner):
    return b'{\\rtf1' + inner + b'}'

def rtf_baseline():
    return rtf_wrap(b'{\\fldinst ' + DDE.encode() + b'}')

def rtf_hex_escape():
    # \'44\'44\'45 == "DDE"; parser keeps literal "'44'44'45"
    return rtf_wrap(b"{\\fldinst \\'44\\'44\\'45AUTO cmd /c calc}")

def rtf_unicode_escape():
    # \u68 == 'D', \u69 == 'E'; parser substitutes nothing, leaves '?'
    return rtf_wrap(b'{\\fldinst \\u68?\\u68?\\u69?AUTO cmd /c calc}')

def rtf_group_split():
    # ignored destination group inside keyword breaks the token
    return rtf_wrap(b'{\\fldinst DD{\\*\\xx}EAUTO cmd /c calc}')

def rtf_nbsp():
    # \~ is NBSP, Word-valid whitespace; regex only accepts ASCII spaces
    return rtf_wrap(b'{\\fldinst DDE\\~AUTO cmd /c calc}')

def rtf_decode_abort():
    # one valid field followed by a field containing a raw non-ASCII byte
    return rtf_wrap(b'{\\fldinst DDEAUTO first-ok}'
                    b'{\\fldinst bad \xe9}'
                    b'{\\fldinst DDEAUTO third-ok}')

# ---------------------------------------------------------------------------
# OLE builders (raw field-character streams; used via process_doc_stream)
#
# A Word field is 0x13 BEGIN ... 0x14 SEP ... 0x15 END ([MS-DOC] 2.8.25).
# ---------------------------------------------------------------------------

def field_8bit(code):
    return b'\x13' + code.encode('latin-1') + b'\x14r\x15'

def ole_baseline():
    return field_8bit(DDE)

def ole_nbsp():
    # 0xA0 = NBSP in CP1252, mapped to '?' (byte >= 128) before matching
    return field_8bit('DDE\xa0AUTO cmd /c calc')

def ole_tab_break():
    # 0x09 tab mapped to '?' (char < 32), splitting the DDE token
    return field_8bit('DDE\tAUTO cmd /c calc')

def ole_padding_evasion():
    # >= 999 leading bytes push the keyword past OLE_FIELD_MAX_SIZE (1000)
    return b'\x13' + b' ' * 999 + b'DDEAUTO cmd /c calc\x14r\x15'

def ole_utf16le():
    # real FE/Unicode .doc storage; parser keeps interspersed NUL high bytes
    return ('\x13' + DDE + '\x14r\x15').encode('utf-16le')

def ole_prefix_overmatch():
    # startswith("dde") overmatches tokens that are not the DDE field
    return field_8bit('DDEAUTOX not-a-real-field')

# ---------------------------------------------------------------------------
# Spec table
# ---------------------------------------------------------------------------

SPECS = [
    # id, container, extension, builder, dde-only expected, blacklist expected
    ('ooxml-baseline',        'OOXML', '.docx', docx_baseline,
     DDE, DDE),
    ('ooxml-simple',          'OOXML', '.docx', docx_simple,
     DDE, DDE),
    ('ooxml-split-runs',      'OOXML', '.docx', docx_split_runs,
     DDE, DDE),
    ('ooxml-two-instr-run',   'OOXML', '.docx', docx_two_instr_one_run,
     '', 'HYPERLINK benign'),
    ('ooxml-orphan-begin',    'OOXML', '.docx', docx_orphan_begin,
     '', ''),
    ('ooxml-bad-namespace',   'OOXML', '.docx', docx_bad_namespace,
     '', ''),
    ('ooxml-quote',           'OOXML', '.docx', docx_quote_obfuscated,
     'DDE A', 'DDE A'),
    ('ooxml-malformed-part',  'OOXML', '.docx', docx_malformed_part,
     ('raises', AssertionError), ('raises', AssertionError)),

    ('rtf-baseline',          'RTF', '.rtf', rtf_baseline,
     DDE, DDE),
    ('rtf-hex-escape',        'RTF', '.rtf', rtf_hex_escape,
     '', "'44'44'45AUTO cmd /c calc"),
    ('rtf-unicode-escape',    'RTF', '.rtf', rtf_unicode_escape,
     '', '???AUTO cmd /c calc'),
    ('rtf-group-split',       'RTF', '.rtf', rtf_group_split,
     '', 'DD*EAUTO cmd /c calc'),
    ('rtf-nbsp',              'RTF', '.rtf', rtf_nbsp,
     '', 'DDE~AUTO cmd /c calc'),
    ('rtf-decode-abort',      'RTF', '.rtf', rtf_decode_abort,
     ('raises', UnicodeDecodeError), ('raises', UnicodeDecodeError)),

    # OLE rows are raw stream blobs (.bin): fed directly to process_doc_stream,
    # which is the exact routine process_doc() applies to every CFB stream.
    # OLE has no filter: process_doc_field() is the only gate, so "dde-only"
    # and "blacklist" columns are identical here. NBSP/tab are rewritten to
    # '?', so the field is returned as a raw non-DDE string but the DDE token
    # itself is no longer matchable -> detection of the DDE link is evaded.
    ('ole-baseline',          'OLE', '.bin', ole_baseline,
     DDE, DDE),
    ('ole-nbsp',              'OLE', '.bin', ole_nbsp,
     'DDE?AUTO cmd /c calc', 'DDE?AUTO cmd /c calc'),
    ('ole-tab-break',         'OLE', '.bin', ole_tab_break,
     'DDE?AUTO cmd /c calc', 'DDE?AUTO cmd /c calc'),
    ('ole-padding-evasion',   'OLE', '.bin', ole_padding_evasion,
     '', ''),
    ('ole-utf16le',           'OLE', '.bin', ole_utf16le,
     None, None),          # checked separately (NUL-interleaved representation)
    ('ole-prefix-overmatch',  'OLE', '.bin', ole_prefix_overmatch,
     'DDEAUTOX not-a-real-field', 'DDEAUTOX not-a-real-field'),
]


def scan(container, path, mode):
    if container == 'OOXML':
        return msodde.process_docx(path, mode)
    if container == 'RTF':
        with open(path, 'rb') as fh:
            return msodde.process_rtf(fh, mode)
    # OLE raw stream
    with open(path, 'rb') as fh:
        return '\n'.join(msodde.process_doc_stream(fh))


def main(build_only=False):
    os.makedirs(OUT_DIR, exist_ok=True)
    rows = []
    failures = 0
    for sid, container, ext, builder, exp_dde, exp_bl in SPECS:
        path = os.path.join(OUT_DIR, sid + ext)
        with open(path, 'wb') as fh:
            fh.write(builder())
        rows.append((sid, container, path, exp_dde, exp_bl))

    if build_only:
        print('built %d samples under %s' % (len(rows), OUT_DIR))
        return 0

    for sid, container, path, exp_dde, exp_bl in rows:
        for mode, expected in ((msodde.FIELD_FILTER_DDE, exp_dde),
                               (msodde.FIELD_FILTER_BLACKLIST, exp_bl)):
            if expected is None:
                continue
            try:
                got = scan(container, path, mode)
                ok = (not isinstance(expected, tuple)) and got == expected
                detail = repr(got)
            except Exception as exc:           # noqa: BLE001
                ok = (isinstance(expected, tuple) and expected[0] == 'raises'
                      and isinstance(exc, expected[1]))
                detail = 'RAISED %s: %s' % (type(exc).__name__, exc)
            status = 'ok ' if ok else 'FAIL'
            if not ok:
                failures += 1
            print('[%s] %-24s %-18s %s' % (status, sid, mode, detail))

    # dedicated UTF-16LE check: parser retains NUL high bytes but the
    # u'\x00d...' fallback in process_doc_field still recognises the token
    u16 = scan('OLE', os.path.join(OUT_DIR, 'ole-utf16le.bin'),
               msodde.FIELD_FILTER_DDE)
    ok = u16.replace('\x00', '').lstrip().lower().startswith('dde')
    print('[%s] %-24s %-18s %s' %
          ('ok ' if ok else 'FAIL', 'ole-utf16le', 'utf16-nul-interleave',
           repr(u16[:20])))
    if not ok:
        failures += 1

    print('\n%d sample(s), %d failure(s)' % (len(rows), failures))
    return 1 if failures else 0


if __name__ == '__main__':
    sys.exit(main(build_only='--build' in sys.argv))
