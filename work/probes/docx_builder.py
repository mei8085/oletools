"""Minimal OOXML (.docx / .docm) builder for msodde container-evasion probes.

Generates valid zip-based OOXML packages from raw word/document.xml bodies.
Only the parts oletools.ooxml.get_type() / XmlParser need are emitted, so we
stay fully local and dependency-light (stdlib zipfile only).
"""
import io
import zipfile

W = 'http://schemas.openxmlformats.org/wordprocessingml/2006/main'
W2003 = 'http://schemas.microsoft.com/office/word/2003/wordml'

CONTENT_TYPES = (
    '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
    '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
    '<Default Extension="rels" ContentType="application/vnd.openxmlformats-'
    'package.relationships+xml"/>'
    '<Default Extension="xml" ContentType="application/xml"/>'
    '<Override PartName="/word/document.xml" ContentType="application/vnd.'
    'openxmlformats-officedocument.wordprocessingml.document.main+xml"/>'
    '</Types>')

RELS = (
    '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
    '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/'
    'relationships">'
    '<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/'
    'officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/>'
    '</Relationships>')

DOC_HEAD = (
    '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
    '<w:document xmlns:w="{ns}"><w:body>')
DOC_TAIL = '</w:body></w:document>'


def build_docx(body_xml, ns=W, extra_parts=None):
    """Return bytes of a minimal .docx with given paragraph body XML."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, 'w', zipfile.ZIP_DEFLATED) as z:
        z.writestr('[Content_Types].xml', CONTENT_TYPES)
        z.writestr('_rels/.rels', RELS)
        z.writestr('word/document.xml',
                   DOC_HEAD.format(ns=ns) + body_xml + DOC_TAIL)
        for name, data in (extra_parts or {}).items():
            z.writestr(name, data)
    return buf.getvalue()


# --- reusable field fragments (default 2006 namespace) ---

def fldchar(kind):
    return '<w:r><w:fldChar w:fldCharType="%s"/></w:r>' % kind


def instr(text):
    return '<w:r><w:instrText>%s</w:instrText></w:r>' % text


def complex_field(code):
    """begin/instr/separate/result/end around one field code."""
    return (fldchar('begin') + instr(code) + fldchar('separate') +
            '<w:r><w:t>r</w:t></w:r>' + fldchar('end'))


def simple_field(code):
    return '<w:fldSimple w:instr="%s"><w:r><w:t>r</w:t></w:r></w:fldSimple>' % code


def para(*runs):
    return '<w:p>%s</w:p>' % ''.join(runs)
