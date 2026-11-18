"""
clsid.py

Collection of known CLSIDs and related vulnerabilities, for the oletools.

Author: Philippe Lagadec - http://www.decalage.info
License: BSD, see source code or documentation

clsid is part of the python-oletools package:
http://www.decalage.info/python/oletools
"""

#=== LICENSE ==================================================================

# oletools are copyright (c) 2018-2023 Philippe Lagadec (http://www.decalage.info)
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without modification,
# are permitted provided that the following conditions are met:
#
#  * Redistributions of source code must retain the above copyright notice, this
#    list of conditions and the following disclaimer.
#  * Redistributions in binary form must reproduce the above copyright notice,
#    this list of conditions and the following disclaimer in the documentation
#    and/or other materials provided with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
# ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
# WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
# DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
# FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
# DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
# SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
# CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
# OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
# OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

#------------------------------------------------------------------------------
# CHANGELOG:
# 2018-04-11 v0.53 PL: - added collection of CLSIDs
# 2018-04-13       PL: - moved KNOWN_CLSIDS from oledir to common.clsid
#                  SQ: - several additions by Shiao Qu
# 2018-04-18       PL: - added known-bad CLSIDs from Cuckoo sandbox (issue #290)
# 2018-05-08       PL: - added more CLSIDs (issues #299, #304), merged and sorted
# 2026-02-09       : - added embedded-object risk grading and high-risk CLSID
#                     identification: strict CLSID parsing/normalization,
#                     curated HIGH/MEDIUM risk tables, suspicious command and
#                     script indicator matching, assess_embedded_object() API

__version__ = '0.60.2.dev2'


# REFERENCES:

# Known-bad CLSIDs from Cuckoo Sandbox:
# https://github.com/cuckoosandbox/community/blob/master/modules/signatures/windows/office.py#L314

# https://justhaifei1.blogspot.nl/2017/07/bypassing-microsofts-cve-2017-0199-patch.html
# https://github.com/nccgroup/yaml2yara/blob/master/sample_data/office_exploits/ole.yaml

# Large database of known CLSIDs/UUIDs:
# https://uuid.pirate-server.com/


KNOWN_CLSIDS = {
    '00000300-0000-0000-C000-000000000046': 'StdOleLink (embedded OLE object - Known Related to CVE-2017-0199, CVE-2017-8570, CVE-2017-8759 or CVE-2018-8174)',
    '00000303-0000-0000-C000-000000000046': 'File Moniker (may trigger CVE-2017-0199 or CVE-2017-8570)',
    '00000304-0000-0000-C000-000000000046': 'Item Moniker',
    '00000305-0000-0000-C000-000000000046': 'Anti Moniker',
    '00000306-0000-0000-C000-000000000046': 'Pointer Moniker',
    '00000308-0000-0000-C000-000000000046': 'Packager Moniker',
    '00000309-0000-0000-C000-000000000046': 'Composite Moniker (may trigger CVE-2017-8570)',
    '0000031A-0000-0000-C000-000000000046': 'Class Moniker',
    '00000535-0000-0010-8000-00AA006D2EA4': 'ADODB.RecordSet (may trigger CVE-2015-0097)',
    '00000FE0-8804-4CA8-8868-36F59DEFD14D': 'ZED! encrypted container',
    '0002034C-0000-0000-C000-000000000046': 'OutlookAttachMoniker',
    '0002034E-0000-0000-C000-000000000046': 'OutlookMessageMoniker',
    '00020810-0000-0000-C000-000000000046': 'Microsoft Excel.Sheet.5',
    '00020811-0000-0000-C000-000000000046': 'Microsoft Excel.Chart.5',
    '00020820-0000-0000-C000-000000000046': 'Microsoft Microsoft Excel 97-2003 Worksheet (Excel.Sheet.8)',
    '00020821-0000-0000-C000-000000000046': 'Microsoft Excel.Chart.8',
    '00020830-0000-0000-C000-000000000046': 'Microsoft Excel.Sheet.12',
    '00020832-0000-0000-C000-000000000046': 'Microsoft Excel sheet with macro enabled (Excel.SheetMacroEnabled.12)',
    '00020833-0000-0000-C000-000000000046': 'Microsoft Excel binary sheet with macro enabled (Excel.SheetBinaryMacroEnabled.12)',
    '00020900-0000-0000-C000-000000000046': 'Microsoft Word 6.0-7.0 Document (Word.Document.6)',
    '00020906-0000-0000-C000-000000000046': 'Microsoft Word 97-2003 Document (Word.Document.8)',
    '00020907-0000-0000-C000-000000000046': 'Microsoft Word Picture (Word.Picture.8)',
    '00020C01-0000-0000-C000-000000000046': 'OLE Package Object (may contain and run any file)',
    '00021401-0000-0000-C000-000000000046': 'Windows LNK Shortcut file', # ref: https://github.com/libyal/liblnk/blob/master/documentation/Windows%20Shortcut%20File%20(LNK)%20format.asciidoc
    '00021700-0000-0000-C000-000000000046': 'Microsoft Equation 2.0 (Known Related to CVE-2017-11882 or CVE-2018-0802)',
    '00022601-0000-0000-C000-000000000046': 'OLE Package Object (may contain and run any file)',
    '00022602-0000-0000-C000-000000000046': 'OLE Package Object (may contain and run any file)',
    '00022603-0000-0000-C000-000000000046': 'OLE Package Object (may contain and run any file)',
    '0002CE02-0000-0000-C000-000000000046': 'Microsoft Equation 3.0 (Known Related to CVE-2017-11882 or CVE-2018-0802)',
    '0002CE03-0000-0000-C000-000000000046': 'MathType Equation Object',
    '0003000A-0000-0000-C000-000000000046': 'Bitmap Image',
    '0003000B-0000-0000-C000-000000000046': 'Microsoft Equation (Known Related to CVE-2017-11882 or CVE-2018-0802)',
    '0003000C-0000-0000-C000-000000000046': 'OLE Package Object (may contain and run any file)',
    '0003000D-0000-0000-C000-000000000046': 'OLE Package Object (may contain and run any file)',
    '0003000E-0000-0000-C000-000000000046': 'OLE Package Object (may contain and run any file)',
    '0004A6B0-0000-0000-C000-000000000046': 'Microsoft Equation 2.0 (Known Related to CVE-2017-11882 or CVE-2018-0802)', # TODO: to be confirmed
    # Referenced in https://devblogs.microsoft.com/setup/identifying-windows-installer-file-types/ :
    '000C1082-0000-0000-C000-000000000046': 'MSI Transform (mst)',
    '000C1084-0000-0000-C000-000000000046': 'MSI Windows Installer Package (msi)',
    '000C1086-0000-0000-C000-000000000046': 'MSI Patch Package (psp)',
    '048EB43E-2059-422F-95E0-557DA96038AF': 'Microsoft Powerpoint.Slide.12',
    '05741520-C4EB-440A-AC3F-9643BBC9F847': 'otkloadr.WRLoader (can be used to bypass ASLR after triggering an exploit)',
    '06290BD2-48AA-11D2-8432-006008C3FBFC': 'Factory bindable using IPersistMoniker (scripletfile)',
    '06290BD3-48AA-11D2-8432-006008C3FBFC': 'Script Moniker, aka Moniker to a Windows Script Component (may trigger CVE-2017-0199)',
    '0CF774D0-F077-11D1-B1BC-00C04F86C324': 'scrrun.dll - HTML File Host Encode Object (ProgID: HTML.HostEncode)',
    '0D43FE01-F093-11CF-8940-00A0C9054228': 'scrrun.dll - FileSystem Object (ProgID: Scripting.FileSystemObject)',
    '0E59F1D5-1FBE-11D0-8FF2-00A0D10038BC': 'MSScriptControl.ScriptControl (may trigger CVE-2015-0097)',
    '1461A561-24E8-4BA3-8D4A-FFEEF980556B': 'BCSAddin.Connect (potential exploit CVE-2016-0042 / MS16-014)',
    '14CE31DC-ABC2-484C-B061-CF3416AED8FF': 'Loads WUAEXT.DLL (Known Related to CVE-2015-6128)',
    '18A06B6B-2F3F-4E2B-A611-52BE631B2D22': 'Word.DocumentMacroEnabled.12 (DOCM)',
    '1D8A9B47-3A28-4CE2-8A4B-BD34E45BCEEB': 'UPnP.DescriptionDocument',
    '1EFB6596-857C-11D1-B16A-00C0F0283628': 'MSCOMCTL.TabStrip (may trigger CVE-2012-1856, CVE-2013-3906 - often used for heap spray)',
    '233C1507-6A77-46A4-9443-F871F945D258': 'Shockwave Control Objects',
    '23CE100B-1390-49D6-BA00-F17D3AEE149C': 'UmOutlookAddin.UmEvmCtrl (potential exploit document CVE-2016-0042 / MS16-014)',
    # Referenced in https://resources.sei.cmu.edu/library/asset-view.cfm?assetid=652438 :
    '29131539-2EED-1069-BF5D-00DD011186B7': 'IBM/Lotus Notes COM interface provided by NLSXBE.DLL (related to CVE-2021-27058)',
    '3018609E-CDBC-47E8-A255-809D46BAA319': 'SSCE DropTable Listener Object (can be used to bypass ASLR after triggering an exploit)',
    '3050F4D8-98B5-11CF-BB82-00AA00BDCE0B': 'HTML Application (may trigger CVE-2017-0199)',
    '33BD73C2-7BB4-48F4-8DBC-82B8B313AE16': 'osf.SandboxManager (Known Related To CVE-2015-1770)',
    '33FD0563-D81A-4393-83CC-0195B1DA2F91': 'UPnP.DescriptionDocumentEx',
    '394C052E-B830-11D0-9A86-00C04FD8DBF7': 'Loads ELSEXT.DLL (Known Related to CVE-2015-6128)',
    '3BA59FA5-41BF-4820-98E4-04645A806698': 'osf.SandboxContent (Known Related To CVE-2015-1770)',
    '41B9BE05-B3AF-460C-BF0B-2CDD44A093B1': 'Search.XmlContentFilter (potential exploit document CVE TODO)',
    '4315D437-5B8C-11D0-BD3B-00A0C911CE86': 'Device Moniker (Known Related to CVE-2016-0015)',
    '44F9A03B-A3EC-4F3B-9364-08E0007F21DF': 'Control.TaskSymbol (Known Related to CVE-2015-1642 & CVE-2015-2424)',
    '46E31370-3F7A-11CE-BED6-00AA00611080': 'Forms.MultiPage',
    '4C599241-6926-101B-9992-00000B65C6F9': 'Forms.Image (may trigger CVE-2015-2424)',
    '4D3263E4-CAB7-11D2-802A-0080C703929C': 'AutoCAD 2000-2002 Document',
    '5E4405B0-5374-11CE-8E71-0020AF04B1D7': 'AutoCAD R14 Document',
    '64818D10-4F9B-11CF-86EA-00AA00B929E8': 'Microsoft Powerpoint.Show.8',
    '64818D11-4F9B-11CF-86EA-00AA00B929E8': 'Microsoft Powerpoint.Slide.8',
    '66833FE6-8583-11D1-B16A-00C0F0283628': 'MSCOMCTL.Toolbar (Known Related to CVE-2012-0158 & CVE-2012-1856)',
    '6A221957-2D85-42A7-8E19-BE33950D1DEB': 'AutoCAD 2013 Document',
    '6AD4AE40-2FF1-4D88-B27A-F76FC7B40440': 'BCSAddin.ManageSolutionHelper (potential exploit CVE-2016-0042 / MS16-014)',
    '6E182020-F460-11CE-9BCD-00AA00608E01': 'Forms.Frame',
    '799ED9EA-FB5E-11D1-B7D6-00C04FC2AAE2': 'Microsoft.VbaAddin (Known Related to CVE-2016-0042)',
    '79EAC9D0-BAF9-11CE-8C82-00AA004BA90B': 'StdHlink',
    '79EAC9D1-BAF9-11CE-8C82-00AA004BA90B': 'StdHlinkBrowseContext',
    '79EAC9E0-BAF9-11CE-8C82-00AA004BA90B': 'URL Moniker (may trigger CVE-2017-0199, CVE-2017-8570, or CVE-2018-8174)',
    '79EAC9E2-BAF9-11CE-8C82-00AA004BA90B': '(http:) Asychronous Pluggable Protocol Handler',
    '79EAC9E3-BAF9-11CE-8C82-00AA004BA90B': '(ftp:) Asychronous Pluggable Protocol Handler',
    '79EAC9E5-BAF9-11CE-8C82-00AA004BA90B': '(https:) Asychronous Pluggable Protocol Handler',
    '79EAC9E6-BAF9-11CE-8C82-00AA004BA90B': '(mk:) Asychronous Pluggable Protocol Handler',
    '79EAC9E7-BAF9-11CE-8C82-00AA004BA90B': '(file:, local:) Asychronous Pluggable Protocol Handler',
    '7AABBB95-79BE-4C0F-8024-EB6AF271231C': 'AutoCAD 2007-2009 Document',
    '85131630-480C-11D2-B1F9-00C04F86C324': 'scrrun.dll - JS File Host Encode Object (ProgID: JSFile.HostEncode)',
    '85131631-480C-11D2-B1F9-00C04F86C324': 'scrrun.dll - VBS File Host Encode Object (ProgID: VBSFile.HostEncode)',
    '8627E73B-B5AA-4643-A3B0-570EDA17E3E7': 'UmOutlookAddin.ButtonBar (potential exploit document CVE-2016-0042 / MS16-014)',
    '88D969E5-F192-11D4-A65F-0040963251E5': 'Msxml2.DOMDocument.5.0',
    '88D969E9-F192-11D4-A65F-0040963251E5': 'Msxml2.DSOControl.5.0',
    '88D969E6-F192-11D4-A65F-0040963251E5': 'Msxml2.FreeThreadedDOMDocument.5.0',
    '88D969F5-F192-11D4-A65F-0040963251E5': 'Msxml2.MXDigitalSignature.5.0',
    '88D969F0-F192-11D4-A65F-0040963251E5': 'Msxml2.MXHTMLWriter.5.0',
    '88D969F1-F192-11D4-A65F-0040963251E5': 'Msxml2.MXNamespaceManager.5.0',
    '88D969EF-F192-11D4-A65F-0040963251E5': 'Msxml2.MXXMLWriter.5.0',
    '88D969EE-F192-11D4-A65F-0040963251E5': 'Msxml2.SAXAttributes.5.0',
    '88D969EC-8B8B-4C3D-859E-AF6CD158BE0F': 'Msxml2.SAXXMLReader.5.0',
    '88D969EB-F192-11D4-A65F-0040963251E5': 'Msxml2.ServerXMLHTTP.5.0',
    '88D969EA-F192-11D4-A65F-0040963251E5': 'Msxml2.XMLHTTP.5.0',
    '88D969E7-F192-11D4-A65F-0040963251E5': 'Msxml2.XMLSchemaCache.5.0',
    '88D969E8-F192-11D4-A65F-0040963251E5': 'Msxml2.XSLTemplate.5.0',
    '88D96A0C-F192-11D4-A65F-0040963251E5': 'SAX XML Reader 6.0 (msxml6.dll)',
    '8E75D913-3D21-11D2-85C4-080009A0C626': 'AutoCAD 2004-2006 Document',
    '9181DC5F-E07D-418A-ACA6-8EEA1ECB8E9E': 'MSCOMCTL.TreeCtrl (may trigger CVE-2012-0158)',
    '975797FC-4E2A-11D0-B702-00C04FD8DBF7': 'Loads ELSEXT.DLL (Known Related to CVE-2015-6128)',
    '978C9E23-D4B0-11CE-BF2D-00AA003F40D0': 'Microsoft Forms 2.0 Label (Forms.Label.1)',
    '996BF5E0-8044-4650-ADEB-0B013914E99C': 'MSCOMCTL.ListViewCtrl (may trigger CVE-2012-0158)',
    # Referenced in https://resources.sei.cmu.edu/library/asset-view.cfm?assetid=652438 :
    '9C38ED61-D565-4728-AEEE-C80952F0ECDE': 'Virtual Disk Service Loader - vdsldr.exe (related to MS Office click-to-run issue CVE-2021-27058)',
    'A08A033D-1A75-4AB6-A166-EAD02F547959': 'otkloadr WRAssembly Object (can be used to bypass ASLR after triggering an exploit)',
    'B54F3741-5B07-11CF-A4B0-00AA004A55E8': 'vbscript.dll - VB Script Language (ProgID: VBS, VBScript)',
    'B801CA65-A1FC-11D0-85AD-444553540000': 'Adobe Acrobat Document - PDF file',
    'BDD1F04B-858B-11D1-B16A-00C0F0283628': 'MSCOMCTL.ListViewCtrl (may trigger CVE-2012-0158)',
    'C08AFD90-F2A1-11D1-8455-00A0C91F3880': 'ShellBrowserWindow',
    'C62A69F0-16DC-11CE-9E98-00AA00574A4F': 'Forms.Form',
    'C74190B6-8589-11D1-B16A-00C0F0283628': 'MSCOMCTL.TreeCtrl (may trigger CVE-2012-0158)',
    'CCD068CD-1260-4AEA-B040-A87974EB3AEF': 'UmOutlookAddin.RoomsCTP (potential exploit document CVE-2016-0042 / MS16-014)',
    'CDDBCC7C-BE18-4A58-9CBF-D62A012272CE': 'osf.Sandbox (Known Related To CVE-2015-1770)',
    'CDF1C8AA-2D25-43C7-8AFE-01F73A3C66DA': 'UmOutlookAddin.InspectorContext (potential exploit document CVE-2016-0042 / MS16-014)',
    'CF4F55F4-8F87-4D47-80BB-5808164BB3F8': 'Microsoft Powerpoint.Show.12',
    'D27CDB6E-AE6D-11CF-96B8-444553540000': 'Shockwave Flash Object (may trigger many CVEs)',
    'D27CDB70-AE6D-11CF-96B8-444553540000': 'Shockwave Flash Object (may trigger many CVEs)',
    'D50FED35-0A08-4B17-B3E0-A8DD0EDE375D': 'UmOutlookAddin.PlayOnPhoneDlg (potential exploit document CVE-2016-0042 / MS16-014)',
    'D7053240-CE69-11CD-A777-00DD01143C57': 'Microsoft Forms 2.0 CommandButton',
    'D70E31AD-2614-49F2-B0FC-ACA781D81F3E': 'AutoCAD 2010-2012 Document',
    'D93CE8B5-3BF8-462C-A03F-DED2730078BA': 'Loads WUAEXT.DLL (Known Related to CVE-2015-6128)',
    'DD9DA666-8594-11D1-B16A-00C0F0283628': 'MSCOMCTL.ImageComboCtrl (may trigger CVE-2014-1761)',
    # Referenced in https://resources.sei.cmu.edu/library/asset-view.cfm?assetid=652438 :
    'DF630910-1C1D-11D0-AE36-8C0F5E000000': 'pythoncomloader27.dll (related to CVE-2021-27058)',
    'DFEAF541-F3E1-4C24-ACAC-99C30715084A': 'Silverlight Objects',
    'E5CA59F5-57C4-4DD8-9BD6-1DEEEDD27AF4': 'InkEd.InkEdit',
    'E8CC4CBE-FDFF-11D0-B865-00A0C9081C1D': 'MSDAORA.1 (potential exploit CVE TODO)', # TODO
    'E8CC4CBF-FDFF-11D0-B865-00A0C9081C1D': 'Loads OCI.DLL (Known Related to CVE-2015-6128)',
    # Referenced in https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-21509 :
    'EAB22AC3-30C1-11CF-A7EB-0000C05BAE0B': 'Shell.Explorer (Known Related to CVE-2026-21509)',
    'ECABAFC6-7F19-11D2-978E-0000F8757E2A': 'New Moniker',
    'ECABAFC9-7F19-11D2-978E-0000F8757E2A': 'Loads MQRT.DLL (Known Related to CVE-2015-6128)',
    'ECABB0C7-7F19-11D2-978E-0000F8757E2A': 'SOAP Moniker (may trigger CVE-2017-8759)',
    'ECF44975-786E-462F-B02A-CBCCB1A2C4A2': 'UmOutlookAddin.FormRegionContext (potential exploit document CVE-2016-0042 / MS16-014)',
    'F20DA720-C02F-11CE-927B-0800095AE340': 'OLE Package Object (may contain and run any file)',
    'F414C260-6AC0-11CF-B6D1-00AA00BBBB58': 'jscript.dll - JScript Language (ProgID: ECMAScript, JavaScript, JScript, LiveScript)',
    'F4754C9B-64F5-4B40-8AF4-679732AC0607': 'Microsoft Word Document (Word.Document.12)',
    'F959DBBB-3867-41F2-8E5F-3B8BEFAA81B3': 'UmOutlookAddin.FormRegionAddin (potential exploit document CVE-2016-0042 / MS16-014)',
}


# === EMBEDDED-OBJECT RISK GRADING ============================================
#
# Design principles (see also module docstring above):
# 1. A HIGH risk conclusion may only come from a curated, human-reviewed CLSID
#    table entry or an exact class-name rule. String similarity (e.g. a CLSID
#    that "looks like" a known-bad one) is never treated as evidence.
# 2. A CLSID that is well-formed but not present in any table is reported as
#    UNKNOWN with LOW confidence: the result is explicitly *unclassified*, not
#    "safe".
# 3. A malformed CLSID either raises MalformedClsidError (strict parsing API)
#    or yields an INVALID assessment with LOW confidence and an explanatory
#    error (lookup/assessment API); it can never be reported as safe.
# 4. Suspicious commands/scripts are matched by exact, word-boundary patterns
#    and can raise the grade at most to MEDIUM on their own.
# 5. All conclusions carry human-readable reasons, the evidence they are based
#    on, a confidence and the provenance (source) of the CLSID.

import re

# --- risk levels (observable, stable string values) -------------------------

RISK_HIGH = 'HIGH'
RISK_MEDIUM = 'MEDIUM'
RISK_LOW = 'LOW'
RISK_UNKNOWN = 'UNKNOWN'

RISK_LEVELS = (RISK_HIGH, RISK_MEDIUM, RISK_LOW, RISK_UNKNOWN)

# --- confidence levels -------------------------------------------------------

CONFIDENCE_HIGH = 'HIGH'
CONFIDENCE_MEDIUM = 'MEDIUM'
CONFIDENCE_LOW = 'LOW'

# --- CLSID provenance --------------------------------------------------------

CLSID_SOURCE_OLE_STORAGE = 'ole_storage_root'
CLSID_SOURCE_OLE1_HEADER = 'ole1_class_name'
CLSID_SOURCE_RTF_CONTROL = 'rtf_object_class'
CLSID_SOURCE_UNKNOWN = 'unknown'

# --- embedded object types ---------------------------------------------------

OBJECT_TYPE_EMBEDDED = 'embedded'
OBJECT_TYPE_LINKED = 'linked'
OBJECT_TYPE_PACKAGE = 'package'
OBJECT_TYPE_UNKNOWN = 'unknown'
OBJECT_TYPE_MALFORMED = 'malformed'


class MalformedClsidError(ValueError):
    """
    Raised by parse_clsid() when a value cannot be interpreted as a CLSID.

    A malformed value must never silently become a "safe" result: callers that
    need non-raising behaviour should use lookup_clsid() / assess_clsid(),
    which return an INVALID/LOW-confidence assessment instead.
    """


# Canonical CLSID format: 8-4-4-4-12 hex digits, without braces.
# Only exact, structural validation is performed - no fuzzy matching.
_CLSID_RE = re.compile(
    r'^[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-'
    r'[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}$')

# Same structural check applied to the brace-wrapped registry representation.
_CLSID_BRACED_RE = re.compile(
    r'^\{[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-'
    r'[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}\}$')


def parse_clsid(value):
    """
    Validate and normalize a CLSID string to its canonical uppercase form.

    Accepts the plain form (``xxxxxxxx-...``) and the brace-wrapped registry
    form (``{xxxxxxxx-...}``), with surrounding whitespace and any mixture of
    upper/lower case. No other normalization (and no fuzzy matching) is done.

    :param value: CLSID as str (bytes are decoded as latin-1 first)
    :return: canonical CLSID string, uppercase, without braces
    :raises MalformedClsidError: if value is None, not a string, empty or does
             not match the CLSID structure exactly
    """
    if value is None:
        raise MalformedClsidError('CLSID is None')
    if isinstance(value, bytes):
        try:
            value = value.decode('latin-1')
        except UnicodeDecodeError as exc:
            raise MalformedClsidError(
                'CLSID is not decodable text: {!r}'.format(value)) from exc
    if not isinstance(value, str):
        raise MalformedClsidError(
            'CLSID is not a string: {!r}'.format(type(value)))
    text = value.strip()
    if not text:
        raise MalformedClsidError('CLSID is an empty string')
    if text.startswith('{') or text.endswith('}'):
        if not _CLSID_BRACED_RE.match(text):
            raise MalformedClsidError(
                'Malformed brace-wrapped CLSID: {!r}'.format(value))
        text = text[1:-1]
    if not _CLSID_RE.match(text):
        raise MalformedClsidError(
            'Malformed CLSID, expected 8-4-4-4-12 hex digits: {!r}'
            .format(value))
    return text.upper()


# --- curated risk tables -----------------------------------------------------
#
# Each entry maps a canonical (uppercase) CLSID to a (category, reason) tuple.
# Categories are stable machine-readable codes; reasons are human-readable
# explanations. Entries are derived strictly from the curated descriptions in
# KNOWN_CLSIDS (documented CVEs or clearly dangerous activation/capability),
# never from resemblance between CLSID strings.
#
# Categories:
#   moniker_activation : monikers able to activate remote/scripted content
#   script_host        : script engines / script controls
#   exploited_control  : ActiveX/OLE controls with documented CVEs
#   exploit_helper     : exploit helpers (ASLR bypass, DLL side-loading, ...)
#   package_lnk        : OLE Package objects and Windows shortcut files
#   document_macro     : macro-enabled Office document classes

CATEGORY_MONIKER = 'moniker_activation'
CATEGORY_SCRIPT_HOST = 'script_host'
CATEGORY_EXPLOITED_CONTROL = 'exploited_control'
CATEGORY_EXPLOIT_HELPER = 'exploit_helper'
CATEGORY_PACKAGE_LNK = 'package_lnk'
CATEGORY_DOCUMENT_MACRO = 'document_macro'


HIGH_RISK_CLSIDS = {
    # Monikers used by the CVE-2017-0199 / CVE-2017-8570 / CVE-2018-8174
    # remote-template and scriptlet activation chains:
    '00000300-0000-0000-C000-000000000046': (
        CATEGORY_MONIKER,
        'StdOleLink embedded OLE object, known related to CVE-2017-0199, '
        'CVE-2017-8570, CVE-2017-8759 or CVE-2018-8174'),
    '00000303-0000-0000-C000-000000000046': (
        CATEGORY_MONIKER,
        'File Moniker, may trigger CVE-2017-0199 or CVE-2017-8570'),
    '00000309-0000-0000-C000-000000000046': (
        CATEGORY_MONIKER,
        'Composite Moniker, may trigger CVE-2017-8570'),
    '06290BD2-48AA-11D2-8432-006008C3FBFC': (
        CATEGORY_MONIKER,
        'Factory bindable using IPersistMoniker (scripletfile)'),
    '06290BD3-48AA-11D2-8432-006008C3FBFC': (
        CATEGORY_MONIKER,
        'Script Moniker to a Windows Script Component, may trigger '
        'CVE-2017-0199'),
    '3050F4D8-98B5-11CF-BB82-00AA00BDCE0B': (
        CATEGORY_MONIKER,
        'HTML Application moniker, may trigger CVE-2017-0199'),
    '4315D437-5B8C-11D0-BD3B-00A0C911CE86': (
        CATEGORY_MONIKER,
        'Device Moniker, known related to CVE-2016-0015'),
    '79EAC9E0-BAF9-11CE-8C82-00AA004BA90B': (
        CATEGORY_MONIKER,
        'URL Moniker, may trigger CVE-2017-0199, CVE-2017-8570 or '
        'CVE-2018-8174'),
    'ECABB0C7-7F19-11D2-978E-0000F8757E2A': (
        CATEGORY_MONIKER,
        'SOAP Moniker, may trigger CVE-2017-8759'),

    # Script engines and script controls enabling in-document code execution:
    '00000535-0000-0010-8000-00AA006D2EA4': (
        CATEGORY_SCRIPT_HOST,
        'ADODB.RecordSet, may trigger CVE-2015-0097'),
    '0E59F1D5-1FBE-11D0-8FF2-00A0D10038BC': (
        CATEGORY_SCRIPT_HOST,
        'MSScriptControl.ScriptControl, may trigger CVE-2015-0097'),
    '0D43FE01-F093-11CF-8940-00A0C9054228': (
        CATEGORY_SCRIPT_HOST,
        'Scripting.FileSystemObject provides file-system access from scripts'),
    'B54F3741-5B07-11CF-A4B0-00AA004A55E8': (
        CATEGORY_SCRIPT_HOST,
        'VBScript language engine (vbscript.dll)'),
    'F414C260-6AC0-11CF-B6D1-00AA00BBBB58': (
        CATEGORY_SCRIPT_HOST,
        'JScript language engine (jscript.dll)'),

    # Controls/classes with documented exploitation (CVE references):
    '00021700-0000-0000-C000-000000000046': (
        CATEGORY_EXPLOITED_CONTROL,
        'Microsoft Equation 2.0, known related to CVE-2017-11882 or '
        'CVE-2018-0802'),
    '0002CE02-0000-0000-C000-000000000046': (
        CATEGORY_EXPLOITED_CONTROL,
        'Microsoft Equation 3.0, known related to CVE-2017-11882 or '
        'CVE-2018-0802'),
    '0003000B-0000-0000-C000-000000000046': (
        CATEGORY_EXPLOITED_CONTROL,
        'Microsoft Equation, known related to CVE-2017-11882 or '
        'CVE-2018-0802'),
    '0004A6B0-0000-0000-C000-000000000046': (
        CATEGORY_EXPLOITED_CONTROL,
        'Microsoft Equation 2.0, known related to CVE-2017-11882 or '
        'CVE-2018-0802'),
    '1461A561-24E8-4BA3-8D4A-FFEEF980556B': (
        CATEGORY_EXPLOITED_CONTROL,
        'BCSAddin.Connect, potential exploit CVE-2016-0042 / MS16-014'),
    '1EFB6596-857C-11D1-B16A-00C0F0283628': (
        CATEGORY_EXPLOITED_CONTROL,
        'MSCOMCTL.TabStrip, may trigger CVE-2012-1856 or CVE-2013-3906, '
        'often used for heap spray'),
    '233C1507-6A77-46A4-9443-F871F945D258': (
        CATEGORY_EXPLOITED_CONTROL,
        'Shockwave Control Object'),
    '29131539-2EED-1069-BF5D-00DD011186B7': (
        CATEGORY_EXPLOITED_CONTROL,
        'IBM/Lotus Notes COM interface (NLSXBE.DLL), related to '
        'CVE-2021-27058'),
    '33BD73C2-7BB4-48F4-8DBC-82B8B313AE16': (
        CATEGORY_EXPLOITED_CONTROL,
        'osf.SandboxManager, known related to CVE-2015-1770'),
    '394C052E-B830-11D0-9A86-00C04FD8DBF7': (
        CATEGORY_EXPLOIT_HELPER,
        'Loads ELSEXT.DLL, known related to CVE-2015-6128'),
    '3BA59FA5-41BF-4820-98E4-04645A806698': (
        CATEGORY_EXPLOITED_CONTROL,
        'osf.SandboxContent, known related to CVE-2015-1770'),
    '44F9A03B-A3EC-4F3B-9364-08E0007F21DF': (
        CATEGORY_EXPLOITED_CONTROL,
        'Control.TaskSymbol, known related to CVE-2015-1642 and '
        'CVE-2015-2424'),
    '4C599241-6926-101B-9992-00000B65C6F9': (
        CATEGORY_EXPLOITED_CONTROL,
        'Forms.Image, may trigger CVE-2015-2424'),
    '66833FE6-8583-11D1-B16A-00C0F0283628': (
        CATEGORY_EXPLOITED_CONTROL,
        'MSCOMCTL.Toolbar, known related to CVE-2012-0158 and CVE-2012-1856'),
    '6AD4AE40-2FF1-4D88-B27A-F76FC7B40440': (
        CATEGORY_EXPLOITED_CONTROL,
        'BCSAddin.ManageSolutionHelper, potential exploit CVE-2016-0042 / '
        'MS16-014'),
    '799ED9EA-FB5E-11D1-B7D6-00C04FC2AAE2': (
        CATEGORY_EXPLOITED_CONTROL,
        'Microsoft.VbaAddin, known related to CVE-2016-0042'),
    '8627E73B-B5AA-4643-A3B0-570EDA17E3E7': (
        CATEGORY_EXPLOITED_CONTROL,
        'UmOutlookAddin.ButtonBar, potential exploit CVE-2016-0042 / '
        'MS16-014'),
    '9181DC5F-E07D-418A-ACA6-8EEA1ECB8E9E': (
        CATEGORY_EXPLOITED_CONTROL,
        'MSCOMCTL.TreeCtrl, may trigger CVE-2012-0158'),
    '975797FC-4E2A-11D0-B702-00C04FD8DBF7': (
        CATEGORY_EXPLOIT_HELPER,
        'Loads ELSEXT.DLL, known related to CVE-2015-6128'),
    '996BF5E0-8044-4650-ADEB-0B013914E99C': (
        CATEGORY_EXPLOITED_CONTROL,
        'MSCOMCTL.ListViewCtrl, may trigger CVE-2012-0158'),
    '9C38ED61-D565-4728-AEEE-C80952F0ECDE': (
        CATEGORY_EXPLOIT_HELPER,
        'Virtual Disk Service Loader (vdsldr.exe), related to CVE-2021-27058'),
    'BDD1F04B-858B-11D1-B16A-00C0F0283628': (
        CATEGORY_EXPLOITED_CONTROL,
        'MSCOMCTL.ListViewCtrl, may trigger CVE-2012-0158'),
    'C74190B6-8589-11D1-B16A-00C0F0283628': (
        CATEGORY_EXPLOITED_CONTROL,
        'MSCOMCTL.TreeCtrl, may trigger CVE-2012-0158'),
    'CCD068CD-1260-4AEA-B040-A87974EB3AEF': (
        CATEGORY_EXPLOITED_CONTROL,
        'UmOutlookAddin.RoomsCTP, potential exploit CVE-2016-0042 / '
        'MS16-014'),
    'CDDBCC7C-BE18-4A58-9CBF-D62A012272CE': (
        CATEGORY_EXPLOITED_CONTROL,
        'osf.Sandbox, known related to CVE-2015-1770'),
    'CDF1C8AA-2D25-43C7-8AFE-01F73A3C66DA': (
        CATEGORY_EXPLOITED_CONTROL,
        'UmOutlookAddin.InspectorContext, potential exploit CVE-2016-0042 / '
        'MS16-014'),
    'D27CDB6E-AE6D-11CF-96B8-444553540000': (
        CATEGORY_EXPLOITED_CONTROL,
        'Shockwave Flash Object, may trigger many CVEs'),
    'D27CDB70-AE6D-11CF-96B8-444553540000': (
        CATEGORY_EXPLOITED_CONTROL,
        'Shockwave Flash Object, may trigger many CVEs'),
    'D50FED35-0A08-4B17-B3E0-A8DD0EDE375D': (
        CATEGORY_EXPLOITED_CONTROL,
        'UmOutlookAddin.PlayOnPhoneDlg, potential exploit CVE-2016-0042 / '
        'MS16-014'),
    'D93CE8B5-3BF8-462C-A03F-DED2730078BA': (
        CATEGORY_EXPLOIT_HELPER,
        'Loads WUAEXT.DLL, known related to CVE-2015-6128'),
    'DD9DA666-8594-11D1-B16A-00C0F0283628': (
        CATEGORY_EXPLOITED_CONTROL,
        'MSCOMCTL.ImageComboCtrl, may trigger CVE-2014-1761'),
    'DF630910-1C1D-11D0-AE36-8C0F5E000000': (
        CATEGORY_EXPLOIT_HELPER,
        'pythoncomloader27.dll, related to CVE-2021-27058'),
    'EAB22AC3-30C1-11CF-A7EB-0000C05BAE0B': (
        CATEGORY_EXPLOITED_CONTROL,
        'Shell.Explorer, known related to CVE-2026-21509'),
    'ECABAFC9-7F19-11D2-978E-0000F8757E2A': (
        CATEGORY_EXPLOIT_HELPER,
        'Loads MQRT.DLL, known related to CVE-2015-6128'),
    'ECF44975-786E-462F-B02A-CBCCB1A2C4A2': (
        CATEGORY_EXPLOITED_CONTROL,
        'UmOutlookAddin.FormRegionContext, potential exploit CVE-2016-0042 / '
        'MS16-014'),
    'E8CC4CBF-FDFF-11D0-B865-00A0C9081C1D': (
        CATEGORY_EXPLOIT_HELPER,
        'Loads OCI.DLL, known related to CVE-2015-6128'),
    'F959DBBB-3867-41F2-8E5F-3B8BEFAA81B3': (
        CATEGORY_EXPLOITED_CONTROL,
        'UmOutlookAddin.FormRegionAddin, potential exploit CVE-2016-0042 / '
        'MS16-014'),
}


MEDIUM_RISK_CLSIDS = {
    # OLE Package objects can wrap and run arbitrary files:
    '00020C01-0000-0000-C000-000000000046': (
        CATEGORY_PACKAGE_LNK,
        'OLE Package Object, may contain and run any file'),
    '00022601-0000-0000-C000-000000000046': (
        CATEGORY_PACKAGE_LNK,
        'OLE Package Object, may contain and run any file'),
    '00022602-0000-0000-C000-000000000046': (
        CATEGORY_PACKAGE_LNK,
        'OLE Package Object, may contain and run any file'),
    '00022603-0000-0000-C000-000000000046': (
        CATEGORY_PACKAGE_LNK,
        'OLE Package Object, may contain and run any file'),
    '0003000C-0000-0000-C000-000000000046': (
        CATEGORY_PACKAGE_LNK,
        'OLE Package Object, may contain and run any file'),
    '0003000D-0000-0000-C000-000000000046': (
        CATEGORY_PACKAGE_LNK,
        'OLE Package Object, may contain and run any file'),
    '0003000E-0000-0000-C000-000000000046': (
        CATEGORY_PACKAGE_LNK,
        'OLE Package Object, may contain and run any file'),
    'F20DA720-C02F-11CE-927B-0800095AE340': (
        CATEGORY_PACKAGE_LNK,
        'OLE Package Object, may contain and run any file'),
    # Windows shortcut files can point at arbitrary executables:
    '00021401-0000-0000-C000-000000000046': (
        CATEGORY_PACKAGE_LNK,
        'Windows LNK Shortcut file'),
    # Macro-enabled Office document classes:
    '00020832-0000-0000-C000-000000000046': (
        CATEGORY_DOCUMENT_MACRO,
        'Excel.SheetMacroEnabled.12, macro-enabled worksheet'),
    '00020833-0000-0000-C000-000000000046': (
        CATEGORY_DOCUMENT_MACRO,
        'Excel.SheetBinaryMacroEnabled.12, macro-enabled binary worksheet'),
    '18A06B6B-2F3F-4E2B-A611-52BE631B2D22': (
        CATEGORY_DOCUMENT_MACRO,
        'Word.DocumentMacroEnabled.12 (DOCM), macro-enabled document'),
    # Exploit helpers without a direct payload capability:
    '05741520-C4EB-440A-AC3F-9643BBC9F847': (
        CATEGORY_EXPLOIT_HELPER,
        'otkloadr.WRLoader, can be used to bypass ASLR after triggering an '
        'exploit'),
    '14CE31DC-ABC2-484C-B061-CF3416AED8FF': (
        CATEGORY_EXPLOIT_HELPER,
        'Loads WUAEXT.DLL, known related to CVE-2015-6128'),
    '23CE100B-1390-49D6-BA00-F17D3AEE149C': (
        CATEGORY_EXPLOITED_CONTROL,
        'UmOutlookAddin.UmEvmCtrl, potential exploit CVE-2016-0042 / '
        'MS16-014'),
    '3018609E-CDBC-47E8-A255-809D46BAA319': (
        CATEGORY_EXPLOIT_HELPER,
        'SSCE DropTable Listener Object, can be used to bypass ASLR after '
        'triggering an exploit'),
    '41B9BE05-B3AF-460C-BF0B-2CDD44A093B1': (
        CATEGORY_EXPLOITED_CONTROL,
        'Search.XmlContentFilter, potential exploit document'),
    'A08A033D-1A75-4AB6-A166-EAD02F547959': (
        CATEGORY_EXPLOIT_HELPER,
        'otkloadr WRAssembly Object, can be used to bypass ASLR after '
        'triggering an exploit'),
    'DFEAF541-F3E1-4C24-ACAC-99C30715084A': (
        CATEGORY_EXPLOITED_CONTROL,
        'Silverlight Object, historical exploitation surface'),
    'E8CC4CBE-FDFF-11D0-B865-00A0C9081C1D': (
        CATEGORY_EXPLOITED_CONTROL,
        'MSDAORA.1, potential exploit (unconfirmed CVE)'),
}


def _validate_risk_tables():
    """
    Import-time sanity checks for the curated risk tables.

    The tables must reference valid, canonical CLSIDs that exist in
    KNOWN_CLSIDS, and the HIGH and MEDIUM tables must be disjoint. This turns
    typos and duplicated classifications into immediate import errors instead
    of silent misclassification.
    """
    for table_name, table in (('HIGH_RISK_CLSIDS', HIGH_RISK_CLSIDS),
                              ('MEDIUM_RISK_CLSIDS', MEDIUM_RISK_CLSIDS)):
        for clsid_key, entry in table.items():
            # canonical form and valid structure:
            if clsid_key != parse_clsid(clsid_key):
                raise AssertionError(
                    '%s contains non-canonical CLSID %r'
                    % (table_name, clsid_key))
            if clsid_key not in KNOWN_CLSIDS:
                raise AssertionError(
                    '%s contains %r which is absent from KNOWN_CLSIDS'
                    % (table_name, clsid_key))
            if (not isinstance(entry, tuple) or len(entry) != 2
                    or not all(isinstance(part, str) and part
                               for part in entry)):
                raise AssertionError(
                    '%s[%r] must be a non-empty (category, reason) str tuple'
                    % (table_name, clsid_key))
    overlap = set(HIGH_RISK_CLSIDS) & set(MEDIUM_RISK_CLSIDS)
    if overlap:
        raise AssertionError(
            'CLSIDs present in both risk tables: %s' % sorted(overlap))


_validate_risk_tables()


# --- suspicious command / script indicators ----------------------------------
#
# Exact, word-boundary patterns only. Matching is case-insensitive. These
# indicators describe *techniques*, not a verdict by themselves: a hit raises
# the grade to at most MEDIUM unless a curated HIGH-risk CLSID is present.
# Each pattern carries a stable indicator id and an explanation.

_SUSPICIOUS_PATTERNS = (
    ('powershell_exec',
     re.compile(r'\bpowershell(?:\.exe)?\b', re.IGNORECASE),
     'PowerShell interpreter reference'),
    ('cmd_exec',
     re.compile(r'\bcmd(?:\.exe)?\b', re.IGNORECASE),
     'Windows command shell reference'),
    ('wscript_exec',
     re.compile(r'\bwscript(?:\.exe)?\b', re.IGNORECASE),
     'Windows Script Host reference'),
    ('cscript_exec',
     re.compile(r'\bcscript(?:\.exe)?\b', re.IGNORECASE),
     'Windows Script Host console reference'),
    ('mshta_exec',
     re.compile(r'\bmshta(?:\.exe)?\b', re.IGNORECASE),
     'MSHTA HTML application host reference'),
    ('rundll32_exec',
     re.compile(r'\brundll32(?:\.exe)?\b', re.IGNORECASE),
     'rundll32 helper reference'),
    ('regsvr32_exec',
     re.compile(r'\bregsvr32(?:\.exe)?\b', re.IGNORECASE),
     'regsvr32 COM registration reference'),
    ('certutil_exec',
     re.compile(r'\bcertutil(?:\.exe)?\b', re.IGNORECASE),
     'certutil reference (often used to decode/download payloads)'),
    ('wmic_exec',
     re.compile(r'\bwmic(?:\.exe)?\b', re.IGNORECASE),
     'WMI command line reference'),
    ('script_sct',
     re.compile(r'\.sct\b', re.IGNORECASE),
     'Windows scriptlet file extension'),
    ('script_vbs',
     re.compile(r'\.vbs(?:\b|$)', re.IGNORECASE),
     'VBScript file extension'),
    ('script_js',
     re.compile(r'\.js(?:\b|$)', re.IGNORECASE),
     'JScript file extension'),
    ('script_ps1',
     re.compile(r'\.ps1(?:\b|$)', re.IGNORECASE),
     'PowerShell script file extension'),
    ('download_cradle',
     re.compile(r'\b(?:downloadstring|downloadfile|downloaddata)\b',
                re.IGNORECASE),
     'web client download method'),
    ('createobject_call',
     re.compile(r'\bcreateobject\b', re.IGNORECASE),
     'late-bound COM object instantiation'),
    ('wscript_shell',
     re.compile(r'\bwscript\.shell\b', re.IGNORECASE),
     'WScript.Shell programmatic execution object'),
    ('shell_exec',
     re.compile(r'\bshell\.(?:exec|run)\b', re.IGNORECASE),
     'programmatic command execution call'),
    ('invoke_expression',
     re.compile(r'\binvoke-expression\b', re.IGNORECASE),
     'PowerShell dynamic code execution'),
    ('encoded_command',
     re.compile(r'(?:^|\s)-(?:e|enc|encodedcommand)\b', re.IGNORECASE),
     'PowerShell encoded-command switch'),
    ('mhtml_scheme',
     re.compile(r'\bmhtml:', re.IGNORECASE),
     'mhtml URI scheme (CVE-2021-40444 abuse)'),
)


def find_suspicious_indicators(data):
    """
    Find exact, word-boundary suspicious command/script indicators in data.

    :param data: text (str) or bytes to inspect; bytes are decoded latin-1 so
                 the scan never raises on arbitrary embedded content
    :return: tuple of dicts, each with keys id, match (the matched text),
             offset (character offset) and reason, ordered by offset. The same
             indicator id appears at most once, at its first match.
    """
    if data is None:
        return ()
    if isinstance(data, bytes):
        text = data.decode('latin-1', errors='replace')
    elif isinstance(data, str):
        text = data
    else:
        raise TypeError('expected str or bytes, got %r' % type(data))
    findings = []
    seen_ids = set()
    for indicator_id, pattern, reason in _SUSPICIOUS_PATTERNS:
        match = pattern.search(text)
        if match is not None:
            seen_ids.add(indicator_id)
            findings.append({
                'id': indicator_id,
                'match': match.group(0),
                'offset': match.start(),
                'reason': reason,
            })
    return tuple(sorted(findings, key=lambda item: item['offset']))


# Exact class-name rules (case-insensitive, whole-string comparison only).
# These mirror long-standing rtfobj detections; no prefix/fuzzy matching beyond
# the explicitly documented prefix below.
_CLASS_NAME_EXACT_HIGH = {
    'ole2link': (
        CATEGORY_MONIKER,
        'OLE2Link class, possibly an exploit for CVE-2017-0199 (VU#921560)'),
}
# Explicit, documented prefix rule for the Equation Editor family
# (rtfobj historically flags class names starting with "equation.3").
_CLASS_NAME_PREFIX_HIGH = (
    ('equation.3',
     (CATEGORY_EXPLOITED_CONTROL,
      'Equation Editor class, possibly an exploit for CVE-2017-11882 '
      '(VU#421280)')),
)
_CLASS_NAME_EXACT_MEDIUM = {
    'package': (
        CATEGORY_PACKAGE_LNK,
        'OLE Package class, may contain and run arbitrary files'),
}


def _assess_class_name(class_name):
    """
    Evaluate an OLE 1.0 class name with exact matching rules.

    :param class_name: str/bytes class name or None
    :return: (risk, confidence, category, reason) or None when no rule matches
    """
    if class_name is None:
        return None
    if isinstance(class_name, bytes):
        class_name = class_name.decode('latin-1', errors='replace')
    if not isinstance(class_name, str):
        return None
    name = class_name.strip().rstrip('\x00').lower()
    if not name:
        return None
    if name in _CLASS_NAME_EXACT_HIGH:
        category, reason = _CLASS_NAME_EXACT_HIGH[name]
        return RISK_HIGH, CONFIDENCE_MEDIUM, category, reason
    for prefix, result in _CLASS_NAME_PREFIX_HIGH:
        if name.startswith(prefix):
            category, reason = result
            return RISK_HIGH, CONFIDENCE_MEDIUM, category, reason
    if name in _CLASS_NAME_EXACT_MEDIUM:
        category, reason = _CLASS_NAME_EXACT_MEDIUM[name]
        return RISK_MEDIUM, CONFIDENCE_MEDIUM, category, reason
    return None


class ClsidAssessment(object):
    """
    Explainable result of identifying and grading a single CLSID.

    Attributes:
      clsid:      canonical uppercase CLSID, or None when invalid/absent
      raw_clsid:  original value as provided (str) or None
      valid:      True when the value matched the CLSID structure exactly
      error:      None or an explanation of why parsing failed
      known:      True when present in KNOWN_CLSIDS (only meaningful if valid)
      risk:       one of RISK_*
      confidence: one of CONFIDENCE_*
      category:   stable machine-readable category code, or None
      reason:     human-readable explanation (never empty)
      source:     provenance of the CLSID, one of the CLSID_SOURCE_* constants
      description: KNOWN_CLSIDS description when available
    """

    def __init__(self, raw_clsid=None, source=CLSID_SOURCE_UNKNOWN):
        self.raw_clsid = raw_clsid
        self.source = source
        self.clsid = None
        self.valid = False
        self.error = None
        self.known = False
        self.risk = RISK_UNKNOWN
        self.confidence = CONFIDENCE_LOW
        self.category = None
        self.reason = ''
        self.description = None
        if raw_clsid is None:
            self.error = 'no CLSID provided'
            self.reason = 'No CLSID available, object cannot be classified ' \
                          'from a CLSID'
            return
        try:
            canonical = parse_clsid(raw_clsid)
        except MalformedClsidError as exc:
            self.error = str(exc)
            self.reason = ('Invalid CLSID structure (%s); the object must not '
                           'be treated as safe' % self.error)
            return
        self.valid = True
        self.clsid = canonical
        self.description = KNOWN_CLSIDS.get(canonical)
        self.known = self.description is not None
        if canonical in HIGH_RISK_CLSIDS:
            self.category, self.reason = HIGH_RISK_CLSIDS[canonical]
            self.risk = RISK_HIGH
            self.confidence = CONFIDENCE_HIGH
        elif canonical in MEDIUM_RISK_CLSIDS:
            self.category, self.reason = MEDIUM_RISK_CLSIDS[canonical]
            self.risk = RISK_MEDIUM
            self.confidence = CONFIDENCE_HIGH
        elif self.known:
            self.risk = RISK_LOW
            self.confidence = CONFIDENCE_HIGH
            self.reason = ('Known, benign object class per curated CLSID '
                           'database: %s' % self.description)
        else:
            # Well-formed but unknown: explicitly unclassified, NOT safe.
            self.risk = RISK_UNKNOWN
            self.confidence = CONFIDENCE_LOW
            self.reason = ('Well-formed CLSID absent from the curated '
                           'database; unclassified and not proven safe')

    def as_dict(self):
        """Return a plain dict suitable for JSON/log serialization."""
        return {
            'clsid': self.clsid,
            'raw_clsid': self.raw_clsid,
            'valid': self.valid,
            'error': self.error,
            'known': self.known,
            'risk': self.risk,
            'confidence': self.confidence,
            'category': self.category,
            'reason': self.reason,
            'source': self.source,
            'description': self.description,
        }

    def __repr__(self):
        return 'ClsidAssessment(clsid=%r, risk=%r, confidence=%r)' % (
            self.clsid, self.risk, self.confidence)


def lookup_clsid(clsid_value, source=CLSID_SOURCE_UNKNOWN):
    """
    Non-raising CLSID lookup/grading entry point.

    Unlike parse_clsid(), this never raises: malformed input yields an
    INVALID (risk UNKNOWN, confidence LOW) assessment carrying an explanatory
    error, so callers cannot accidentally treat garbage as safe.

    :param clsid_value: raw CLSID (str/bytes), or None
    :param source: provenance constant from CLSID_SOURCE_*
    :return: ClsidAssessment
    """
    return ClsidAssessment(clsid_value, source=source)


def assess_clsid(clsid_value, source=CLSID_SOURCE_UNKNOWN):
    """Alias of lookup_clsid() naming the grading semantics explicitly."""
    return lookup_clsid(clsid_value, source=source)


_RISK_ORDER = {RISK_LOW: 0, RISK_UNKNOWN: 1, RISK_MEDIUM: 2, RISK_HIGH: 3}
_CONFIDENCE_ORDER = {CONFIDENCE_LOW: 0, CONFIDENCE_MEDIUM: 1,
                     CONFIDENCE_HIGH: 2}


def _max_risk(current, candidate):
    """Return the more severe of two RISK_* values."""
    if _RISK_ORDER[candidate] > _RISK_ORDER[current]:
        return candidate
    return current


class EmbeddedObjectRiskAssessment(object):
    """
    Explainable risk grade for an embedded object.

    The grade combines three independent evidence kinds, exactly as required:
      * object type (embedded / linked / package / malformed / unknown),
      * CLSID provenance and curated CLSID risk table,
      * suspicious command/script indicators and exact class-name rules.

    Attributes:
      risk, confidence: overall verdict and its confidence
      object_type:     one of the OBJECT_TYPE_* constants
      clsid_assessment: ClsidAssessment instance (always present)
      indicators:      tuple of indicator dicts from
                       find_suspicious_indicators()
      reasons:         tuple of human-readable evidence strings supporting
                       the verdict
    """

    def __init__(self, risk, confidence, object_type, clsid_assessment,
                 indicators, reasons):
        self.risk = risk
        self.confidence = confidence
        self.object_type = object_type
        self.clsid_assessment = clsid_assessment
        self.indicators = tuple(indicators)
        self.reasons = tuple(reasons)

    @property
    def clsid(self):
        """Canonical CLSID string or None when absent/invalid."""
        return self.clsid_assessment.clsid

    def as_dict(self):
        """Plain dict serialization, including the nested CLSID assessment."""
        return {
            'risk': self.risk,
            'confidence': self.confidence,
            'object_type': self.object_type,
            'clsid': self.clsid_assessment.as_dict(),
            'indicators': list(self.indicators),
            'reasons': list(self.reasons),
        }

    def summary(self):
        """One-line human-readable summary of the verdict."""
        return 'risk=%s confidence=%s type=%s' % (
            self.risk, self.confidence, self.object_type)

    def __repr__(self):
        return ('EmbeddedObjectRiskAssessment(risk=%r, confidence=%r, '
                'object_type=%r)' % (self.risk, self.confidence,
                                     self.object_type))


def assess_embedded_object(clsid=None, class_name=None, object_type=None,
                           indicators_data=None,
                           clsid_source=CLSID_SOURCE_UNKNOWN):
    """
    Grade the risk of an embedded OLE object from structured evidence.

    :param clsid: raw CLSID value as found in the file (any case, braced or
                  not), or None when absent
    :param class_name: OLE 1.0 class name (str/bytes), or None
    :param object_type: one of OBJECT_TYPE_*; defaults to OBJECT_TYPE_UNKNOWN
    :param indicators_data: bytes/str content scanned for suspicious commands
                  and scripts (e.g. native stream or OLE1 object data); None
                  skips the scan
    :param clsid_source: provenance constant from CLSID_SOURCE_*
    :return: EmbeddedObjectRiskAssessment

    Verdict rules:
      * malformed object type or invalid CLSID -> never LOW/safe; at best
        UNKNOWN/LOW confidence with an explicit error reason;
      * curated HIGH-risk CLSID -> HIGH/HIGH;
      * exact OLE2Link/Equation class-name rules -> HIGH/MEDIUM;
      * curated MEDIUM-risk CLSID, package/linked type, or suspicious
        indicators -> at least MEDIUM;
      * known benign CLSID without other evidence -> LOW/HIGH;
      * well-formed unknown CLSID without other evidence -> UNKNOWN/LOW.
    """
    if object_type is None:
        object_type = OBJECT_TYPE_UNKNOWN
    if object_type not in (OBJECT_TYPE_EMBEDDED, OBJECT_TYPE_LINKED,
                           OBJECT_TYPE_PACKAGE, OBJECT_TYPE_UNKNOWN,
                           OBJECT_TYPE_MALFORMED):
        raise ValueError('unknown object_type %r' % (object_type,))

    clsid_info = lookup_clsid(clsid, source=clsid_source)
    indicators = find_suspicious_indicators(indicators_data)
    reasons = []

    # --- malformed container / invalid CLSID: never report as safe ----------
    if object_type == OBJECT_TYPE_MALFORMED:
        reasons.append('Object is not a well-formed OLE object')
    if not clsid_info.valid and clsid is not None:
        reasons.append(clsid_info.reason)

    # --- start from the CLSID verdict ---------------------------------------
    risk = clsid_info.risk
    confidence = clsid_info.confidence
    if clsid_info.valid:
        reasons.append('CLSID %s: %s' % (clsid_info.clsid, clsid_info.reason))

    # --- exact class-name rules ---------------------------------------------
    name_result = _assess_class_name(class_name)
    if name_result is not None:
        name_risk, name_conf, name_category, name_reason = name_result
        reasons.append('class name %r: %s' % (class_name, name_reason))
        risk = _max_risk(risk, name_risk)
        confidence = max(confidence, name_conf,
                         key=lambda value: _CONFIDENCE_ORDER[value])

    # --- object type evidence -----------------------------------------------
    if object_type == OBJECT_TYPE_PACKAGE:
        reasons.append('OLE Package object can wrap and execute arbitrary '
                       'files')
        risk = _max_risk(risk, RISK_MEDIUM)
    elif object_type == OBJECT_TYPE_LINKED:
        reasons.append('Linked object references external content')
        # a link alone is suspicious but not as strong as a package:
        risk = _max_risk(risk, RISK_MEDIUM)

    # --- suspicious command / script indicators -----------------------------
    if indicators:
        ids_text = ', '.join(sorted({item['id'] for item in indicators}))
        reasons.append('Suspicious command/script indicators: %s' % ids_text)
        # indicators alone cap at MEDIUM by design:
        risk = _max_risk(risk, RISK_MEDIUM)

    # --- hard safety guard: anything invalid/unknown cannot be LOW ----------
    # The verdict is forced away from LOW, but an existing strong conclusion
    # (e.g. an exact OLE2Link/Equation class-name rule) keeps its confidence.
    # Only an object whose evidence is itself weak is pushed to LOW confidence.
    if (object_type == OBJECT_TYPE_MALFORMED
            or (clsid is not None and not clsid_info.valid)):
        if risk == RISK_LOW:
            risk = RISK_UNKNOWN
        if risk != RISK_HIGH:
            confidence = CONFIDENCE_LOW
        if not reasons:
            reasons.append('Malformed or unparseable evidence, cannot '
                           'establish safety')

    if not reasons:
        if clsid_info.valid and clsid_info.known:
            reasons.append('Known benign object class with no suspicious '
                           'command, script or linkage evidence')
        else:
            reasons.append('No risk evidence found, and no positive benign '
                           'identification was possible either; result stays '
                           'unclassified, not proven safe')

    return EmbeddedObjectRiskAssessment(
        risk=risk,
        confidence=confidence,
        object_type=object_type,
        clsid_assessment=clsid_info,
        indicators=indicators,
        reasons=reasons)

