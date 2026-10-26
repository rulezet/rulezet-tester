"""
File types recognised from their first bytes — never from their name only, never by running
anything. Used to build sample sets ("the PDF and Office documents of /usr/share", later "the
pcaps of a folder" for Suricata) and to label samples.

    detect(head) -> 'pe' | 'elf' | 'pdf' | ... | None      head = the first HEAD_BYTES of a file
    detect_file(path) -> same, reading only the head of the file

Adding a type: one entry in TYPES (name, description, check, usual extensions). The extensions
only narrow a folder walk (cheap); the check on the bytes always decides.
"""
import struct

HEAD_BYTES = 4096


def _pe(h):
    if h[:2] != b'MZ' or len(h) < 0x40:
        return False
    offset = struct.unpack_from('<I', h, 0x3C)[0]
    return offset + 4 <= len(h) and h[offset:offset + 4] == b'PE\0\0'


def _zip_member(h, *names):
    """A zip whose first local entry is one of `names` (Office Open XML puts [Content_Types].xml
    first, OpenDocument puts mimetype first)."""
    if h[:4] != b'PK\x03\x04' or len(h) < 30:
        return False
    length = struct.unpack_from('<H', h, 26)[0]
    first = h[30:30 + length]
    return any(first == n or first.startswith(n) for n in names)


TYPES = {
    'pe':     ('Windows executable or library (PE: .exe, .dll, .sys, .efi)', _pe,
               ('.exe', '.dll', '.sys', '.efi', '.ocx', '.cpl', '.scr', '.drv', '.mui', '.signed')),
    'elf':    ('Linux / Unix executable or library (ELF)', lambda h: h[:4] == b'\x7fELF', ()),
    'macho':  ('macOS executable (Mach-O)', lambda h: h[:4] in (b'\xfe\xed\xfa\xce', b'\xfe\xed\xfa\xcf',
                                                                 b'\xce\xfa\xed\xfe', b'\xcf\xfa\xed\xfe',
                                                                 b'\xca\xfe\xba\xbe'), ('.dylib',)),
    'pdf':    ('PDF document', lambda h: h[:1024].lstrip()[:5] == b'%PDF-', ('.pdf',)),
    'ole':    ('Legacy Office document (OLE: .doc, .xls, .ppt, .msi)',
               lambda h: h[:8] == b'\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1', ('.doc', '.xls', '.ppt', '.msi', '.msg')),
    'ooxml':  ('Office Open XML document (.docx, .xlsx, .pptx)',
               lambda h: _zip_member(h, b'[Content_Types].xml', b'_rels/', b'docProps/', b'word/', b'xl/', b'ppt/'),
               ('.docx', '.xlsx', '.pptx', '.docm', '.xlsm', '.pptm')),
    'odf':    ('OpenDocument (.odt, .ods, .odp)', lambda h: _zip_member(h, b'mimetype') and b'application/vnd.oasis' in h[:200],
               ('.odt', '.ods', '.odp', '.ott', '.ots', '.otp')),
    'rtf':    ('Rich Text Format document', lambda h: h[:5] == b'{\\rtf', ('.rtf',)),
    'zip':    ('Zip archive', lambda h: h[:4] == b'PK\x03\x04', ('.zip', '.jar', '.apk')),
    'pcap':   ('Network capture (pcap)', lambda h: h[:4] in (b'\xd4\xc3\xb2\xa1', b'\xa1\xb2\xc3\xd4',
                                                               b'\x4d\x3c\xb2\xa1', b'\xa1\xb2\x3c\x4d'), ('.pcap', '.cap')),
    'pcapng': ('Network capture (pcapng)', lambda h: h[:4] == b'\x0a\x0d\x0d\x0a', ('.pcapng',)),
}

# the most specific first: a .docx is also a zip
_ORDER = ('pe', 'elf', 'macho', 'pdf', 'ole', 'ooxml', 'odf', 'rtf', 'pcap', 'pcapng', 'zip')


def detect(head: bytes):
    for name in _ORDER:
        try:
            if TYPES[name][1](head):
                return name
        except (struct.error, IndexError):
            continue
    return None


def detect_file(path):
    try:
        with open(path, 'rb') as f:
            return detect(f.read(HEAD_BYTES))
    except OSError:
        return None


def extensions(type_names):
    """The usual extensions of these types (a walk filter), or None when one type has none
    (ELF programs: every file must be read)."""
    out = set()
    for name in type_names:
        exts = TYPES.get(name, (None, None, ()))[2]
        if not exts:
            return None
        out.update(exts)
    return tuple(sorted(out))
