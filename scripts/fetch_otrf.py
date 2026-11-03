"""Builds samples/recorded-attacks-windows from OTRF Security-Datasets (MIT, Roberto & Jose Rodriguez,
https://github.com/OTRF/Security-Datasets): Windows hosts recorded while an attack technique ran
(Sysmon, Security, PowerShell events, JSON Lines), stored gzip-compressed. Run by hand (it downloads):

    python scripts/fetch_otrf.py
"""
import gzip
import io
import json
import pathlib
import urllib.request
import zipfile

BASE = 'https://raw.githubusercontent.com/OTRF/Security-Datasets/master/datasets/atomic/windows/'
# (path, label) — small recordings, one technique each
DATASETS = [
    ('execution/host/cmd_sharpview_pcre_net', 'SharpView via PCRE.NET (T1087 / T1059)'),
    ('execution/host/psh_powershell_httplistener', 'PowerShell HttpListener (T1059.001)'),
    ('credential_access/host/cmd_lsass_memory_dumpert_syscalls', 'LSASS memory dump with Dumpert syscalls (T1003.001)'),
    ('credential_access/host/cmd_psexec_lsa_secrets_dump', 'PsExec then LSA secrets dump (T1003.004)'),
    ('credential_access/host/cmd_sam_copy_esentutl', 'SAM copied with esentutl (T1003.002)'),
    ('defense_evasion/host/cmd_bitsadmin_download_psh_script', 'bitsadmin downloads a PowerShell script (T1197)'),
    ('defense_evasion/host/cmd_mshta_vbscript_execute_psh', 'mshta runs VBScript that starts PowerShell (T1218.005)'),
    ('defense_evasion/host/cmd_netsh_fw_mod_open_ports', 'netsh opens firewall ports (T1562.004)'),
    ('persistence/host/cmd_userinitmprlogonscript_batch', 'UserInitMprLogonScript persistence (T1037.001)'),
]
OUT = pathlib.Path(__file__).resolve().parents[1] / 'samples' / 'recorded-attacks-windows'


def main():
    OUT.mkdir(parents=True, exist_ok=True)
    listing = []
    for path, label in DATASETS:
        name = path.rsplit('/', 1)[1]
        with urllib.request.urlopen(BASE + path + '.zip', timeout=60) as r:
            z = zipfile.ZipFile(io.BytesIO(r.read()))
        member = next(m for m in z.namelist() if m.endswith('.json'))
        lines = [l for l in z.read(member).decode('utf-8', 'replace').splitlines() if l.strip()]
        for l in lines:
            json.loads(l)                       # JSON Lines, checked
        (OUT / f'{name}.jsonl.gz').write_bytes(gzip.compress('\n'.join(lines).encode() + b'\n', mtime=0))
        listing.append({'file': f'{name}.jsonl.gz', 'label': f'{label} — {len(lines)} events'})
    (OUT / 'samples.json').write_text(json.dumps(listing, indent=2) + '\n')
    (OUT / 'set.json').write_text(json.dumps({
        'name': 'Recorded attacks — Windows (OTRF Security-Datasets)', 'format': 'sigma', 'kind': 'synthetic',
        'description': 'Real Windows hosts recorded while an attack technique ran (Sysmon, Security, PowerShell events), '
                       'from OTRF Security-Datasets (MIT). Each recording also holds the normal activity around the attack.',
        'labels': {'product': 'windows'}, 'tlp': 'clear', 'source': 'https://github.com/OTRF/Security-Datasets',
    }, indent=2) + '\n')
    print(f'{len(listing)} recordings -> {OUT}')


if __name__ == '__main__':
    main()
