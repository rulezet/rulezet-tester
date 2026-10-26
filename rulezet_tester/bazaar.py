"""
Import real malware samples from MalwareBazaar (abuse.ch) into an encrypted set — ON THE LAB VM
ONLY, as the dedicated fetch user (the only account the VM firewall lets out, see docs/lab.md).

    rulezet-tester fetch-bazaar /srv/rulezet-lab/samples/emotet --signature Emotet --limit 25 \\
        --auth-key-file /home/rzfetch/.mb_auth_key

What it does, and does not do:
  - asks the MalwareBazaar API for the latest samples of a signature (family) or a tag;
  - downloads each sample *as MalwareBazaar serves it*: a zip encrypted with the password
    "infected". The zip is written as it came (atomically, read-only, named <sha256>.zip) and is
    **never decrypted here**: the sandboxed worker decrypts it in memory at test time and checks
    its sha256 then;
  - refuses to run as root, refuses a destination outside the configured sample roots when a
    lab config is given, skips samples larger than --max-size, never executes anything.

API: https://bazaar.abuse.ch/api/ (POST https://mb-api.abuse.ch/api/v1/, header Auth-Key; a free
key comes with an abuse.ch account). Check the current documentation if a query stops working.
"""
import json
import os
import re
import urllib.parse
import urllib.request
from pathlib import Path

API = 'https://mb-api.abuse.ch/api/v1/'
_SHA = re.compile(r'^[0-9a-f]{64}$')
_NAME = re.compile(r'^[A-Za-z0-9][A-Za-z0-9 _.:-]{0,63}$')


class BazaarError(Exception):
    pass


def _post(fields, auth_key, timeout=60, opener=None):
    data = urllib.parse.urlencode(fields).encode()
    req = urllib.request.Request(API, data=data, headers={'Auth-Key': auth_key, 'User-Agent': 'rulezet-tester'})
    open_ = opener or urllib.request.urlopen
    with open_(req, timeout=timeout) as res:
        return res.read(200 * 1024 * 1024 + 1)


def list_samples(auth_key, signature=None, tag=None, limit=25, opener=None):
    if bool(signature) == bool(tag):
        raise BazaarError('give either a signature or a tag')
    value = signature or tag
    if not _NAME.match(value):
        raise BazaarError('invalid signature / tag')
    query = {'query': 'get_siginfo', 'signature': value} if signature else {'query': 'get_taginfo', 'tag': value}
    raw = _post({**query, 'limit': str(max(1, min(int(limit), 1000)))}, auth_key, opener=opener)
    try:
        answer = json.loads(raw)
    except ValueError as e:
        raise BazaarError('MalwareBazaar did not answer with JSON') from e
    if answer.get('query_status') != 'ok':
        raise BazaarError(f"MalwareBazaar: {answer.get('query_status')}")
    return answer.get('data') or []


def fetch(dest, auth_key, signature=None, tag=None, limit=25, max_size=20 * 1024 * 1024,
          allowed_roots=None, opener=None, log=print):
    if hasattr(os, 'geteuid') and os.geteuid() == 0:
        raise BazaarError('do not run this as root: use the dedicated fetch user (docs/lab.md)')
    dest = Path(dest).resolve()
    if allowed_roots is not None and not any(Path(r).resolve() in dest.parents for r in allowed_roots):
        raise BazaarError(f'{dest} is not inside the lab sample folders')
    if not re.match(r'^[A-Za-z0-9][A-Za-z0-9_.-]{0,99}$', dest.name):
        raise BazaarError('the set folder name may only use letters, digits, _ . -')
    dest.mkdir(parents=True, exist_ok=True)
    listing_path = dest / 'samples.json'
    listing = json.loads(listing_path.read_text()) if listing_path.is_file() else []
    have = {e.get('sha256') for e in listing}

    added = 0
    for item in list_samples(auth_key, signature, tag, limit, opener):
        sha = str(item.get('sha256_hash') or '').lower()
        size = int(item.get('file_size') or 0)
        if not _SHA.match(sha) or sha in have:
            continue
        if size <= 0 or size > max_size:
            log(f'skip {sha}: size {size}')
            continue
        blob = _post({'query': 'get_file', 'sha256_hash': sha}, auth_key, opener=opener)
        if not blob.startswith(b'PK\x03\x04'):
            log(f'skip {sha}: not a zip ({blob[:80]!r})')
            continue
        if len(blob) > max_size + 1024 * 1024:
            log(f'skip {sha}: download larger than announced')
            continue
        target = dest / f'{sha}.zip'
        tmp = dest / f'.{sha}.part'
        with open(tmp, 'wb') as f:
            f.write(blob)
        os.chmod(tmp, 0o440)
        os.replace(tmp, target)
        listing.append({'file': target.name, 'sha256': sha, 'size': size,
                        'label': f"{item.get('signature') or value_of(signature, tag)} · {item.get('file_type') or '?'} · {sha[:12]}",
                        'source': f'https://bazaar.abuse.ch/sample/{sha}/', 'first_seen': item.get('first_seen'),
                        'tags': item.get('tags') or []})
        have.add(sha)
        added += 1
        log(f'added {sha} ({size} bytes)')

    listing_path.write_text(json.dumps(listing, indent=2) + '\n')
    set_json = dest / 'set.json'
    if not set_json.is_file():
        name = signature or tag
        set_json.write_text(json.dumps({
            'name': f'{name} (MalwareBazaar)', 'format': 'yara', 'kind': 'malicious', 'encrypted': True,
            'password': 'infected', 'description': f'Real samples of {name}, from MalwareBazaar. Encrypted at rest.',
            'labels': {'family': signature} if signature else {'tag': tag},
            'tlp': 'clear', 'source': 'MalwareBazaar (abuse.ch)',
        }, indent=2) + '\n')
    return added


def value_of(signature, tag):
    return signature or tag
