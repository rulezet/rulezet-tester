# The lab VM — testing rules on real malware

Real malware samples live in **one place only**: a dedicated virtual machine, the *lab*. Rulezet
(or any other client) never holds them; it sends a rule and sample ids over SSH and gets verdicts
back. This page is the setup, the reasons behind each choice, and the checks to run.

**Never import real samples anywhere else**: not on a laptop, not on the Rulezet server, not in
this repository.

## 1. Threat model

| Threat | Protection | Where |
|---|---|---|
| A sample gets executed | Nothing executes samples: YARA only reads bytes. Samples are stored encrypted, read-only, never `+x`; decrypted in memory only | `worker.py`, `samples.py` |
| Antivirus alert, accidental double-click, backup copying live malware | Samples stay in zips encrypted with `infected` (the convention of malware repositories); the clear bytes exist only in the sandboxed worker's memory | `worker.py` (`decrypt`) |
| A crafted sample exploits the engine (YARA module parser bug) | The worker runs in **bubblewrap** (no network, empty read-only file system, no capabilities, memory / CPU / file limits) **inside the VM** | `sandbox.py` |
| Code that escaped the sandbox calls home or attacks the network | The VM firewall drops every outbound packet except for the fetch user (HTTPS + DNS) and apt; `rzlab` and the sandbox have no way out | `deploy/lab/nftables.conf` |
| A compromised VM attacks Rulezet | Rulezet only opens SSH connections *to* the VM; nothing on the VM can reach Rulezet (firewall). Answers are JSON parsed with size limits | `remote.py` |
| A compromised Rulezet attacks the VM | Its key can only run the agent (`ForceCommand`, `restrict`, `from=`), no shell, no tty, no forwarding. The agent accepts one strict JSON request (≤ 1 MB, known keys, sample **ids** never paths, rule ≤ 512 KB, `include` refused) | `deploy/lab/sshd_lab.conf`, `lab.py` |
| Someone else reaches the VM | SSH only from two IPs (Rulezet, admin), keys only, keys in a root-owned folder, rate-limited | `nftables.conf`, `sshd_lab.conf` |
| A sample is swapped or corrupted on disk | Its sha256 is checked in the sandbox before every scan | `worker.py` |
| Zip bomb | Declared size checked before reading, 64 MB cap, memory limit | `worker.py` |
| Man in the middle between Rulezet and the VM | SSH host key pinned in a dedicated `known_hosts`, `StrictHostKeyChecking=yes` | `remote.py` |
| The agent account is used to modify samples or config | Samples owned by `rzfetch`, read-only for `rzlab`; config root-owned; `lab-check` verifies both | `provision.sh`, `lab.py` |

What this does **not** cover, by design: the hypervisor itself. Keep it patched and follow §2.

## 2. The VM (hypervisor side)

- A dedicated VM: Debian 12 or 13, 2 vCPU, 2–4 GB RAM, 40 GB disk. Nothing else runs on it.
- **No** shared folders, **no** clipboard / drag-and-drop sharing, **no** USB passthrough, no
  guest additions beyond what the hypervisor strictly needs.
- Its own network segment (host-only or a dedicated VLAN). Only Rulezet and the admin machine can
  reach it; it reaches the internet only through the firewall rules of §3.
- Disk encryption on the host side if the host is shared; snapshots before every import.
- Not in the same backups as Rulezet (or a separate, encrypted backup).

## 3. Install

On the Rulezet server, create the key Rulezet will use (it never leaves this server):

```bash
sudo install -d -m 700 -o <rulezet user> /etc/rulezet
sudo -u <rulezet user> ssh-keygen -t ed25519 -N '' -C rulezet-lab -f /etc/rulezet/lab_ed25519
cat /etc/rulezet/lab_ed25519.pub
```

On the VM, as root, with your admin user already able to log in with a key:

```bash
git clone https://github.com/rulezet/rulezet-tester.git /root/rulezet-tester
cd /root/rulezet-tester/deploy/lab
RULEZET_IP=<rulezet ip> ADMIN_IP=<your ip> ADMIN_USER=<your sudo user> \
RULEZET_PUBKEY="$(cat lab_ed25519.pub)" ./provision.sh
```

`provision.sh` installs bubblewrap and rulezet-tester (in `/opt`, root-owned), creates the two
accounts, the sample folder, the SSH and firewall configuration, a few kernel hardening settings.
Read it before running it: every step is commented.

| Account | Can | Cannot |
|---|---|---|
| `rzlab` | run the agent (forced command), read samples | log in to a shell, write samples or config, reach any network |
| `rzfetch` | write samples, reach HTTPS + DNS | log in over SSH |
| your admin user | maintenance over SSH from `ADMIN_IP` | — (keep it off the sample folder) |

## 4. Verify — before any real sample

```bash
sudo -u rzlab /opt/rulezet-tester/.venv/bin/rulezet-tester lab-check --config /etc/rulezet-tester/lab.json
```

Every line must be `PASS`: not root, bwrap mode, the sandbox starts and runs YARA, pyzipper
present, **no outbound network** (three probes), sample folders exist and are read-only for
`rzlab`, no executable file in them, every malicious set encrypted, config read-only. Run it
again after every update.

Then from the Rulezet server, pin the host key and test the connection:

```bash
ssh-keyscan -t ed25519 <vm ip> > /etc/rulezet/lab_known_hosts      # check the fingerprint against the VM console
echo '{"op":"ping"}' | ssh -i /etc/rulezet/lab_ed25519 -o UserKnownHostsFile=/etc/rulezet/lab_known_hosts rzlab@<vm ip>
```

The answer is `{"ok": true, "version": ..., "formats": ["yara"], ...}`. Anything you type other
than a JSON request gets an error: there is no shell.

## 5. Import samples

On the VM, as `rzfetch` (the only account the firewall lets out). Keep the abuse.ch key in a file,
never on the command line:

```bash
sudo -u rzfetch bash -c 'umask 077; cat > /var/lib/rzfetch/.mb_auth_key'       # paste the key, Ctrl+D
sudo -u rzfetch /opt/rulezet-tester/.venv/bin/rulezet-tester fetch-bazaar \
    /srv/rulezet-lab/samples/emotet --signature Emotet --limit 25 \
    --auth-key-file /var/lib/rzfetch/.mb_auth_key --config /etc/rulezet-tester/lab.json
```

Samples arrive exactly as MalwareBazaar serves them (encrypted zips), named `<sha256>.zip`,
read-only; `samples.json` and `set.json` (kind `malicious`, `encrypted: true`) are written next
to them. Nothing is decrypted. Other sources (MISP, your own collection) go through the same
format: one encrypted zip per sample with one file inside, listed with its sha256.

Benign sets for false positives, on the VM: the `benign-usr-bin` set shipped with rulezet-tester
scans `/usr/bin` in place; `rulezet-tester benign-set` copies a wider mix from `/usr`.

## 6. Connect Rulezet

In Rulezet's `.env`:

```
RULE_TESTS_LAB=rzlab@<vm ip>
RULE_TESTS_LAB_KEY=/etc/rulezet/lab_ed25519
RULE_TESTS_LAB_KNOWN_HOSTS=/etc/rulezet/lab_known_hosts
```

Restart Rulezet: the Test panel now lists the lab's sets, runs happen on the VM, and nothing about
the samples except metadata and verdicts ever reaches Rulezet. Without `RULE_TESTS_LAB`, Rulezet
tests locally on the safe sets only.

## 7. Operating

- Update: `git -C /opt/rulezet-tester pull && /opt/rulezet-tester/.venv/bin/pip install "/opt/rulezet-tester[yara,lab]"`
  as root, then `lab-check`.
- Watch the firewall log (`journalctl -k | grep rulezet-lab`): a denied packet from anything but
  `rzfetch` or apt deserves a look.
- Rotate Rulezet's key: new key on the Rulezet server, replace the line in
  `/etc/ssh/authorized_keys/rzlab`.
- Retire a sample: delete its zip and its line in `samples.json` (as `rzfetch`).
