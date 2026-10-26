#!/bin/bash
# Turns a fresh Debian 12/13 VM into a rulezet-tester lab: the only place real malware samples
# may live. Read docs/lab.md first. Run as root, once, on the VM:
#
#   RULEZET_IP=10.0.0.5 ADMIN_IP=10.0.0.9 RULEZET_PUBKEY="ssh-ed25519 AAAA... rulezet" \
#   ADMIN_USER=admin ./provision.sh
#
#   RULEZET_IP      the only machine allowed to run tests (SSH as rzlab, forced command)
#   ADMIN_IP        the only machine allowed to SSH in as ADMIN_USER (maintenance)
#   RULEZET_PUBKEY  public key of Rulezet (its private key never leaves the Rulezet server)
#   ADMIN_USER      an existing sudo user with an SSH key, used for maintenance
#   TESTER_REF      git ref of rulezet-tester to install (default: main)
#
# Afterwards: sudo -u rzlab /opt/rulezet-tester/.venv/bin/rulezet-tester lab-check \
#             --config /etc/rulezet-tester/lab.json      -> every line must be PASS.
set -euo pipefail

: "${RULEZET_IP:?set RULEZET_IP}" "${ADMIN_IP:?set ADMIN_IP}" "${RULEZET_PUBKEY:?set RULEZET_PUBKEY}" "${ADMIN_USER:?set ADMIN_USER}"
TESTER_REF="${TESTER_REF:-main}"
HERE="$(cd "$(dirname "$0")" && pwd)"
[ "$(id -u)" -eq 0 ] || { echo "run as root"; exit 1; }
id "$ADMIN_USER" >/dev/null || { echo "ADMIN_USER $ADMIN_USER does not exist"; exit 1; }
case "$RULEZET_PUBKEY" in ssh-ed25519\ *|ssh-rsa\ *|ecdsa-*) ;; *) echo "RULEZET_PUBKEY is not an SSH public key"; exit 1;; esac

echo "== packages"
apt-get update -q
DEBIAN_FRONTEND=noninteractive apt-get install -y -q --no-install-recommends \
    bubblewrap python3 python3-venv python3-dev gcc libssl-dev git nftables openssh-server unattended-upgrades
systemctl enable --now unattended-upgrades

echo "== users"
# rzlab: runs the agent, reads samples, no network, no shell beyond the forced command
id rzlab  >/dev/null 2>&1 || useradd --system --home-dir /var/lib/rzlab  --create-home --shell /bin/sh rzlab
# rzfetch: the only account allowed out (HTTPS + DNS), writes samples, never logs in over SSH
id rzfetch >/dev/null 2>&1 || useradd --system --home-dir /var/lib/rzfetch --create-home --shell /usr/sbin/nologin rzfetch
passwd -l rzlab >/dev/null; passwd -l rzfetch >/dev/null
chmod 700 /var/lib/rzlab /var/lib/rzfetch

echo "== rulezet-tester in /opt (root-owned, read-only for everyone else)"
if [ ! -d /opt/rulezet-tester/.git ]; then
    git clone --quiet https://github.com/rulezet/rulezet-tester.git /opt/rulezet-tester
fi
git -C /opt/rulezet-tester fetch --quiet origin
git -C /opt/rulezet-tester checkout --quiet "$TESTER_REF"
python3 -m venv /opt/rulezet-tester/.venv
/opt/rulezet-tester/.venv/bin/pip install --quiet --upgrade pip
/opt/rulezet-tester/.venv/bin/pip install --quiet "/opt/rulezet-tester[yara,lab]"
chown -R root:root /opt/rulezet-tester
chmod -R go-w /opt/rulezet-tester

echo "== samples: written by rzfetch, read-only for rzlab, never executable"
install -d -o rzfetch -g rzlab -m 2750 /srv/rulezet-lab /srv/rulezet-lab/samples
# new files: rw for rzfetch, r for the rzlab group, nothing for others, never +x
setfacl -d -m u::rw,g::r,o::- /srv/rulezet-lab/samples 2>/dev/null || true

echo "== configuration"
install -d -o root -g root -m 755 /etc/rulezet-tester
install -o root -g rzlab -m 640 "$HERE/lab.json" /etc/rulezet-tester/lab.json

echo "== SSH: keys in a root-owned folder, forced command for rzlab, nothing else"
install -d -o root -g root -m 755 /etc/ssh/authorized_keys
printf 'restrict,command="/opt/rulezet-tester/.venv/bin/rulezet-tester lab-agent --config /etc/rulezet-tester/lab.json",from="%s" %s\n' \
    "$RULEZET_IP" "$RULEZET_PUBKEY" > /etc/ssh/authorized_keys/rzlab
chown root:root /etc/ssh/authorized_keys/rzlab; chmod 644 /etc/ssh/authorized_keys/rzlab
if [ -f "/home/$ADMIN_USER/.ssh/authorized_keys" ] && [ ! -f "/etc/ssh/authorized_keys/$ADMIN_USER" ]; then
    install -o root -g root -m 644 "/home/$ADMIN_USER/.ssh/authorized_keys" "/etc/ssh/authorized_keys/$ADMIN_USER"
fi
[ -s "/etc/ssh/authorized_keys/$ADMIN_USER" ] || { echo "no SSH key for $ADMIN_USER: you would be locked out"; exit 1; }
sed -e "s/@ADMIN_USER@/$ADMIN_USER/g" "$HERE/sshd_lab.conf" > /etc/ssh/sshd_config.d/10-rulezet-lab.conf
chmod 644 /etc/ssh/sshd_config.d/10-rulezet-lab.conf
sshd -t
systemctl reload ssh

echo "== firewall: in = SSH from Rulezet and the admin only; out = rzfetch (HTTPS, DNS) and apt only"
sed -e "s/@RULEZET_IP@/$RULEZET_IP/g" -e "s/@ADMIN_IP@/$ADMIN_IP/g" \
    -e "s/@RZFETCH_UID@/$(id -u rzfetch)/g" -e "s/@APT_UID@/$(id -u _apt 2>/dev/null || echo 0)/g" \
    "$HERE/nftables.conf" > /etc/nftables.conf
chmod 600 /etc/nftables.conf
nft -c -f /etc/nftables.conf
systemctl enable --now nftables
nft -f /etc/nftables.conf

echo "== kernel: user namespaces are needed by bubblewrap; nothing else is opened"
cat > /etc/sysctl.d/90-rulezet-lab.conf <<'EOF'
kernel.dmesg_restrict = 1
kernel.kptr_restrict = 2
kernel.yama.ptrace_scope = 2
net.ipv4.ip_forward = 0
net.ipv6.conf.all.forwarding = 0
fs.suid_dumpable = 0
EOF
sysctl --system >/dev/null

echo
echo "Done. Now, as root on the VM:"
echo "  sudo -u rzlab /opt/rulezet-tester/.venv/bin/rulezet-tester lab-check --config /etc/rulezet-tester/lab.json"
echo "Every line must be PASS before any real sample is imported (docs/lab.md, 'Import samples')."
