#!/usr/bin/env bash
#
# Linux101 capstone CTF: setup script
#
# Run it with:   sudo bash ctf-setup.sh
# Undo it with:  sudo bash ctf-setup.sh --cleanup
#
# What it does:
#   - creates the directory /opt/l101 with a few files inside
#   - adds one extra user account, called "ghost"
#   - starts one harmless background process, called "flagd"
#   - writes a few lines to the system journal
#   - writes your challenge list to ~/linux101/session4/challenges.txt
# It changes nothing else on your machine.
#
set -u

if [ "$(id -u)" -ne 0 ]; then
    echo "Run this with sudo:  sudo bash $0"
    exit 1
fi

STUDENT="${SUDO_USER:-root}"
HOME_DIR="$(getent passwd "$STUDENT" | cut -d: -f6)"
BASE=/opt/l101
OUTDIR="$HOME_DIR/linux101/session4"

decode() { printf '%s' "$1" | base64 -d; }

cleanup() {
    pkill -f 'flagd --secret' 2>/dev/null
    userdel ghost 2>/dev/null
    rm -rf "$BASE"
    rm -f "$OUTDIR/challenges.txt"
}

if [ "${1:-}" = "--cleanup" ]; then
    cleanup
    echo "CTF removed."
    exit 0
fi

cleanup   # always start from a clean slate, so running it twice is safe

# The seven flags, stored encoded.
F1="TDEwMXtoaWRkZW5faW5fcGxhaW5fc2lnaHR9"
F2="TDEwMXt0aHJlZV9sYXllcnNfZGVlcH0="
F3="TDEwMXt0cnVzdF9idXRfdmVyaWZ5fQ=="
F4="TDEwMXtwZXJtaXNzaW9uX2dyYW50ZWR9"
F5="TDEwMXtnaG9zdF9pbl90aGVfcGFzc3dkfQ=="
F6="TDEwMXtwcm9jZXNzZXNfdGVsbF9hbGx9"
F7="TDEwMXt0aGVfam91cm5hbF9yZW1lbWJlcnN9"

install -d -o "$STUDENT" -g "$(id -gn "$STUDENT")" "$HOME_DIR/linux101" "$OUTDIR"

# Challenge 1: a hidden file
mkdir -p "$BASE"/{docs,notes,logs,backup/2024,backup/2025}
echo "Meeting moved to Thursday."        > "$BASE/notes/todo.txt"
echo "Nothing to see here."              > "$BASE/docs/readme.txt"
echo "disk usage report, all normal"     > "$BASE/logs/report.txt"
echo "2025 backup: 14 files"             > "$BASE/backup/2025/manifest.txt"
touch "$BASE/docs/.keep"
{ decode "$F1"; echo; }                  > "$BASE/backup/2024/.old_credentials"

# Challenge 2: three layers of encoding (base64, then ROT13, then hex)
decode "$F2" | base64 -w0 | tr 'A-Za-z' 'N-ZA-Mn-za-m' | od -An -tx1 | tr -d ' \n' > "$BASE/mystery.txt"
echo >> "$BASE/mystery.txt"

# Challenge 3: fifty files, one of which has a particular SHA-256
mkdir -p "$BASE/vault"
TARGET=$(( RANDOM % 50 + 1 ))
for i in $(seq 1 50); do
    n=$(printf '%02d' "$i")
    if [ "$i" -eq "$TARGET" ]; then
        { echo "Access granted."; decode "$F3"; echo; } > "$BASE/vault/record_$n.dat"
    else
        echo "Record $n: nothing of interest ($RANDOM$RANDOM)" > "$BASE/vault/record_$n.dat"
    fi
done
HASH=$(sha256sum "$BASE/vault/record_$(printf '%02d' "$TARGET").dat" | cut -d' ' -f1)

# Challenge 4: a script that is not allowed to run
cat > "$BASE/unlock.sh" <<EOF
#!/bin/bash
echo "Unlocked: \$(echo '$F4' | base64 -d)"
EOF
chown "$STUDENT" "$BASE/unlock.sh"
chmod 644 "$BASE/unlock.sh"

# Challenge 5: a user account with something in its comment field
useradd -M -s /usr/sbin/nologin -c "$(decode "$F5")" ghost

# Challenge 6: a background process called flagd
export FLAGD_ARG0="flagd --secret=$(decode "$F6")"
setsid nohup bash -c 'exec -a "$FLAGD_ARG0" sleep infinity' >/dev/null 2>&1 &
unset FLAGD_ARG0

# Challenge 7: a message in the system journal
logger -t l101 "setup started"
logger -t l101 "flag: $(decode "$F7")" || echo "(could not write to the journal)"
logger -t l101 "setup finished"

chmod -R a+rX "$BASE"

cat > "$OUTDIR/challenges.txt" <<EOF
LINUX101 CAPSTONE CTF

Every flag looks like L101{...}
Save each one in ~/linux101/session4/flags.txt, appending with >>

1  Navigation   A hidden file is somewhere under /opt/l101
2  Text-Fu      /opt/l101/mystery.txt is encoded, three layers deep. One pipeline
3  Integrity    /opt/l101/vault holds 50 files. Exactly one has this SHA-256:
                $HASH
4  Permissions  /opt/l101/unlock.sh exists but will not run. Make it run
5  Users        A user called ghost hides something in its account info
6  Processes    A background process called flagd carries something in its arguments
7  Logs         The setup wrote something to the system journal, tagged l101
EOF
chown "$STUDENT" "$OUTDIR/challenges.txt"

echo "Done. Your challenges are in ~/linux101/session4/challenges.txt"
