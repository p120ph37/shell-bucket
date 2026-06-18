# Self-test for busybox-style symlink dedup (no pty/network).
#   sb __linktest <name>  -> "<cp>\t<terminal-basename>" | ERR
# ensure_cached's link branch: a manifest entry with a 4th link-target column
# fetches the terminal ONCE and materializes a local symlink -> it. Here SB_CACHE
# is pre-staged with the terminal already current, so no FILEREQ fires -- we test
# the fetch-skip + link materialization in isolation.
B=/b/sb
C=/tmp/linkcache
ck() { if [ "$2" = "$3" ]; then echo "ok:   $1"; else echo "FAIL: $1 (exp=[$2] got=[$3])"; fi; }

rm -rf "$C"; mkdir -p "$C"
# Terminal binary present + current (mtime matches the manifest version id).
printf '\177ELFbusybox' > "$C/busybox"
chmod +x "$C/busybox"
touch -d @300 "$C/busybox" 2>/dev/null || touch -t 197001010005.00 "$C/busybox"
# Manifest: busybox (plain) + ls (symlink -> busybox, terminal's mtime/exec).
printf '%s\n' \
  "$(printf 'busybox\t300\tx')" \
  "$(printf 'ls\t300\tx\tbusybox')" > "$C/sb-manifest"

# Resolve `ls` on this host's os/arch (root entry). SB_OS/SB_ARCH unset -> uname.
out=$(SB_CACHE="$C" SB_TOKEN=t:s $B __linktest ls)
cp=$(printf '%s' "$out" | cut -f1)
tgt=$(printf '%s' "$out" | cut -f2)

ck "ls cache path"            "$C/ls"   "$cp"
ck "ls is a symlink"          "yes"     "$([ -L "$cp" ] && echo yes || echo no)"
ck "ls -> busybox terminal"    "busybox" "$tgt"
# Dedup: exactly ONE real (non-symlink) binary on disk -- busybox. `ls` is a link,
# not a second copy. Count regular, non-symlink files in the cache root.
ck "only one real copy"       "1"       "$(find "$C" -maxdepth 1 -type f ! -name sb-manifest | grep -c .)"
# The link resolves to executable busybox bytes (multi-call dispatch works on exec).
ck "link resolves to exec"    "yes"     "$([ -x "$cp" ] && echo yes || echo no)"
ck "link content is busybox"  "yes"     "$(head -c 11 "$cp" | grep -qa ELFbusybox && echo yes || echo no)"
echo "=== done ==="
