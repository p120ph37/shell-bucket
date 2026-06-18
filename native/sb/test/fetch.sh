# Deterministic self-tests for the sb FILEREQ client (no pty).
#   sb __fetchtest <token> <name> <outpath> [os] [arch]
#     emits the FILEREQ to stdout, reads the response from stdin, writes outpath;
#     status (fr_eof=0 / fr_notchanged=1 / fr_err=2) to stderr.
B=/b/sb
ck() { if [ "$2" = "$3" ]; then echo "ok:   $1"; else echo "FAIL: $1 (exp=$2 got=$3)"; fi; }

# --- T1: a successful ~EOF: decode + chmod + mtime, and request format ---
payload=$(printf 'HELLO\n' | base64 | tr -d '\n')
printf '%s\n~EOF chmod=+x mtime=1700000000\n' "$payload" \
  | $B __fetchtest TESTTOK myfile /tmp/out Linux aarch64 >/tmp/req 2>/tmp/st
req=$(tr -d '\033\\' < /tmp/req)
case "$req" in
  *"shell-bucket:FILEREQ:myfile:mtime=0:os=Linux:arch=aarch64"*) echo "ok:   T1 request format" ;;
  *) echo "FAIL: T1 request format: [$req]" ;;
esac
ck "T1 status eof" "status=0" "$(cat /tmp/st)"
ck "T1 decoded content" "HELLO" "$(cat /tmp/out)"
ck "T1 exec bit" "yes" "$([ -x /tmp/out ] && echo yes || echo no)"
ck "T1 mtime touched" "1700000000" "$(stat -c %Y /tmp/out 2>/dev/null || stat -f %m /tmp/out)"

# --- T2: non-executable (no chmod flag) ---
printf '%s\n~EOF mtime=1700000001\n' "$(printf 'data\n' | base64 | tr -d '\n')" \
  | $B __fetchtest TESTTOK plain /tmp/plain >/dev/null 2>/dev/null
ck "T2 not executable" "no" "$([ -x /tmp/plain ] && echo yes || echo no)"
ck "T2 content" "data" "$(cat /tmp/plain)"

# --- T3: ~ERR NOT_CHANGED -> status 1, no file written ---
rm -f /tmp/nc
printf '~ERR NOT_CHANGED\n' | $B __fetchtest TESTTOK x /tmp/nc >/dev/null 2>/tmp/st
ck "T3 notchanged status" "status=1" "$(cat /tmp/st)"
ck "T3 no file" "absent" "$([ -e /tmp/nc ] && echo present || echo absent)"

# --- T4: ~ERR NOT_FOUND -> status 2 ---
printf '~ERR NOT_FOUND\n' | $B __fetchtest TESTTOK x /tmp/nf >/dev/null 2>/tmp/st
ck "T4 err status" "status=2" "$(cat /tmp/st)"

# --- T5: multi-line base64 body reassembles ---
big=$(head -c 200 /dev/zero | tr '\0' 'A' | base64)   # multi-line base64
printf '%s\n~EOF\n' "$big" | $B __fetchtest TESTTOK big /tmp/big >/dev/null 2>/dev/null
ck "T5 multiline size" "200" "$(wc -c < /tmp/big | tr -d ' ')"
echo "=== done ==="
