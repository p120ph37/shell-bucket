# Deterministic self-tests for the APC Scanner (no pty, label-swap).
#   sb __muxscan  reads stdin, prints `T:<passthru>` then one `P:<payload>` per
#   extracted our-prefix APC. The wire carries NO token: any
#   `shell-bucket:`-prefixed APC is ours; recognition is prefix-only.
B=/b/sb
scan() { printf "$1" | $B __muxscan; }
check() { if [ "$2" = "$3" ]; then echo "ok:   $1"; else echo "FAIL: $1 (exp=[$2] got=[$3])"; fi; }

check "extract our-prefix payload" "P:R5:FILEREQ:imgcat" \
  "$(scan '\033_shell-bucket:R5:FILEREQ:imgcat\033\\')"

check "foreign-prefix APC -> passthru" "T:$(printf '\033_other-app:FILEREQ:x\033\\')" \
  "$(scan '\033_other-app:FILEREQ:x\033\\')"

check "foreign APC -> passthru" "T:$(printf '\033_Gkitty=1\033\\')" \
  "$(scan '\033_Gkitty=1\033\\')"

check "plain text -> passthru" "T:hello world" "$(scan 'hello world')"

out="$(scan 'A\033_shell-bucket:BEGIN\033\\B')"
case "$out" in *"T:AB"*) echo "ok:   text split to passthru" ;; *) echo "FAIL: passthru ([$out])" ;; esac
case "$out" in *"P:BEGIN"*) echo "ok:   BEGIN extracted" ;; *) echo "FAIL: payload ([$out])" ;; esac
echo "=== done ==="
