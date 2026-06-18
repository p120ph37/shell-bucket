# Self-test for `select_kills` -- the safe-kill selector logic behind `sb ctl kill`.
#   sb __killtest <selector> [match]  -> space-joined chosen PIDs | "none"
# Fixed synthetic inventory (see __killtest):
#   101 relay "ssh bastion"
#   102 port  "bind:127.0.0.1:8080:all"
#   103 port  "dial:db:5432"
#   104 rpc   "FILEREQ"
#     0 rpc   "unknownpid"   <- pid 0 must NEVER be selected
B=/b/sb
ck() { if [ "$2" = "$3" ]; then echo "ok:   $1"; else echo "FAIL: $1 (exp=[$2] got=[$3])"; fi; }

ck "all -> every real pid"          "101 102 103 104" "$($B __killtest all)"
ck "relays -> just the relay"       "101"             "$($B __killtest relays)"
ck "ports -> both ports"            "102 103"         "$($B __killtest ports)"
ck "rpcs -> real rpc only (not 0)"  "104"             "$($B __killtest rpcs)"
ck "pid selector -> that pid"       "102"             "$($B __killtest 102)"
ck "unknown pid -> none"            "none"            "$($B __killtest 999)"
ck "pid 0 never selected"          "none"            "$($B __killtest 0)"

# --match= filters by description substring (across categories).
ck "match 8080 -> the 8080 port"    "102"             "$($B __killtest all 8080)"
ck "match db -> the db port"        "103"             "$($B __killtest ports db)"
ck "category + match (ports/db)"   "103"             "$($B __killtest ports db)"
ck "match miss -> none"             "none"            "$($B __killtest all nope)"

# PID + match double-guard: the pid must ALSO match the description (PID-reuse safety).
ck "pid+match agree -> kill"        "102"             "$($B __killtest 102 8080)"
ck "pid+match disagree -> none"     "none"            "$($B __killtest 102 5432)"
echo "=== done ==="
