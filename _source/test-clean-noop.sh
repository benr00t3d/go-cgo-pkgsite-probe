#!/bin/sh
set -eu

root=$(CDPATH= cd "$(dirname "$0")/.." && pwd -P)
test_root=$(mktemp -d /tmp/v063-clean-noop-test.XXXXXX)
trap 'rm -rf "$test_root"' EXIT HUP INT TERM
mkdir -p "$test_root/bin"

for path in \
  /etc/tls/server-pool/server-tls-pool.pem \
  /etc/tls/client/tls.crt \
  /etc/tls/client/tls.key; do
  [ ! -r "$path" ] || {
    printf 'test requires absent mTLS prerequisite: %s\n' "$path" >&2
    exit 1
  }
done

cat >"$test_root/bin/curl" <<'EOF'
#!/bin/sh
set -eu
count=0
[ ! -f "$V63_CURL_COUNT" ] || count=$(cat "$V63_CURL_COUNT")
count=$((count + 1))
printf '%s\n' "$count" >"$V63_CURL_COUNT"
output=
while [ "$#" -gt 0 ]; do
  case "$1" in
    -o)
      output=$2
      shift 2
      ;;
    -w)
      shift 2
      ;;
    *)
      shift
      ;;
  esac
done
[ -n "$output" ] || exit 97
printf '%s' '{"package":"github.com/benr00t3d/go-byteman-crosswrite-canary","version":"v0.0.1","capabilities":[],"hasErrors":false}' >"$output"
printf '200'
EOF

cat >"$test_root/bin/getent" <<'EOF'
#!/bin/sh
: >"$V63_GETENT_SENTINEL"
exit 99
EOF
chmod 755 "$test_root/bin/curl" "$test_root/bin/getent"

PATH="$test_root/bin:/usr/bin:/bin" \
V63_CURL_COUNT="$test_root/curl.count" \
V63_GETENT_SENTINEL="$test_root/getent.called" \
  /bin/sh "$root/poc.sh" >"$test_root/stdout" 2>"$test_root/stderr"

grep -q '^NOOP_ALREADY_CLEAN=1 sha256=bb0f29abd8210aa614a6175e38265532487079bebd25ab94ca21eaaeb13c157c$' \
  "$test_root/stdout"
[ "$(cat "$test_root/curl.count")" -eq 1 ]
[ ! -e "$test_root/getent.called" ]
[ ! -s "$test_root/stderr" ]
printf '%s\n' 'clean_noop_without_mtls_or_internal_lookup: PASS'
