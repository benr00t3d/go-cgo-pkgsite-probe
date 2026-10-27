#!/bin/bash
set -euo pipefail

root=$(CDPATH= cd "$(dirname "$0")/.." && pwd -P)
source <(sed '$d' "$root/poc.sh")

test_root=$(mktemp -d /tmp/v065-state-test.XXXXXX)
trap 'rm -rf "$test_root"' EXIT HUP INT TERM

CURRENT='github.com/benr00t3d/go-cgo-pkgsite-probe@v0.0.65-codex'
TARGET='github.com/benr00t3d/go-byteman-crosswrite-canary@v0.0.1'
PACKAGE=${TARGET%@*}
VERSION=${TARGET##*@}
EXPECTED_REFRESH_SHA256='5f5604aff7ef29643b7768e58b3dfdc510e58adcd37e596ac0892b72c733290a'
EXPECTED_BASELINE_SHA256='bb0f29abd8210aa614a6175e38265532487079bebd25ab94ca21eaaeb13c157c'
EXPECTED_ALTERED_SHA256='5ec2c29ccadbf5bee106dbc53146bb8c2ec5edd37f573720c4bfabe5ca01efa4'

fetch_public() {
  FETCH_COUNT=$((FETCH_COUNT + 1))
  public_status=200
  case "$TEST_MODE:$FETCH_COUNT" in
    unknown:7)
      public_digest='0000000000000000000000000000000000000000000000000000000000000000'
      public_body='{}'
      ;;
    altered:10|altered:30)
      public_digest=$EXPECTED_ALTERED_SHA256
      public_body=$altered_body
      ;;
    *)
      public_digest=$EXPECTED_BASELINE_SHA256
      public_body=$clean_body
      ;;
  esac
  printf '%s' "$public_body" >"$1"
}

sleep() { :; }

prepare_altered_worker() {
  PREPARE_COUNT=$((PREPARE_COUNT + 1))
}

send_refresh() {
  REFRESH_COUNT=$((REFRESH_COUNT + 1))
  build_refresh "$receipt_dir/refresh.bin"
  [ "$(file_size "$receipt_dir/refresh.bin")" -eq 74 ]
  [ "$(sha256sum "$receipt_dir/refresh.bin" | awk '{print $1}')" = "$EXPECTED_REFRESH_SHA256" ]
}

reset_case() {
  case_name=$1
  receipt_dir="$test_root/$case_name"
  mkdir -p "$receipt_dir"
  PREPARE_COUNT=0
  REFRESH_COUNT=0
  FETCH_COUNT=0
  PRECHECK_SAMPLES=21
  PRECHECK_INTERVAL=1
  POSTCHECK_SAMPLES=21
  POLL_INTERVAL=1
  POLL_TIMEOUT=100
}

clean_body='{"package":"github.com/benr00t3d/go-byteman-crosswrite-canary","version":"v0.0.1","capabilities":[],"hasErrors":false}'
altered_body='{"package":"github.com/benr00t3d/go-byteman-crosswrite-canary","version":"v0.0.1","capabilities":[],"hasErrors":true}'

reset_case clean
TEST_MODE=clean
run_state_machine >"$receipt_dir/stdout" 2>"$receipt_dir/stderr"
[ "$PREPARE_COUNT:$REFRESH_COUNT:$FETCH_COUNT" = '0:0:21' ]
grep -q '^NOOP_CONVERGED_CLEAN=1 samples=21' "$receipt_dir/stdout"
[ "$(((PRECHECK_SAMPLES - 1) * PRECHECK_INTERVAL))" -ge 20 ]

reset_case unknown
TEST_MODE=unknown
set +e
run_state_machine >"$receipt_dir/stdout" 2>"$receipt_dir/stderr"
unknown_rc=$?
set -e
[ "$unknown_rc" -eq 1 ]
[ "$PREPARE_COUNT:$REFRESH_COUNT:$FETCH_COUNT" = '0:0:7' ]

reset_case altered
TEST_MODE=altered
run_state_machine >"$receipt_dir/stdout" 2>"$receipt_dir/stderr"
[ "$PREPARE_COUNT:$REFRESH_COUNT:$FETCH_COUNT" = '1:1:51' ]
[ "$(file_size "$receipt_dir/refresh.bin")" -eq 74 ]
[ "$(sha256sum "$receipt_dir/refresh.bin" | awk '{print $1}')" = "$EXPECTED_REFRESH_SHA256" ]
[ "$(sha256sum "$receipt_dir/public-restored.json" | awk '{print $1}')" = "$EXPECTED_BASELINE_SHA256" ]
grep -q 'phase=restore status=200 sha256=5ec2c29.*clean_streak=0/21' "$receipt_dir/public-poll.log"
grep -q 'phase=restore status=200 sha256=bb0f29.*clean_streak=21/21' "$receipt_dir/public-poll.log"
grep -q '^RESTORED_CONVERGED=1 samples=21 baseline_sha256=bb0f29' "$receipt_dir/stdout"

headers="$test_root/headers"
printf 'HTTP/2 200 \r\ncontent-type: application/grpc\r\ngrpc-status: 0\r\n' >"$headers"
grpc_response_ok "$headers"
printf 'grpc-status: 0\r\n' >>"$headers"
! grpc_response_ok "$headers"
printf 'HTTP/2 200 \r\ncontent-type: text/plain\r\ngrpc-status: 0\r\n' >"$headers"
! grpc_response_ok "$headers"
printf 'HTTP/2 200 \r\ncontent-type: application/grpc\r\ngrpc-status: 7\r\n' >"$headers"
! grpc_response_ok "$headers"

printf '%s\n' 'convergence_window_unknown_altered_refresh_and_grpc_headers: PASS'
