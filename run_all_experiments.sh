#!/usr/bin/env bash
# run_all_experiments.sh
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ARTIFACT_DIR="${ARTIFACT_DIR:-$ROOT_DIR}"
OUT_DIR="${OUT_DIR:-$ARTIFACT_DIR/results}"
RAW_DIR="$OUT_DIR/raw"
JSONL="$OUT_DIR/results.jsonl"

DOCKER_IMAGE="${DOCKER_IMAGE:-aid-distribution}"
DOCKER_BUILD_CONTEXT="${DOCKER_BUILD_CONTEXT:-$ARTIFACT_DIR}"

DINGHY_HINT="${DINGHY_HINT:-android}"
NUM_RECIPIENTS="${NUM_RECIPIENTS:-10000}"
SHOW_UP="${SHOW_UP:-9000}"
THRESHOLD="${THRESHOLD:-2000}"

jsonl_append() {
  local exp="$1" role="$2" cmd="$3" log="$4" status="$5"
  printf '{"ts":"%s","experiment":"%s","role":"%s","cmd":"%s","log_path":"%s","exit_code":%s}\n' \
    "$(now_iso)" \
    "$exp" \
    "$role" \
    "$(echo "$cmd" | sed 's/\\/\\\\/g; s/"/\\"/g')" \
    "$log" \
    "$status" >> "$JSONL"
}

run_and_log() {
  local exp="$1" role="$2" name="$3" cmd="$4"
  local log="$RAW_DIR/${name}.log"
  echo "[$exp][$role] $cmd"
  set +e
  bash -lc "cd \"$ARTIFACT_DIR\" && $cmd" >"$log" 2>&1
  local status=$?
  set -e
  jsonl_append "$exp" "$role" "$cmd" "$log" "$status"
  if [[ $status -ne 0 ]]; then
    echo "Command failed (exit $status). See: $log" >&2
    exit $status
  fi
}

docker_ensure_image() {
  if docker image inspect "$DOCKER_IMAGE" >/dev/null 2>&1; then
    return 0
  fi
  echo "==> Building Docker image $DOCKER_IMAGE"
  docker buildx build --load -t "$DOCKER_IMAGE" "$DOCKER_BUILD_CONTEXT"
}

docker_run_mpspdz() {
  docker run --rm \
    -e NUM_RECIPIENTS="$NUM_RECIPIENTS" \
    -e SHOW_UP="$SHOW_UP" \
    -e THRESHOLD="$THRESHOLD" \
    -w /home/artifact/aid-distribution-with-assessments-artifacts/MP-SPDZ \
    "$DOCKER_IMAGE" \
    bash -lc "set -euo pipefail; $1"
}

run_mpspdz_and_log() {
  local exp="$1" role="$2" name="$3" cmd="$4"
  local log="$RAW_DIR/${name}.log"
  echo "[$exp][$role] $cmd"
  set +e
  docker_ensure_image
  docker_run_mpspdz "$cmd" >"$log" 2>&1
  local status=$?
  set -e
  jsonl_append "$exp" "$role" "docker: $cmd" "$log" "$status"
  if [[ $status -ne 0 ]]; then
    echo "MP-SPDZ command failed (exit $status). See: $log" >&2
  fi
}

mkdir -p "$RAW_DIR"
: > "$JSONL"

now_iso() { date -u +"%Y-%m-%dT%H:%M:%SZ"; }

# -----------------------
# Experiment 1: HbC-2PC-f1
# Recipient P
run_and_log "Exp1_HbC-2PC-f1" "Recipient" \
  "exp1_hbc_2pc_1_recipient" \
  "cargo dinghy -d \"$DINGHY_HINT\" bench --bench hbc_2pc_1 -- hbc_2pc_1_recipient"

# Distribution station D, Helper H
run_mpspdz_and_log "Exp1_HbC-2PC-f1" "Distribution+Helper" \
  "exp1_mpspdz_thresholded_stats" \
  "./create_inputs_1.sh && Scripts/semi.sh assessment_thresholded_stats -v"

# -----------------------
# Experiment 2: HbC-2PC-f2
# Auditor A
run_and_log "Exp2_HbC-2PC-f2" "Auditor" \
  "exp2_hbc_2pc_2_auditor" \
  "cargo bench --bench hbc_2pc_2"

# Distribution station D, Helper H
run_mpspdz_and_log "Exp2_HbC-2PC-f2" "Distribution+Helper" \
  "exp2_mpspdz_conditional_disclosure" \
  "./create_inputs_2.sh && Scripts/semi.sh assessment_conditional_disclosure -v"

# -----------------------
# Experiment 3: HbC-thHE-f1
# Recipient P
run_and_log "Exp3_HbC-thHE-f1" "Recipient" \
  "exp3_hbc_thhe_1_recipient" \
  "cargo dinghy -d \"$DINGHY_HINT\" bench --bench hbc_thhe_1 -- hbc_thhe_1_recipient"

# Distribution station D, Helper H
run_and_log "Exp3_HbC-thHE-f1" "Distribution+Helper" \
  "exp3_hbc_thhe_1_laptop" \
  "cargo bench --bench hbc_thhe_1 -- --nocapture"

# -----------------------
# Experiment 4: HbC-thHE-f2
# Recipient P
run_and_log "Exp4_HbC-thHE-f2" "Recipient" \
  "exp4_hbc_thhe_2_recipient" \
  "cargo dinghy -d \"$DINGHY_HINT\" bench --bench hbc_thhe_2 -- hbc_thhe_2_recipient"

# Distribution station D, Helper H, Auditor A
run_and_log "Exp4_HbC-thHE-f2" "Distribution+Helper+Auditor" \
  "exp4_hbc_thhe_2_laptop" \
  "cargo bench --bench hbc_thhe_2 -- --nocapture"

# -----------------------
# Experiment 5: Mal-thHE-f1
# Recipient P
run_and_log "Exp5_Mal-thHE-f1" "Recipient" \
  "exp5_mal_thhe_1_recipient" \
  "cargo dinghy -d \"$DINGHY_HINT\" bench --bench mal_thhe_1 -- mal_thhe_1_recipient"

# Distribution station D, Helper H, Auditor A
run_and_log "Exp5_Mal-thHE-f1" "Distribution+Helper+Auditor" \
  "exp5_mal_thhe_1_laptop" \
  "cargo bench --bench mal_thhe_1 -- --nocapture"

# -----------------------
# Experiment 6: Mal-thHE-f2
# Recipient P
run_and_log "Exp6_Mal-thHE-f2" "Recipient" \
  "exp6_mal_thhe_2_recipient" \
  "cargo dinghy -d \"$DINGHY_HINT\" bench --bench mal_thhe_2 -- mal_thhe_2_recipient"

# Distribution station D, Helper H, Auditor A
run_and_log "Exp6_Mal-thHE-f2" "Distribution+Helper+Auditor" \
  "exp6_mal_thhe_2_laptop" \
  "cargo bench --bench mal_thhe_2 -- --nocapture"