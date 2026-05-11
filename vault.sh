#!/usr/bin/env bash
set -euo pipefail

ts() {
  date "+%Y-%m-%d %H:%M:%S"
}

log_line() {
  local level="$1"
  shift
  printf '[%s] [%s] %s\n' "$(ts)" "$level" "$*" >&2
}

debug() {
  if [[ "${DEBUG}" == "1" ]]; then
    log_line "DEBUG" "$*"
  fi
}

fail() {
  log_line "ERROR" "$*"
  exit 1
}

mask() {
  local value="$1"
  local n=${#value}
  if (( n <= 8 )); then
    printf '****'
    return
  fi
  printf '%s****%s' "${value:0:4}" "${value:n-4:4}"
}

DEBUG="${VAULT_DEBUG:-0}"

trap 'log_line "ERROR" "Command failed at line ${LINENO}: ${BASH_COMMAND}"' ERR

MOUNT_POINT="${VAULT_MOUNT_POINT:-secret}"
SECRET_PATH="${VAULT_SECRET_PATH:-}"
SECRET_KEY="${VAULT_SECRET_KEY:-}"
GET_SECRET=""
PUT_SECRET=""
PUT_VALUE=""
KEY_SET="0"
ACTION="get"
DEFAULT_PUT_KEY="${VAULT_DEFAULT_PUT_KEY:-value}"

print_help() {
  cat <<'EOF'
vault.sh - Read HashiCorp Vault KV v2 secrets using AppRole

Usage:
  vault.sh [options]

Options:
  --get-secret <path>    Full Vault API path (/v1/<mount>/data/<path>)
  --put-secret <path>    Full Vault API path (/v1/<mount>/data/<path>) to write
  --value <value>        Value to write (used with --put-secret)
  --mount-point <name>   KV v2 mount point (default: VAULT_MOUNT_POINT or secret)
  --path <path>          Secret path inside KV v2
  --key <key>            Secret field key to extract
  --debug                Enable debug logs
  -h, --help             Show this help

Authentication:
  - AppRole only, via environment variables:
      VAULT_ROLE_ID
      VAULT_SECRET_ID

Connection:
  - VAULT_ADDR defaults to script default if not set.
  - VAULT_NAMESPACE is optional and sent as X-Vault-Namespace.

How secret targeting works:
  1) Preferred: --get-secret
     Accepts:
       /v1/<mount>/data/<secret-path>
       <mount>/data/<secret-path>
       https://host/v1/<mount>/data/<secret-path>

     Optional key can be embedded:
       ...#myKey
       ...?key=myKey

  2) Explicit: --mount-point + --path (+ optional --key)

Write mode (--put-secret) guessing rules:
  - If key is present in path (#key or ?key=key), update that key.
  - Else if --value is a JSON object, write it as the whole secret object.
  - Else if secret exists and has exactly one key, update that key.
  - Else if secret exists and has multiple keys, fail as ambiguous.
  - Else (secret does not exist), create with default key "value"
    (overridable via VAULT_DEFAULT_PUT_KEY).

Priority rules:
  - If --get-secret is provided, it sets mount/path automatically.
  - If --key is explicitly provided, it overrides key from --get-secret.
  - If no --key is provided and secret has one key, value-only output is returned.
  - If no --key is provided and secret has multiple keys, full JSON object is returned.
  - If --key is provided:
      scalar value => raw scalar output
      object/array => JSON output

Examples:
  # Full path parsing
  ./vault.sh --get-secret "/v1/secret/data/team/app"

  # Put scalar with key in path
  ./vault.sh --put-secret "/v1/secret/data/team/app#token" --value "s3cr3t"

  # Put whole object
  ./vault.sh --put-secret "/v1/secret/data/team/app" --value '{"user":"alice","token":"abc"}'

  # Full URL + key in fragment
  ./vault.sh --get-secret "https://vault.example.com/v1/secret/data/team/app#token"

  # Explicit mount/path with debug logs
  ./vault.sh --mount-point secret --path "team/app" --debug

  # Use key from query parameter
  ./vault.sh --get-secret "/v1/secret/data/team/app?key=password"

Common troubleshooting:
  - Permission denied => AppRole authenticated, but policy lacks read on <mount>/data/<path>.
  - Redirect/login errors => set VAULT_ADDR to canonical HTTPS endpoint.
  - Missing jq/curl => install required binaries.
EOF
}

parse_secret_target() {
  local raw="$1"
  local key_is_explicit="$2"
  local parsed="$raw"
  local parsed_mount=""
  local parsed_path=""
  local fragment_key=""
  local query_key=""
  local query=""

  if [[ "$parsed" =~ ^https?://[^/]+(/.*)$ ]]; then
    parsed="${BASH_REMATCH[1]}"
  fi

  if [[ "$parsed" == *"#"* ]]; then
    fragment_key="${parsed#*#}"
    parsed="${parsed%%#*}"
  fi

  if [[ "$parsed" == *"?"* ]]; then
    query="${parsed#*\?}"
    parsed="${parsed%%\?*}"
    if [[ "$query" =~ (^|&)key=([^&]+)($|&) ]]; then
      query_key="${BASH_REMATCH[2]}"
    fi
  fi

  parsed="${parsed#/}"
  if [[ "$parsed" == v1/* ]]; then
    parsed="${parsed#v1/}"
  fi

  if [[ "$parsed" != */data/* ]]; then
    fail "Secret target must look like /v1/<mount>/data/<path>"
  fi

  parsed_mount="${parsed%%/data/*}"
  parsed_path="${parsed#*/data/}"

  if [[ -z "$parsed_mount" || -z "$parsed_path" ]]; then
    fail "Unable to parse mount/path from secret target '${raw}'"
  fi

  MOUNT_POINT="$parsed_mount"
  SECRET_PATH="$parsed_path"

  if [[ "$key_is_explicit" == "0" ]]; then
    SECRET_KEY=""
    if [[ -n "$fragment_key" ]]; then
      SECRET_KEY="$fragment_key"
    elif [[ -n "$query_key" ]]; then
      SECRET_KEY="$query_key"
    fi
  fi

  debug "Parsed secret target mount=${MOUNT_POINT} path=${SECRET_PATH} key=${SECRET_KEY:-<none>}"
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --mount-point)
      MOUNT_POINT="$2"
      shift 2
      ;;
    --path)
      SECRET_PATH="$2"
      shift 2
      ;;
    --key)
      SECRET_KEY="$2"
      KEY_SET="1"
      shift 2
      ;;
    --get-secret)
      GET_SECRET="$2"
      ACTION="get"
      shift 2
      ;;
    --put-secret)
      PUT_SECRET="$2"
      ACTION="put"
      shift 2
      ;;
    --value)
      PUT_VALUE="$2"
      shift 2
      ;;
    --debug)
      DEBUG="1"
      shift
      ;;
    -h|--help)
      print_help
      exit 0
      ;;
    *)
      echo "Unknown argument: $1" >&2
      echo "Use --help for usage." >&2
      exit 2
      ;;
  esac
done

if [[ -n "$GET_SECRET" && -n "$PUT_SECRET" ]]; then
  fail "Use either --get-secret or --put-secret, not both"
fi

if [[ -n "$GET_SECRET" ]]; then
  parse_secret_target "$GET_SECRET" "$KEY_SET"
elif [[ -n "$PUT_SECRET" ]]; then
  parse_secret_target "$PUT_SECRET" "$KEY_SET"
fi

debug "Starting Vault secret retrieval"
debug "CLI arguments parsed"

VAULT_ADDR="${VAULT_ADDR:-PLACEHOLDER_DEFAULT_VAULT_ADDR}"
VAULT_ADDR="${VAULT_ADDR%/}"
: "${VAULT_ROLE_ID:?Missing VAULT_ROLE_ID}"
: "${VAULT_SECRET_ID:?Missing VAULT_SECRET_ID}"
: "${SECRET_PATH:?Missing secret path (use --path)}"
if [[ "$ACTION" == "put" ]]; then
  : "${PUT_VALUE:?Missing value (use --value)}"
fi

for bin in curl jq; do
  if ! command -v "$bin" >/dev/null 2>&1; then
    fail "Missing required command: $bin"
  fi
done

debug "Using VAULT_ADDR=${VAULT_ADDR}"
debug "Using mount point=${MOUNT_POINT}"
debug "Using secret path=${SECRET_PATH}"
if [[ -n "$SECRET_KEY" ]]; then
  debug "Filtering on key=${SECRET_KEY}"
else
  debug "No key filter set; all fields will be printed"
fi
if [[ -n "${VAULT_NAMESPACE:-}" ]]; then
  debug "Using namespace=${VAULT_NAMESPACE}"
else
  debug "No namespace configured"
fi
debug "Using AppRole role_id=$(mask "$VAULT_ROLE_ID") secret_id=$(mask "$VAULT_SECRET_ID")"

AUTH_HEADERS=(-H "Content-Type: application/json")
READ_HEADERS=()

if [[ -n "${VAULT_NAMESPACE:-}" ]]; then
  AUTH_HEADERS+=(-H "X-Vault-Namespace: ${VAULT_NAMESPACE}")
  READ_HEADERS+=(-H "X-Vault-Namespace: ${VAULT_NAMESPACE}")
fi

LOGIN_PAYLOAD="$(jq -n --arg role_id "$VAULT_ROLE_ID" --arg secret_id "$VAULT_SECRET_ID" '{role_id: $role_id, secret_id: $secret_id}')"
debug "Authenticating with AppRole at ${VAULT_ADDR}/v1/auth/approle/login"

if ! LOGIN_RESP="$({
  curl -sS \
    --location \
    --max-redirs 5 \
    --post301 \
    --post302 \
    --post303 \
    "${AUTH_HEADERS[@]}" \
    --request POST \
    --data "$LOGIN_PAYLOAD" \
    --write-out $'\n%{http_code}\n%{url_effective}\n%{num_redirects}' \
    "${VAULT_ADDR}/v1/auth/approle/login"
})"; then
  fail "Login request failed (network/TLS/connection issue)"
fi

LOGIN_REDIRECTS="${LOGIN_RESP##*$'\n'}"
LOGIN_TMP="${LOGIN_RESP%$'\n'*}"
LOGIN_EFFECTIVE_URL="${LOGIN_TMP##*$'\n'}"
LOGIN_TMP="${LOGIN_TMP%$'\n'*}"
LOGIN_STATUS="${LOGIN_TMP##*$'\n'}"
LOGIN_BODY="${LOGIN_TMP%$'\n'*}"
debug "Login response HTTP status=${LOGIN_STATUS}"
debug "Login effective URL=${LOGIN_EFFECTIVE_URL} redirects=${LOGIN_REDIRECTS}"
debug "Login response body=${LOGIN_BODY}"

if [[ ! "$LOGIN_STATUS" =~ ^2 ]]; then
  fail "Vault AppRole login failed with HTTP ${LOGIN_STATUS}"
fi

if ! TOKEN="$(jq -er '.auth.client_token' <<<"$LOGIN_BODY")"; then
  fail "Login succeeded but token missing in response"
fi

debug "Vault token acquired successfully (masked=$(mask "$TOKEN"), length=${#TOKEN})"

READ_HEADERS+=(-H "X-Vault-Token: ${TOKEN}")
READ_URL="${VAULT_ADDR}/v1/${MOUNT_POINT}/data/${SECRET_PATH}"
if [[ "$ACTION" == "get" ]]; then
  debug "Reading secret from ${READ_URL}"

  if ! READ_RESP="$({
    curl -sS \
      --location \
      --max-redirs 5 \
      "${READ_HEADERS[@]}" \
      --write-out $'\n%{http_code}\n%{url_effective}\n%{num_redirects}' \
      "$READ_URL"
  })"; then
    fail "Secret read request failed (network/TLS/connection issue)"
  fi

  READ_REDIRECTS="${READ_RESP##*$'\n'}"
  READ_TMP="${READ_RESP%$'\n'*}"
  READ_EFFECTIVE_URL="${READ_TMP##*$'\n'}"
  READ_TMP="${READ_TMP%$'\n'*}"
  READ_STATUS="${READ_TMP##*$'\n'}"
  RESP="${READ_TMP%$'\n'*}"
  debug "Read response HTTP status=${READ_STATUS}"
  debug "Read effective URL=${READ_EFFECTIVE_URL} redirects=${READ_REDIRECTS}"
  debug "Read response body=${RESP}"

  if [[ ! "$READ_STATUS" =~ ^2 ]]; then
    if ERRORS="$(jq -r '.errors[]?' <<<"$RESP" 2>/dev/null)" && [[ -n "$ERRORS" ]]; then
      log_line "ERROR" "Vault errors: ${ERRORS}"
    fi
    fail "Vault secret read failed with HTTP ${READ_STATUS}"
  fi

  if [[ -n "$SECRET_KEY" ]]; then
    debug "Extracting single key '${SECRET_KEY}'"
    VALUE_TYPE="$(jq -er --arg k "$SECRET_KEY" '.data.data[$k] | type' <<<"$RESP")"
    if [[ "$VALUE_TYPE" == "object" || "$VALUE_TYPE" == "array" ]]; then
      jq -e --arg k "$SECRET_KEY" '.data.data[$k]' <<<"$RESP"
    else
      jq -er --arg k "$SECRET_KEY" '.data.data[$k]' <<<"$RESP"
    fi
  else
    KEY_COUNT="$(jq -er '.data.data | keys | length' <<<"$RESP")"
    if [[ "$KEY_COUNT" -eq 1 ]]; then
      debug "Single-key secret detected; printing value only"
      VALUE_TYPE="$(jq -er '.data.data | to_entries[0].value | type' <<<"$RESP")"
      if [[ "$VALUE_TYPE" == "object" || "$VALUE_TYPE" == "array" ]]; then
        jq -e '.data.data | to_entries[0].value' <<<"$RESP"
      else
        jq -er '.data.data | to_entries[0].value' <<<"$RESP"
      fi
    else
      debug "Multi-key secret detected; printing full JSON object"
      jq -e '.data.data' <<<"$RESP"
    fi
  fi
else
  debug "Preparing put-secret operation for ${READ_URL}"
  debug "Raw --value input=${PUT_VALUE}"

  VALUE_IS_JSON="0"
  VALUE_JSON=""
  VALUE_JSON_TYPE=""
  if VALUE_JSON="$(jq -ce . <<<"$PUT_VALUE" 2>/dev/null)"; then
    VALUE_IS_JSON="1"
    VALUE_JSON_TYPE="$(jq -r 'type' <<<"$VALUE_JSON")"
    debug "--value parsed as JSON type=${VALUE_JSON_TYPE}"
  else
    debug "--value is treated as plain string"
  fi

  if ! CURRENT_RESP="$({
    curl -sS \
      --location \
      --max-redirs 5 \
      "${READ_HEADERS[@]}" \
      --write-out $'\n%{http_code}\n%{url_effective}\n%{num_redirects}' \
      "$READ_URL"
  })"; then
    fail "Secret pre-read request failed (network/TLS/connection issue)"
  fi

  CURRENT_REDIRECTS="${CURRENT_RESP##*$'\n'}"
  CURRENT_TMP="${CURRENT_RESP%$'\n'*}"
  CURRENT_EFFECTIVE_URL="${CURRENT_TMP##*$'\n'}"
  CURRENT_TMP="${CURRENT_TMP%$'\n'*}"
  CURRENT_STATUS="${CURRENT_TMP##*$'\n'}"
  CURRENT_BODY="${CURRENT_TMP%$'\n'*}"
  debug "Pre-read response HTTP status=${CURRENT_STATUS}"
  debug "Pre-read effective URL=${CURRENT_EFFECTIVE_URL} redirects=${CURRENT_REDIRECTS}"
  debug "Pre-read response body=${CURRENT_BODY}"

  SECRET_EXISTS="0"
  EXISTING_DATA='{}'
  if [[ "$CURRENT_STATUS" =~ ^2 ]]; then
    SECRET_EXISTS="1"
    if ! EXISTING_DATA="$(jq -ce '.data.data' <<<"$CURRENT_BODY")"; then
      fail "Could not parse existing secret object from Vault response"
    fi
  elif [[ "$CURRENT_STATUS" == "404" ]]; then
    debug "Secret does not exist yet; will create it"
  else
    if ERRORS="$(jq -r '.errors[]?' <<<"$CURRENT_BODY" 2>/dev/null)" && [[ -n "$ERRORS" ]]; then
      log_line "ERROR" "Vault errors: ${ERRORS}"
    fi
    fail "Vault secret pre-read failed with HTTP ${CURRENT_STATUS}"
  fi

  TARGET_KEY=""
  WRITE_DATA_JSON=""
  if [[ -n "$SECRET_KEY" ]]; then
    TARGET_KEY="$SECRET_KEY"
    debug "Using explicit key '${TARGET_KEY}' for write"
  elif [[ "$VALUE_IS_JSON" == "1" && "$VALUE_JSON_TYPE" == "object" ]]; then
    WRITE_DATA_JSON="$VALUE_JSON"
    debug "Value is a JSON object; writing whole object"
  else
    if [[ "$SECRET_EXISTS" == "1" ]]; then
      EXISTING_KEY_COUNT="$(jq -er 'keys | length' <<<"$EXISTING_DATA")"
      if [[ "$EXISTING_KEY_COUNT" -eq 1 ]]; then
        TARGET_KEY="$(jq -er 'keys[0]' <<<"$EXISTING_DATA")"
        debug "Existing secret has one key; updating key '${TARGET_KEY}'"
      elif [[ "$EXISTING_KEY_COUNT" -eq 0 ]]; then
        TARGET_KEY="$DEFAULT_PUT_KEY"
        debug "Existing secret is empty; using default key '${TARGET_KEY}'"
      else
        fail "Ambiguous write target: secret has multiple keys. Use #<key>, ?key=<key>, or --key."
      fi
    else
      TARGET_KEY="$DEFAULT_PUT_KEY"
      debug "Secret does not exist; using default key '${TARGET_KEY}'"
    fi
  fi

  if [[ -n "$TARGET_KEY" ]]; then
    if [[ "$VALUE_IS_JSON" == "1" ]]; then
      PATCH_JSON="$(jq -cn --arg k "$TARGET_KEY" --argjson v "$VALUE_JSON" '{($k): $v}')"
    else
      PATCH_JSON="$(jq -cn --arg k "$TARGET_KEY" --arg v "$PUT_VALUE" '{($k): $v}')"
    fi
    debug "Write patch JSON=${PATCH_JSON}"
    WRITE_DATA_JSON="$(jq -cn --argjson base "$EXISTING_DATA" --argjson patch "$PATCH_JSON" '$base + $patch')"
  fi

  debug "Resolved write data JSON=${WRITE_DATA_JSON}"

  WRITE_PAYLOAD="$(jq -cn --argjson data "$WRITE_DATA_JSON" '{data: $data}')"
  debug "Write request URL=${READ_URL}"
  debug "Write request payload=${WRITE_PAYLOAD}"
  WRITE_HEADERS=("${READ_HEADERS[@]}" -H "Content-Type: application/json")

  if ! WRITE_RESP="$({
    curl -sS \
      --location \
      --max-redirs 5 \
      --post301 \
      --post302 \
      --post303 \
      "${WRITE_HEADERS[@]}" \
      --request POST \
      --data "$WRITE_PAYLOAD" \
      --write-out $'\n%{http_code}\n%{url_effective}\n%{num_redirects}' \
      "$READ_URL"
  })"; then
    fail "Secret write request failed (network/TLS/connection issue)"
  fi

  WRITE_REDIRECTS="${WRITE_RESP##*$'\n'}"
  WRITE_TMP="${WRITE_RESP%$'\n'*}"
  WRITE_EFFECTIVE_URL="${WRITE_TMP##*$'\n'}"
  WRITE_TMP="${WRITE_TMP%$'\n'*}"
  WRITE_STATUS="${WRITE_TMP##*$'\n'}"
  WRITE_BODY="${WRITE_TMP%$'\n'*}"
  debug "Write response HTTP status=${WRITE_STATUS}"
  debug "Write effective URL=${WRITE_EFFECTIVE_URL} redirects=${WRITE_REDIRECTS}"
  debug "Write response body=${WRITE_BODY}"

  if [[ ! "$WRITE_STATUS" =~ ^2 ]]; then
    if ERRORS="$(jq -r '.errors[]?' <<<"$WRITE_BODY" 2>/dev/null)" && [[ -n "$ERRORS" ]]; then
      log_line "ERROR" "Vault errors: ${ERRORS}"
    fi
    fail "Vault secret write failed with HTTP ${WRITE_STATUS}"
  fi

  jq -e --argjson data "$WRITE_DATA_JSON" '$data' <<<"{}"
fi

debug "Completed successfully"
