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
TOKEN_INFO="0"
RENEW_TOKEN="0"
RENEW_INCREMENT=""
ENV_FILE=""
VAULT_AUTH_METHOD="${VAULT_AUTH_METHOD:-}"
DEFAULT_PUT_KEY="${VAULT_DEFAULT_PUT_KEY:-value}"

print_help() {
  cat <<'EOF'
vault.sh - Read/Write HashiCorp Vault KV v2 secrets

Usage:
  vault.sh [options]

Options:
  --get-secret <path>    Full Vault API path (/v1/<mount>/data/<path>)
  --put-secret <path>    Full Vault API path (/v1/<mount>/data/<path>) to write
  --value <value>        Value to write (used with --put-secret)
  --mount-point <name>   KV v2 mount point (default: VAULT_MOUNT_POINT or secret)
  --path <path>          Secret path inside KV v2
  --key <key>            Secret field key to extract
  --token-info           Show token TTL, expiry, and renewable status
  --renew-token          Renew current token (if renewable)
  --increment <duration> Requested renewal increment (e.g. 30m, 1h)
  --env-file <path>      Load environment variables from file before execution
  --debug                Enable debug logs
  -h, --help             Show this help

Authentication:
  - Auth method via VAULT_AUTH_METHOD (AppRole|token, optional)
  - If VAULT_AUTH_METHOD is not set, script auto-selects:
      VAULT_TOKEN set => token
      VAULT_ROLE_ID and VAULT_SECRET_ID set => AppRole
  - AppRole requires:
      VAULT_ROLE_ID + VAULT_SECRET_ID
  - token uses:
      VAULT_TOKEN

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

  # Show token metadata
  ./vault.sh --token-info

  # Renew token and request increment
  ./vault.sh --renew-token --increment 1h

  # Load variables from file
  ./vault.sh --env-file .vault.env --get-secret "/v1/secret/data/team/app#token"

Common troubleshooting:
  - Permission denied => authenticated, but policy lacks read on <mount>/data/<path>.
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

load_env_file() {
  local file_path="$1"

  if [[ ! -f "$file_path" ]]; then
    fail "Env file not found: ${file_path}"
  fi
  if [[ ! -r "$file_path" ]]; then
    fail "Env file is not readable: ${file_path}"
  fi

  debug "Loading environment from file=${file_path}"
  set -a
  # shellcheck disable=SC1090
  source "$file_path"
  set +a
}

load_token_from_env() {
  if [[ -n "${VAULT_TOKEN:-}" ]]; then
    TOKEN="$VAULT_TOKEN"
    return
  fi

  fail "Missing token: set VAULT_TOKEN"
}

auth_with_approle() {
  : "${VAULT_ROLE_ID:?Missing VAULT_ROLE_ID}"
  : "${VAULT_SECRET_ID:?Missing VAULT_SECRET_ID}"

  local login_payload login_resp login_redirects login_tmp login_effective_url login_status login_body
  login_payload="$(jq -n --arg role_id "$VAULT_ROLE_ID" --arg secret_id "$VAULT_SECRET_ID" '{role_id: $role_id, secret_id: $secret_id}')"
  debug "Authenticating with AppRole at ${VAULT_ADDR}/v1/auth/approle/login"

  if ! login_resp="$({
    curl -sS \
      --location \
      --max-redirs 5 \
      --post301 \
      --post302 \
      --post303 \
      "${AUTH_HEADERS[@]}" \
      --request POST \
      --data "$login_payload" \
      --write-out $'\n%{http_code}\n%{url_effective}\n%{num_redirects}' \
      "${VAULT_ADDR}/v1/auth/approle/login"
  })"; then
    fail "Login request failed (network/TLS/connection issue)"
  fi

  login_redirects="${login_resp##*$'\n'}"
  login_tmp="${login_resp%$'\n'*}"
  login_effective_url="${login_tmp##*$'\n'}"
  login_tmp="${login_tmp%$'\n'*}"
  login_status="${login_tmp##*$'\n'}"
  login_body="${login_tmp%$'\n'*}"
  debug "Login response HTTP status=${login_status}"
  debug "Login effective URL=${login_effective_url} redirects=${login_redirects}"
  debug "Login response body=${login_body}"

  if [[ ! "$login_status" =~ ^2 ]]; then
    fail "Vault AppRole login failed with HTTP ${login_status}"
  fi

  if ! TOKEN="$(jq -er '.auth.client_token' <<<"$login_body")"; then
    fail "Login succeeded but token missing in response"
  fi
}

resolve_token() {
  local method="$VAULT_AUTH_METHOD"

  if [[ -z "$method" ]]; then
    if [[ -n "${VAULT_TOKEN:-}" ]]; then
      method="token"
    elif [[ -n "${VAULT_ROLE_ID:-}" && -n "${VAULT_SECRET_ID:-}" ]]; then
      method="AppRole"
    else
      fail "Could not determine auth method. Set VAULT_AUTH_METHOD=token with VAULT_TOKEN, or VAULT_AUTH_METHOD=AppRole with VAULT_ROLE_ID and VAULT_SECRET_ID."
    fi
  fi

  VAULT_AUTH_METHOD="$method"

  case "$method" in
    approle|AppRole)
      debug "Auth method=AppRole role_id=$(mask "${VAULT_ROLE_ID:-}") secret_id=$(mask "${VAULT_SECRET_ID:-}")"
      auth_with_approle
      ;;
    token)
      debug "Auth method=token"
      load_token_from_env
      ;;
    *)
      fail "Unsupported VAULT_AUTH_METHOD='${method}' (expected AppRole or token)"
      ;;
  esac
}

show_token_info() {
  local lookup_url resp tmp status body redirects effective_url
  lookup_url="${VAULT_ADDR}/v1/auth/token/lookup-self"

  if ! resp="$({
    curl -sS \
      --location \
      --max-redirs 5 \
      "${READ_HEADERS[@]}" \
      --request GET \
      --write-out $'\n%{http_code}\n%{url_effective}\n%{num_redirects}' \
      "${lookup_url}"
  })"; then
    fail "Token lookup request failed (network/TLS/connection issue)"
  fi

  redirects="${resp##*$'\n'}"
  tmp="${resp%$'\n'*}"
  effective_url="${tmp##*$'\n'}"
  tmp="${tmp%$'\n'*}"
  status="${tmp##*$'\n'}"
  body="${tmp%$'\n'*}"

  if [[ ! "$status" =~ ^2 ]]; then
    if ERRORS="$(jq -r '.errors[]?' <<<"$body" 2>/dev/null)" && [[ -n "$ERRORS" ]]; then
      log_line "ERROR" "Vault errors: ${ERRORS}"
    fi
    fail "Vault token lookup failed with HTTP ${status}"
  fi

  jq -e '{ttl: .data.ttl, expire_time: .data.expire_time, renewable: .data.renewable, orphan: .data.orphan, policies: .data.policies}' <<<"$body"
}

renew_token() {
  local renew_url resp tmp status body redirects effective_url payload
  renew_url="${VAULT_ADDR}/v1/auth/token/renew-self"

  if [[ -n "$RENEW_INCREMENT" ]]; then
    payload="$(jq -cn --arg increment "$RENEW_INCREMENT" '{increment: $increment}')"
  else
    payload='{}'
  fi

  if ! resp="$({
    curl -sS \
      --location \
      --max-redirs 5 \
      "${READ_HEADERS[@]}" \
      -H "Content-Type: application/json" \
      --request POST \
      --data "$payload" \
      --write-out $'\n%{http_code}\n%{url_effective}\n%{num_redirects}' \
      "${renew_url}"
  })"; then
    fail "Token renew request failed (network/TLS/connection issue)"
  fi

  redirects="${resp##*$'\n'}"
  tmp="${resp%$'\n'*}"
  effective_url="${tmp##*$'\n'}"
  tmp="${tmp%$'\n'*}"
  status="${tmp##*$'\n'}"
  body="${tmp%$'\n'*}"

  if [[ ! "$status" =~ ^2 ]]; then
    if ERRORS="$(jq -r '.errors[]?' <<<"$body" 2>/dev/null)" && [[ -n "$ERRORS" ]]; then
      log_line "ERROR" "Vault errors: ${ERRORS}"
    fi
    fail "Vault token renew failed with HTTP ${status}"
  fi

  jq -e '{renewed: true, ttl: .auth.lease_duration, renewable: .auth.renewable}' <<<"$body"
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
    --token-info)
      TOKEN_INFO="1"
      ACTION="token_info"
      shift
      ;;
    --renew-token)
      RENEW_TOKEN="1"
      ACTION="renew_token"
      shift
      ;;
    --increment)
      RENEW_INCREMENT="$2"
      shift 2
      ;;
    --env-file)
      ENV_FILE="$2"
      shift 2
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

if [[ -n "$ENV_FILE" ]]; then
  load_env_file "$ENV_FILE"
fi

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
if [[ "$ACTION" != "token_info" && "$ACTION" != "renew_token" ]]; then
  : "${SECRET_PATH:?Missing secret path (use --path)}"
fi
if [[ "$ACTION" == "put" ]]; then
  : "${PUT_VALUE:?Missing value (use --value)}"
fi

for bin in curl jq; do
  if ! command -v "$bin" >/dev/null 2>&1; then
    fail "Missing required command: $bin"
  fi
done

debug "Using VAULT_ADDR=${VAULT_ADDR}"
debug "Using auth method=${VAULT_AUTH_METHOD}"
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
AUTH_HEADERS=(-H "Content-Type: application/json")
READ_HEADERS=()

if [[ -n "${VAULT_NAMESPACE:-}" ]]; then
  AUTH_HEADERS+=(-H "X-Vault-Namespace: ${VAULT_NAMESPACE}")
  READ_HEADERS+=(-H "X-Vault-Namespace: ${VAULT_NAMESPACE}")
fi

resolve_token

debug "Vault token acquired successfully (masked=$(mask "$TOKEN"), length=${#TOKEN})"

READ_HEADERS+=(-H "X-Vault-Token: ${TOKEN}")
if [[ "$ACTION" == "token_info" ]]; then
  show_token_info
  exit 0
fi
if [[ "$ACTION" == "renew_token" ]]; then
  renew_token
  exit 0
fi

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
