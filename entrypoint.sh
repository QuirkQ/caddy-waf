#!/bin/sh
set -eu

# ============================
# User setup (PUID/PGID)
# ============================

PUID="${PUID:-1000}"
PGID="${PGID:-1000}"

setup_user() {
  CUR_UID=$(id -u caddy)
  CUR_GID=$(id -g caddy)

  if [ "$CUR_GID" != "$PGID" ]; then
    sed -i "s/^caddy:x:${CUR_GID}:/caddy:x:${PGID}:/" /etc/group
    sed -i "s/^\(caddy:[^:]*:[^:]*:\)${CUR_GID}:/\1${PGID}:/" /etc/passwd
  fi

  if [ "$CUR_UID" != "$PUID" ]; then
    sed -i "s/^caddy:\([^:]*\):${CUR_UID}:/caddy:\1:${PUID}:/" /etc/passwd
  fi

  chown -R caddy:caddy /etc/caddy /data /config 2>/dev/null || true
}

if [ "$(id -u)" = "0" ]; then
  setup_user
fi

# ============================
# Validators
# ============================

is_port() {
  case "$1" in ''|*[!0-9]*) return 1 ;; esac
  [ "$1" -ge 1 ] && [ "$1" -le 65535 ]
}

is_uint() {
  case "$1" in ''|*[!0-9]*) return 1 ;; esac
  [ "$1" -ge 0 ]
}

# Domain or *.domain or domain:port — alphanumerics, dot, dash, asterisk, colon
is_domain() {
  case "$1" in
    ''|*[!A-Za-z0-9.:*-]*) return 1 ;;
  esac
  return 0
}

# Upstream — host[:port], or scheme://host[:port][/path]. No spaces or quotes.
is_upstream() {
  case "$1" in
    ''|*[!A-Za-z0-9.:/_+-]*) return 1 ;;
  esac
  return 0
}

# Escape for Caddyfile double-quoted strings (backslash, then double quote).
esc() {
  printf '%s' "$1" | sed 's/\\/\\\\/g; s/"/\\"/g'
}

# ============================
# TLS / cert injection
# ============================

TLS_DIR="/etc/caddy/tls"
mkdir -p "$TLS_DIR"
chown caddy:caddy "$TLS_DIR" 2>/dev/null || true

decode_b64() {
  varname="$1"; dest="$2"; mode="$3"
  eval "val=\${${varname}:-}"
  if [ -n "$val" ]; then
    echo "$val" | base64 -d > "$dest"
    chmod "$mode" "$dest"
    chown caddy:caddy "$dest" 2>/dev/null || true
  fi
}

decode_b64 TLS_CERT_B64 "$TLS_DIR/server.crt" 644
decode_b64 TLS_KEY_B64  "$TLS_DIR/server.key" 600
decode_b64 TLS_CA_B64   "$TLS_DIR/ca.crt"     644

TLS_CERT_FILE="${TLS_CERT_FILE:-$TLS_DIR/server.crt}"
TLS_KEY_FILE="${TLS_KEY_FILE:-$TLS_DIR/server.key}"

# ============================
# Health port
# ============================

HEALTH_PORT="${HEALTH_PORT:-8080}"
if [ "$HEALTH_PORT" != "0" ] && ! is_port "$HEALTH_PORT"; then
  echo "ERROR: HEALTH_PORT must be 0 or 1-65535, got: $HEALTH_PORT" >&2
  exit 1
fi

# ============================
# Caddyfile generation
# ============================

CADDYFILE="/etc/caddy/Caddyfile"
CONF_DIR="/etc/caddy/conf.d"
mkdir -p "$CONF_DIR"
chown caddy:caddy "$CONF_DIR" 2>/dev/null || true

generate_caddyfile() {
  CADDY_DOMAIN="${CADDY_DOMAIN:-}"
  CADDY_UPSTREAM="${CADDY_UPSTREAM:-}"

  if [ -z "$CADDY_DOMAIN" ] || [ -z "$CADDY_UPSTREAM" ]; then
    echo "ERROR: set CADDY_DOMAIN + CADDY_UPSTREAM, mount /etc/caddy/Caddyfile, or set CADDYFILE_B64" >&2
    exit 1
  fi

  if ! is_domain "$CADDY_DOMAIN"; then
    echo "ERROR: CADDY_DOMAIN contains invalid characters: $CADDY_DOMAIN" >&2
    exit 1
  fi
  if ! is_upstream "$CADDY_UPSTREAM"; then
    echo "ERROR: CADDY_UPSTREAM contains invalid characters: $CADDY_UPSTREAM" >&2
    exit 1
  fi

  WAF_MODE="${WAF_MODE:-On}"
  case "$WAF_MODE" in
    On|Off|DetectionOnly) ;;
    *) echo "ERROR: WAF_MODE must be On|Off|DetectionOnly, got: $WAF_MODE" >&2; exit 1 ;;
  esac

  PARANOIA="${WAF_PARANOIA:-1}"
  if ! is_uint "$PARANOIA" || [ "$PARANOIA" -lt 1 ] || [ "$PARANOIA" -gt 4 ]; then
    echo "ERROR: WAF_PARANOIA must be 1-4, got: $PARANOIA" >&2
    exit 1
  fi

  IN_THRESHOLD="${WAF_ANOMALY_INBOUND:-5}"
  OUT_THRESHOLD="${WAF_ANOMALY_OUTBOUND:-4}"
  is_uint "$IN_THRESHOLD"  || { echo "ERROR: WAF_ANOMALY_INBOUND must be a non-negative integer" >&2; exit 1; }
  is_uint "$OUT_THRESHOLD" || { echo "ERROR: WAF_ANOMALY_OUTBOUND must be a non-negative integer" >&2; exit 1; }

  HTTP_PORT="${CADDY_HTTP_PORT:-80}"
  HTTPS_PORT="${CADDY_HTTPS_PORT:-443}"
  is_port "$HTTP_PORT"  || { echo "ERROR: CADDY_HTTP_PORT must be a valid port" >&2; exit 1; }
  is_port "$HTTPS_PORT" || { echo "ERROR: CADDY_HTTPS_PORT must be a valid port" >&2; exit 1; }

  # Decode custom WAF directives into a separate file. Keeping user-supplied
  # rules out of the Caddyfile avoids cross-format escaping (Caddyfile string
  # rules + modsec directive rules).
  WAF_RULES_FILE="$CONF_DIR/custom-rules.conf"
  rm -f "$WAF_RULES_FILE"
  if [ -n "${WAF_CUSTOM_RULES_B64:-}" ]; then
    echo "$WAF_CUSTOM_RULES_B64" | base64 -d > "$WAF_RULES_FILE"
    chmod 400 "$WAF_RULES_FILE"
    chown caddy:caddy "$WAF_RULES_FILE" 2>/dev/null || true
  fi

  # Pre-CRS tuning file — overrides defaults set in crs-setup.conf
  PRE_CRS_FILE="$CONF_DIR/pre-crs.conf"
  cat > "$PRE_CRS_FILE" <<PREEOF
SecAction "id:900000,phase:1,nolog,pass,t:none,setvar:tx.blocking_paranoia_level=${PARANOIA},setvar:tx.detection_paranoia_level=${PARANOIA}"
SecAction "id:900110,phase:1,nolog,pass,t:none,setvar:tx.inbound_anomaly_score_threshold=${IN_THRESHOLD},setvar:tx.outbound_anomaly_score_threshold=${OUT_THRESHOLD}"
PREEOF
  chmod 400 "$PRE_CRS_FILE"
  chown caddy:caddy "$PRE_CRS_FILE" 2>/dev/null || true

  HAS_MANUAL_TLS=false
  if [ -f "$TLS_CERT_FILE" ] && [ -f "$TLS_KEY_FILE" ]; then
    HAS_MANUAL_TLS=true
  fi
  TLS_INTERNAL="${TLS_INTERNAL:-false}"

  : > "$CADDYFILE"

  # Global options
  {
    echo "{"
    echo "    order coraza_waf first"
    [ "$HTTP_PORT"  != "80"  ] && printf '    http_port %s\n'  "$HTTP_PORT"
    [ "$HTTPS_PORT" != "443" ] && printf '    https_port %s\n' "$HTTPS_PORT"
    [ -n "${EMAIL:-}" ]   && printf '    email "%s"\n'   "$(esc "$EMAIL")"
    [ -n "${ACME_CA:-}" ] && printf '    acme_ca "%s"\n' "$(esc "$ACME_CA")"
    if [ -n "${ADMIN_API:-}" ]; then
      printf '    admin "%s"\n' "$(esc "$ADMIN_API")"
    else
      echo "    admin off"
    fi
    echo "    log {"
    printf '        level %s\n' "$(esc "${LOG_LEVEL:-INFO}")"
    echo "    }"
    echo "}"
    echo ""
  } >> "$CADDYFILE"

  # WAF snippet — reusable per-site via `import waf`
  {
    echo "(waf) {"
    echo "    coraza_waf {"
    echo "        directives \`"
    echo "            SecRuleEngine ${WAF_MODE}"
    echo "            SecRequestBodyAccess On"
    echo "            SecRequestBodyLimit 13107200"
    echo "            SecRequestBodyNoFilesLimit 131072"
    echo "            SecRequestBodyLimitAction Reject"
    echo "            SecResponseBodyAccess On"
    echo "            SecResponseBodyLimit 1048576"
    echo "            SecResponseBodyLimitAction ProcessPartial"
    echo "            SecResponseBodyMimeType text/plain text/html text/xml application/json"
    echo "            SecAuditEngine RelevantOnly"
    echo "            SecAuditLogParts ABIJDEFHZ"
    echo "            SecAuditLog /dev/stdout"
    echo "            SecAuditLogType Serial"
    echo "            Include $PRE_CRS_FILE"
    echo "            Include /etc/caddy/crs/crs-setup.conf"
    echo "            Include /etc/caddy/crs/rules/*.conf"
    if [ -f "$WAF_RULES_FILE" ]; then
      echo "            Include $WAF_RULES_FILE"
    fi
    echo "        \`"
    echo "    }"
    echo "}"
    echo ""
  } >> "$CADDYFILE"

  # Site block
  {
    echo "${CADDY_DOMAIN} {"
    echo "    import waf"
    if [ "$HAS_MANUAL_TLS" = "true" ]; then
      printf '    tls "%s" "%s"\n' "$(esc "$TLS_CERT_FILE")" "$(esc "$TLS_KEY_FILE")"
    elif [ "$TLS_INTERNAL" = "true" ]; then
      echo "    tls internal"
    fi
    printf '    reverse_proxy %s\n' "$CADDY_UPSTREAM"
    echo "}"
  } >> "$CADDYFILE"

  chmod 400 "$CADDYFILE"
  chown caddy:caddy "$CADDYFILE" 2>/dev/null || true
}

# 1) Full Caddyfile via base64 takes precedence over env-var generation.
if [ -n "${CADDYFILE_B64:-}" ]; then
  echo "$CADDYFILE_B64" | base64 -d > "$CADDYFILE"
  chmod 400 "$CADDYFILE"
  chown caddy:caddy "$CADDYFILE" 2>/dev/null || true
fi

# 2) Otherwise, if no Caddyfile is mounted at /etc/caddy/Caddyfile, generate one.
if [ ! -f "$CADDYFILE" ]; then
  generate_caddyfile
fi

# Validate the resulting Caddyfile before launching. Validate provisions
# modules just like `run` does, including the internal CA, so it must run as
# the caddy user — otherwise root-owned files end up in /data and the real
# run later can't read them.
if [ "$(id -u)" = "0" ]; then
  su-exec caddy /usr/bin/caddy validate --config "$CADDYFILE" --adapter caddyfile >/dev/null
else
  /usr/bin/caddy validate --config "$CADDYFILE" --adapter caddyfile >/dev/null
fi

# ============================
# Health endpoint
# ============================

start_health_server() {
  HEALTH_DIR="/tmp/health"
  mkdir -p "$HEALTH_DIR/cgi-bin"

  cat > "$HEALTH_DIR/cgi-bin/health" <<'HEALTHEOF'
#!/bin/sh
if pgrep caddy > /dev/null 2>&1; then
  printf 'Content-Type: text/plain\r\n\r\nok\n'
else
  printf 'Status: 503\r\nContent-Type: text/plain\r\n\r\ncaddy not running\n'
fi
HEALTHEOF
  chmod +x "$HEALTH_DIR/cgi-bin/health"

  httpd -p "$HEALTH_PORT" -h "$HEALTH_DIR"
}

if [ "$HEALTH_PORT" != "0" ]; then
  start_health_server
fi

# ============================
# Launch Caddy
# ============================

if [ "$(id -u)" = "0" ]; then
  exec su-exec caddy /usr/bin/caddy run --config "$CADDYFILE" --adapter caddyfile
else
  exec /usr/bin/caddy run --config "$CADDYFILE" --adapter caddyfile
fi
