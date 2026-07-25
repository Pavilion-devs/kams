#!/usr/bin/env bash
# Bring up SigNoz via Foundry and make it ready to receive telemetry.
#
# The non-obvious step is org creation. SigNoz's collector fetches its pipeline
# config from the server over OpAMP, and the server refuses to register an agent
# before an organization exists ("cannot create agent without orgId"). Until then
# the collector starts its extensions but NOT its OTLP receivers -- so 4317/4318
# look open from outside (Docker publishes the ports regardless) while every
# connection is reset. Telemetry silently goes nowhere.
#
# Idempotent: safe to re-run.

set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO"

SIGNOZ_URL="${SIGNOZ_URL:-http://localhost:8080}"
ADMIN_EMAIL="${KAMS_ADMIN_EMAIL:-admin@kams.local}"
ADMIN_NAME="${KAMS_ADMIN_NAME:-Kams Admin}"
ORG_NAME="${KAMS_ORG_NAME:-Kams}"
# SigNoz requires >=12 chars with upper, lower, digit, and symbol.
ADMIN_PASSWORD="${KAMS_ADMIN_PASSWORD:-Kams!Dev2026}"

say() { printf '\033[1;36m==>\033[0m %s\n' "$*"; }
die() { printf '\033[1;31mERROR:\033[0m %s\n' "$*" >&2; exit 1; }

command -v docker >/dev/null || die "docker not found"
docker info >/dev/null 2>&1 || die "docker daemon not running -- start Docker Desktop"

export PATH="$HOME/.local/bin:$PATH"
if ! command -v foundryctl >/dev/null; then
  say "installing foundryctl"
  curl -fsSL https://signoz.io/foundry.sh | bash
fi

say "forging deployment files (writes casting.yaml.lock)"
foundryctl forge -f casting.yaml

say "casting SigNoz (first run pulls ~3.5GB of images)"
foundryctl cast -f casting.yaml

say "waiting for the SigNoz API"
for _ in $(seq 1 60); do
  [ "$(curl -s -o /dev/null -w '%{http_code}' "$SIGNOZ_URL/api/v1/health" || true)" = "200" ] && break
  sleep 5
done
[ "$(curl -s -o /dev/null -w '%{http_code}' "$SIGNOZ_URL/api/v1/health")" = "200" ] \
  || die "SigNoz API never became healthy"

# --- the step that actually matters -------------------------------------------
if curl -s "$SIGNOZ_URL/api/v1/version" | grep -q '"setupCompleted":true'; then
  say "org already exists, skipping registration"
else
  say "creating the first org (required before the collector can register)"
  resp="$(curl -s -X POST "$SIGNOZ_URL/api/v1/register" \
    -H 'Content-Type: application/json' \
    -d "{\"name\":\"$ADMIN_NAME\",\"orgName\":\"$ORG_NAME\",\"email\":\"$ADMIN_EMAIL\",\"password\":\"$ADMIN_PASSWORD\"}")"
  echo "$resp" | grep -q '"status":"success"' || die "registration failed: $resp"
  say "org created, admin=$ADMIN_EMAIL"
fi

# A collector that has been failing its OpAMP handshake will keep backing off.
# Restarting makes it pick up the now-registerable state immediately.
say "restarting ingester so it registers and starts its OTLP receivers"
docker restart signoz-ingester-1 >/dev/null

say "waiting for OTLP receivers to bind (4317/4318)"
ok=""
for _ in $(seq 1 30); do
  if [ "$(curl -s -o /dev/null -w '%{http_code}' -X POST "http://localhost:4318/v1/traces" \
        -H 'Content-Type: application/json' -d '{"resourceSpans":[]}' || true)" = "200" ]; then
    ok=1; break
  fi
  sleep 4
done
[ -n "$ok" ] || die "OTLP receivers never started -- check: docker logs signoz-signoz-0 | grep opamp"

cat <<EOF

  SigNoz is ready.

    UI          $SIGNOZ_URL   ($ADMIN_EMAIL / $ADMIN_PASSWORD)
    OTLP gRPC   localhost:4317
    OTLP HTTP   localhost:4318
    SigNoz MCP  localhost:8000/mcp   (needs a SIGNOZ-API-KEY header)

  Next: create an API key in the UI under Settings -> API Keys and put it in
  .env as SIGNOZ_API_KEY, so dashboards and alerts can be provisioned as code.

EOF
