#!/usr/bin/env bash
set -euo pipefail

MODE="${1:-fast}"
APP_CONTAINER="${APP_CONTAINER:-cajal-app}"
DB_CONTAINER="${DB_CONTAINER:-cajal-postgres}"
SOCKET_PROXY_CONTAINER="${SOCKET_PROXY_CONTAINER:-cajal-socket-proxy}"
WATCHTOWER_CONTAINER="${WATCHTOWER_CONTAINER:-cajal-watchtower}"
APP_IMAGE="${APP_IMAGE:-cajal-app-local}"
NETWORK_NAME="${NETWORK_NAME:-cajal-net}"
DB_VOLUME="${DB_VOLUME:-cajal-postgres-data}"

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT_DIR"

if ! command -v docker >/dev/null 2>&1; then
  echo "docker is not installed or not in PATH"
  exit 1
fi

compose_restart() {
  local compose_cmd="$1"
  if [ "$compose_cmd" = "docker compose" ]; then
    docker compose restart cajal
  else
    docker-compose restart cajal
  fi
}

compose_rebuild() {
  local compose_cmd="$1"
  if [ "$compose_cmd" = "docker compose" ]; then
    docker compose up -d --build
  else
    docker-compose up -d --build
  fi
}

detect_compose() {
  if docker compose version >/dev/null 2>&1; then
    echo "docker compose"
    return
  fi
  if command -v docker-compose >/dev/null 2>&1; then
    echo "docker-compose"
    return
  fi
  echo ""
}

ensure_env() {
  # ── Create .env from example if missing ───────────────────────────────────
  if [ ! -f .env ]; then
    if [ -f .env.example ]; then
      cp .env.example .env
      echo "INFO: .env created from .env.example"
    else
      echo "ERROR: .env file is missing and no .env.example found."
      exit 1
    fi
  fi

  # ── Auto-generate CAJAL_CONFIG_KEY if missing or default ──────────────────
  local config_key
  config_key="$(grep -E '^CAJAL_CONFIG_KEY=' .env 2>/dev/null | cut -d= -f2- | tr -d "\"'" || true)"
  if [ -z "$config_key" ] || echo "$config_key" | grep -qi 'change_me\|CHANGE_ME'; then
    local new_key
    new_key="$(node -e "console.log(require('crypto').randomBytes(32).toString('base64url'))")"
    if grep -q '^CAJAL_CONFIG_KEY=' .env; then
      sed -i "s|^CAJAL_CONFIG_KEY=.*|CAJAL_CONFIG_KEY=${new_key}|" .env
    else
      echo "CAJAL_CONFIG_KEY=${new_key}" >> .env
    fi
    echo "INFO: CAJAL_CONFIG_KEY auto-generated and saved to .env"
  fi

  # ── Auto-generate CAJAL_DB_PASSWORD if missing or default ─────────────────
  local db_pass
  db_pass="$(grep -E '^CAJAL_DB_PASSWORD=' .env 2>/dev/null | cut -d= -f2- | tr -d "\"'" || true)"
  if [ -z "$db_pass" ] || echo "$db_pass" | grep -qi 'change_me\|CHANGE_ME'; then
    local new_pass
    new_pass="$(node -e "console.log(require('crypto').randomBytes(16).toString('hex'))")"
    if grep -q '^CAJAL_DB_PASSWORD=' .env; then
      sed -i "s|^CAJAL_DB_PASSWORD=.*|CAJAL_DB_PASSWORD=${new_pass}|" .env
    else
      echo "CAJAL_DB_PASSWORD=${new_pass}" >> .env
    fi
    echo "INFO: CAJAL_DB_PASSWORD auto-generated and saved to .env"
    db_pass="$new_pass"
  fi

  # ── Auto-generate CAJAL_WATCHTOWER_TOKEN if missing or default ────────────
  local wt_token
  wt_token="$(grep -E '^CAJAL_WATCHTOWER_TOKEN=' .env 2>/dev/null | cut -d= -f2- | tr -d "\"'" || true)"
  if [ -z "$wt_token" ] || [ "$wt_token" = "changeme" ]; then
    local new_wt_token
    new_wt_token="$(node -e "console.log(require('crypto').randomBytes(32).toString('base64url'))")"
    if grep -q '^CAJAL_WATCHTOWER_TOKEN=' .env; then
      sed -i "s|^CAJAL_WATCHTOWER_TOKEN=.*|CAJAL_WATCHTOWER_TOKEN=${new_wt_token}|" .env
    else
      echo "CAJAL_WATCHTOWER_TOKEN=${new_wt_token}" >> .env
    fi
    echo "INFO: CAJAL_WATCHTOWER_TOKEN auto-generated and saved to .env"
  fi
}

ensure_postgres_container() {
  docker network inspect "$NETWORK_NAME" >/dev/null 2>&1 || docker network create "$NETWORK_NAME" >/dev/null
  docker volume inspect "$DB_VOLUME" >/dev/null 2>&1 || docker volume create "$DB_VOLUME" >/dev/null

  if docker inspect "$DB_CONTAINER" >/dev/null 2>&1; then
    local db_status
    db_status="$(docker inspect -f '{{.State.Status}}' "$DB_CONTAINER")"
    if [ "$db_status" != "running" ]; then
      docker start "$DB_CONTAINER" >/dev/null
    fi
    return
  fi

  local db_pass
  db_pass="$(grep -E '^CAJAL_DB_PASSWORD=' .env 2>/dev/null | cut -d= -f2- | tr -d "\"'" || true)"
  db_pass="${db_pass:-cajal}"

  docker run -d \
    --name "$DB_CONTAINER" \
    --network "$NETWORK_NAME" \
    --restart unless-stopped \
    -e POSTGRES_DB=cajal \
    -e POSTGRES_USER=cajal \
    -e POSTGRES_PASSWORD="$db_pass" \
    -v "$DB_VOLUME:/var/lib/postgresql/data" \
    --health-cmd "pg_isready -U cajal -d cajal" \
    --health-interval 5s \
    --health-timeout 3s \
    --health-retries 20 \
    postgres:16-alpine >/dev/null
}

run_app_container() {
  docker rm -f "$APP_CONTAINER" >/dev/null 2>&1 || true
  docker run -d \
    --name "$APP_CONTAINER" \
    --network "$NETWORK_NAME" \
    --restart unless-stopped \
    --label com.centurylinklabs.watchtower.enable=true \
    --env-file .env \
    -e PORT=4000 \
    -e CAJAL_STORAGE_BACKEND=postgres \
    -e CAJAL_DATABASE_URL=postgresql://cajal:"$(grep -E '^CAJAL_DB_PASSWORD=' .env 2>/dev/null | cut -d= -f2- | tr -d "\"'" || echo cajal)"@"$DB_CONTAINER":5432/cajal \
    -e CAJAL_DATABASE_SSL=disable \
    -p 4000:4000 \
    -p 5514:5514/udp \
    -p 5514:5514/tcp \
    -p 2055:2055/udp \
    -v "$ROOT_DIR/data:/app/data" \
    "$APP_IMAGE" >/dev/null
}

run_socket_proxy_container() {
  docker rm -f "$SOCKET_PROXY_CONTAINER" 2>/dev/null || true
  docker run -d \
    --name "$SOCKET_PROXY_CONTAINER" \
    --network "$NETWORK_NAME" \
    --restart unless-stopped \
    -v /var/run/docker.sock:/var/run/docker.sock \
    -e CONTAINERS=1 \
    -e IMAGES=1 \
    -e AUTH=1 \
    -e POST=1 \
    -e DELETE=1 \
    -e NETWORKS=1 \
    tecnativa/docker-socket-proxy >/dev/null
}

run_watchtower_container() {
  local token
  token="$(grep -E '^CAJAL_WATCHTOWER_TOKEN=' .env 2>/dev/null | cut -d= -f2- | tr -d "\"'" || true)"

  docker rm -f "$WATCHTOWER_CONTAINER" 2>/dev/null || true
  docker run -d \
    --name "$WATCHTOWER_CONTAINER" \
    --network "$NETWORK_NAME" \
    --restart unless-stopped \
    -e DOCKER_HOST=tcp://"$SOCKET_PROXY_CONTAINER":2375 \
    -e WATCHTOWER_HTTP_API_TOKEN="$token" \
    -e WATCHTOWER_LABEL_ENABLE=true \
    -e WATCHTOWER_CLEANUP=true \
    containrrr/watchtower \
    --http-api-update \
    --interval 86400 >/dev/null
}

manual_fast_restart() {
  if ! docker inspect "$APP_CONTAINER" >/dev/null 2>&1; then
    echo "Container '$APP_CONTAINER' does not exist. Run: ./docker-reload.sh rebuild"
    exit 1
  fi
  docker restart "$APP_CONTAINER" >/dev/null
}

manual_rebuild() {
  ensure_env
  ensure_postgres_container
  docker build -t "$APP_IMAGE" .
  run_app_container
  run_socket_proxy_container
  run_watchtower_container
}

main() {
  local compose_cmd
  compose_cmd="$(detect_compose)"

  case "$MODE" in
    fast)
      if [ -n "$compose_cmd" ] && [ -f docker-compose.yml ]; then
        compose_restart "$compose_cmd"
      else
        manual_fast_restart
      fi
      ;;
    rebuild)
      if [ -n "$compose_cmd" ] && [ -f docker-compose.yml ]; then
        compose_rebuild "$compose_cmd"
      else
        manual_rebuild
      fi
      ;;
    *)
      echo "Usage: ./docker-reload.sh [fast|rebuild]"
      exit 1
      ;;
  esac

  docker ps --format 'table {{.Names}}\t{{.Status}}\t{{.Ports}}'
}

main
