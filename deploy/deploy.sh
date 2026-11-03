#!/usr/bin/env bash
# Forced command for the CI deploy key (installed as /usr/local/sbin/vps-console-deploy).
# The key can only run:  deploy <40-hex commit on origin/main>
# Deploys that commit, checks /healthz reports it, and rolls back otherwise.
set -euo pipefail

APP=/opt/vps-console
SRC="$APP/src"
PIP="$APP/env/bin/pip"
PORT="${VPSC_PORT:-8091}"
cmd="${SSH_ORIGINAL_COMMAND:-$*}"

if [[ ! "$cmd" =~ ^deploy\ ([0-9a-f]{40})$ ]]; then
  echo "usage: deploy <commit sha>" >&2
  exit 2
fi
sha="${BASH_REMATCH[1]}"

exec 9>/run/vps-console-deploy.lock
flock -w 600 9

cd "$SRC"
git fetch --quiet origin main
if ! git merge-base --is-ancestor "$sha" origin/main; then
  echo "refusing: $sha is not on origin/main" >&2
  exit 3
fi
prev="$(git rev-parse HEAD)"

activate() {
  git checkout --quiet --detach "$1"
  "$PIP" install --quiet --disable-pip-version-check -r requirements.txt
  echo "VPSC_VERSION=$1" > /etc/vps-console/version.env
  systemctl restart vps-console
}

healthy() {
  for _ in $(seq 1 40); do
    sleep 1
    if curl -fsS "http://127.0.0.1:$PORT/healthz" 2>/dev/null | grep -q "\"version\":\"$1\""; then
      return 0
    fi
  done
  return 1
}

echo "deploying $sha (was $prev)"
activate "$sha"
if healthy "$sha"; then
  echo "deployed $sha"
  exit 0
fi

echo "health check failed, rolling back to $prev" >&2
journalctl -u vps-console -n 30 --no-pager >&2 || true
activate "$prev"
healthy "$prev" && echo "rolled back to $prev" >&2
exit 1
