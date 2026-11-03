#!/usr/bin/env bash
# One-time server setup. Safe to re-run.
# Usage: bootstrap.sh <domain> <repo-url> <tls-cert-path> <tls-key-path>
set -euo pipefail

DOMAIN="$1"
REPO="$2"
CERT="$3"
KEY="$4"
CONDA="${CONDA:-/root/miniconda3/bin/conda}"
APP=/opt/vps-console

id vpsconsole >/dev/null 2>&1 || useradd --system --home-dir /var/lib/vps-console --shell /usr/sbin/nologin vpsconsole
install -d -m 755 "$APP"
install -d -o vpsconsole -g vpsconsole -m 700 /var/lib/vps-console
install -d -o root -g vpsconsole -m 750 /etc/vps-console

[ -d "$APP/src/.git" ] || git clone --quiet "$REPO" "$APP/src"
[ -x "$APP/env/bin/python" ] || "$CONDA" create -y -q -p "$APP/env" python=3.12
"$APP/env/bin/pip" install --quiet --disable-pip-version-check --root-user-action=ignore -r "$APP/src/requirements.txt"

secret_file() {
  local path="$1" value="$2"
  if [ ! -s "$path" ]; then
    printf '%s' "$value" > "$path"
  fi
  chown root:vpsconsole "$path"
  chmod 640 "$path"
}
secret_file /etc/vps-console/session.key "$("$APP/env/bin/python" -c 'import secrets;print(secrets.token_urlsafe(48))')"
secret_file /etc/vps-console/fernet.key "$("$APP/env/bin/python" -c 'from cryptography.fernet import Fernet;print(Fernet.generate_key().decode())')"
printf 'VPSC_BASE_URL=https://%s\nVPSC_SECURE_COOKIES=1\n' "$DOMAIN" > /etc/vps-console/app.env
chmod 644 /etc/vps-console/app.env
[ -f /etc/vps-console/version.env ] || echo "VPSC_VERSION=$(git -C "$APP/src" rev-parse HEAD)" > /etc/vps-console/version.env

install -m 755 "$APP/src/deploy/deploy.sh" /usr/local/sbin/vps-console-deploy
install -m 644 "$APP/src/deploy/vps-console.service" /etc/systemd/system/vps-console.service
systemctl daemon-reload
systemctl enable --now vps-console

site="/etc/caddy/sites/$DOMAIN.conf"
sed -e "s|__DOMAIN__|$DOMAIN|g" -e "s|__CERT__|$CERT|g" -e "s|__KEY__|$KEY|g" \
  "$APP/src/deploy/caddy-site.conf" > "$site.new"
mv "$site.new" "$site"
caddy validate --config /etc/caddy/Caddyfile --adapter caddyfile >/dev/null
echo "Caddy config valid. Restart caddy to load $DOMAIN (its admin API is off, so reload is not possible)."
