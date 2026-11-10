#!/bin/sh
# OpenHeadscaleGUI – Installer / Updater / Uninstaller
#
#   curl -fsSL https://raw.githubusercontent.com/testbild-media/openHeadscaleGUI/main/install.sh | sudo sh
#
# Optionen (als Argumente nach "sh -s --" oder als Umgebungsvariablen):
#   --domain admin.example.com   Domain der Verwaltungsoberfläche   (OHG_ADMIN_DOMAIN)
#   --email  admin@example.com   E-Mail für Let's Encrypt            (OHG_ACME_EMAIL)
#   --version v1.2.3             bestimmte Version statt der neuesten (OHG_VERSION)
#   --from-source                aus dem Quellcode bauen (lädt bei Bedarf Go herunter)
#   --yes                        keine Rückfragen
#   --uninstall [--purge]        entfernen (--purge löscht auch Konfiguration und Daten)
#
# Beispiel ohne Rückfragen:
#   curl -fsSL …/install.sh | sudo sh -s -- --yes --domain admin.example.com --email ich@example.com
set -eu

REPO="testbild-media/openHeadscaleGUI"
HEADSCALE_VERSION="${HEADSCALE_VERSION:-0.29.7}"
GO_VERSION="${GO_VERSION:-1.27.3}"
OHG_VERSION="${OHG_VERSION:-latest}"
SOURCE_REF="${OHG_SOURCE_REF:-main}"

BIN=/usr/local/bin/ohg
LIBDIR=/usr/local/lib/ohg
ETC=/etc/ohg
DATA=/var/lib/ohg
UNIT=/etc/systemd/system/ohg.service
SVC_USER=ohg

MODE=install
PURGE=0
FROM_SOURCE=0
ASSUME_YES=0
DOMAIN="${OHG_ADMIN_DOMAIN:-}"
EMAIL="${OHG_ACME_EMAIL:-}"

# ---------------------------------------------------------------- helpers
if [ -t 1 ]; then
	C_B="$(printf '\033[1m')"; C_BLUE="$(printf '\033[1;34m')"; C_Y="$(printf '\033[1;33m')"
	C_R="$(printf '\033[1;31m')"; C_G="$(printf '\033[1;32m')"; C_0="$(printf '\033[0m')"
else
	C_B=""; C_BLUE=""; C_Y=""; C_R=""; C_G=""; C_0=""
fi
info() { printf '%s==>%s %s\n' "$C_BLUE" "$C_0" "$*"; }
ok() { printf '%s ✓%s %s\n' "$C_G" "$C_0" "$*"; }
warn() { printf '%s !!%s %s\n' "$C_Y" "$C_0" "$*" >&2; }
die() { printf '%sFehler:%s %s\n' "$C_R" "$C_0" "$*" >&2; exit 1; }

have_tty() { [ "$ASSUME_YES" = 0 ] && [ -r /dev/tty ] && [ -w /dev/tty ]; }

# ask "Frage" "Default" -> answer on stdout
ask() {
	if have_tty; then
		if [ -n "$2" ]; then printf '%s [%s]: ' "$1" "$2" >/dev/tty; else printf '%s: ' "$1" >/dev/tty; fi
		read -r _a </dev/tty || _a=""
		[ -n "$_a" ] && printf '%s' "$_a" || printf '%s' "$2"
	else
		printf '%s' "$2"
	fi
}

# confirm "Frage" default(y|n) -> 0 = yes
confirm() {
	if ! have_tty; then [ "$2" = y ]; return; fi
	_d="j/N"; [ "$2" = y ] && _d="J/n"
	printf '%s [%s] ' "$1" "$_d" >/dev/tty
	read -r _a </dev/tty || _a=""
	case "$_a" in
	[jJyY]*) return 0 ;;
	[nN]*) return 1 ;;
	*) [ "$2" = y ] ;;
	esac
}

fetch() { # fetch URL FILE
	if command -v curl >/dev/null 2>&1; then
		curl -fsSL --retry 3 --connect-timeout 15 -o "$2" "$1"
	elif command -v wget >/dev/null 2>&1; then
		wget -q -O "$2" "$1"
	else
		die "curl oder wget wird benötigt"
	fi
}

verify_sha256() { # verify FILE EXPECTED_HASH
	_got="$(sha256sum "$1" | awk '{print $1}')"
	[ "$_got" = "$2" ] || die "Prüfsumme für $(basename "$1") stimmt nicht (erwartet $2, erhalten $_got)"
}

# ---------------------------------------------------------------- args
while [ $# -gt 0 ]; do
	case "$1" in
	--uninstall) MODE=uninstall ;;
	--purge) PURGE=1 ;;
	--from-source) FROM_SOURCE=1 ;;
	-y | --yes) ASSUME_YES=1 ;;
	--domain) DOMAIN="${2:-}"; shift ;;
	--email) EMAIL="${2:-}"; shift ;;
	--version) OHG_VERSION="${2:-}"; shift ;;
	-h | --help)
		sed -n '2,17p' "$0" 2>/dev/null || true
		exit 0
		;;
	*) die "Unbekannte Option: $1" ;;
	esac
	shift
done

# ---------------------------------------------------------------- checks
[ "$(uname -s)" = Linux ] || die "OpenHeadscaleGUI läuft nur unter Linux"
[ "$(id -u)" = 0 ] || die "Bitte als root ausführen, z. B.: curl -fsSL https://raw.githubusercontent.com/$REPO/main/install.sh | sudo sh"
if ! command -v systemctl >/dev/null 2>&1 || [ ! -d /run/systemd/system ]; then
	die "systemd wird benötigt (Debian/Ubuntu/…)"
fi

case "$(uname -m)" in
x86_64 | amd64) ARCH=amd64 ;;
aarch64 | arm64) ARCH=arm64 ;;
*) die "Nicht unterstützte Architektur: $(uname -m) (unterstützt: amd64, arm64)" ;;
esac

TMP="$(mktemp -d)"
cleanup() { rm -rf "$TMP"; }
trap cleanup EXIT INT TERM

# ---------------------------------------------------------------- uninstall
if [ "$MODE" = uninstall ]; then
	info "Entferne OpenHeadscaleGUI"
	systemctl disable --now ohg >/dev/null 2>&1 || true
	rm -f "$UNIT" "$BIN"
	rm -rf "$LIBDIR"
	systemctl daemon-reload || true
	ok "Programm und Dienst entfernt"
	if [ "$PURGE" = 1 ]; then
		if [ "$ASSUME_YES" = 1 ] || confirm "Konfiguration ($ETC) und ALLE Daten ($DATA) unwiderruflich löschen?" n; then
			rm -rf "$ETC" "$DATA"
			userdel "$SVC_USER" >/dev/null 2>&1 || true
			ok "Konfiguration, Daten und Benutzer gelöscht"
		else
			warn "Daten bleiben erhalten: $ETC, $DATA"
		fi
	else
		info "Konfiguration und Daten bleiben erhalten: $ETC, $DATA (löschen mit --uninstall --purge)"
	fi
	exit 0
fi

UPGRADE=0
[ -x "$BIN" ] && UPGRADE=1

printf '\n%sOpenHeadscaleGUI%s – Verwaltung für Headscale/Tailscale-Netze\n\n' "$C_B" "$C_0"
OS_NAME="$(sed -n "s/^PRETTY_NAME=//p" /etc/os-release 2>/dev/null | tr -d '"')"
info "System: Linux/$ARCH, ${OS_NAME:-unbekannt}"
[ "$UPGRADE" = 1 ] && info "Bestehende Installation gefunden – es wird aktualisiert (Konfiguration und Daten bleiben erhalten)"

for t in tar sha256sum awk sed; do
	command -v "$t" >/dev/null 2>&1 || die "$t wird benötigt"
done

# ---------------------------------------------------------------- go toolchain (source builds)
GO=""
ensure_go() {
	[ -n "$GO" ] && return 0
	if command -v go >/dev/null 2>&1; then
		_v="$(go env GOVERSION 2>/dev/null | sed 's/^go//')"
		if [ "$(printf '%s\n%s\n' "$GO_VERSION" "$_v" | sort -V | head -n1)" = "$GO_VERSION" ]; then
			GO="$(command -v go)"
			return 0
		fi
	fi
	info "Lade Go $GO_VERSION (nur für den Build, wird danach gelöscht)"
	_f="go$GO_VERSION.linux-$ARCH.tar.gz"
	fetch "https://dl.google.com/go/$_f" "$TMP/$_f"
	fetch "https://dl.google.com/go/$_f.sha256" "$TMP/$_f.sha256"
	verify_sha256 "$TMP/$_f" "$(awk '{print $1}' "$TMP/$_f.sha256")"
	tar -C "$TMP" -xzf "$TMP/$_f"
	GO="$TMP/go/bin/go"
	export GOPATH="$TMP/gopath" GOCACHE="$TMP/gocache" GOTOOLCHAIN=local
}

# ---------------------------------------------------------------- ohg binary
install_ohg_release() {
	if [ "$OHG_VERSION" = latest ]; then
		_base="https://github.com/$REPO/releases/latest/download"
	else
		_base="https://github.com/$REPO/releases/download/$OHG_VERSION"
	fi
	_f="ohg_linux_$ARCH.tar.gz"
	info "Lade OpenHeadscaleGUI ($OHG_VERSION, $ARCH)"
	fetch "$_base/$_f" "$TMP/$_f" 2>/dev/null || return 1
	fetch "$_base/checksums.txt" "$TMP/ohg-checksums.txt" || die "checksums.txt des Releases fehlt"
	_sum="$(awk -v f="$_f" '$2==f || $2=="*"f {print $1}' "$TMP/ohg-checksums.txt")"
	[ -n "$_sum" ] || die "Keine Prüfsumme für $_f gefunden"
	verify_sha256 "$TMP/$_f" "$_sum"
	mkdir -p "$TMP/pkg"
	tar -C "$TMP/pkg" -xzf "$TMP/$_f"
	[ -f "$TMP/pkg/ohg" ] || die "Release-Archiv enthält kein ohg-Binary"
	PKG="$TMP/pkg"
	return 0
}

install_ohg_source() {
	ensure_go
	info "Baue OpenHeadscaleGUI aus dem Quellcode ($SOURCE_REF)"
	fetch "https://github.com/$REPO/archive/$SOURCE_REF.tar.gz" "$TMP/src.tar.gz" || die "Quellcode konnte nicht geladen werden"
	mkdir -p "$TMP/src"
	tar -C "$TMP/src" --strip-components=1 -xzf "$TMP/src.tar.gz"
	(cd "$TMP/src" && CGO_ENABLED=0 "$GO" build -trimpath \
		-ldflags "-s -w -X github.com/testbild-media/openHeadscaleGUI/internal/app.Version=src-$SOURCE_REF" \
		-o "$TMP/src/ohg" ./cmd/ohg) || die "Build fehlgeschlagen"
	PKG="$TMP/src"
}

PKG=""
if [ "$FROM_SOURCE" = 1 ]; then
	install_ohg_source
elif ! install_ohg_release; then
	warn "Kein Release-Binary verfügbar (noch kein Release veröffentlicht?) – baue aus dem Quellcode"
	install_ohg_source
fi

# ---------------------------------------------------------------- headscale
install_headscale() {
	if [ -x "$LIBDIR/headscale" ] && "$LIBDIR/headscale" version 2>/dev/null | grep -q "$HEADSCALE_VERSION"; then
		ok "Headscale $HEADSCALE_VERSION ist bereits installiert"
		return 0
	fi
	mkdir -p "$LIBDIR"
	_f="headscale_${HEADSCALE_VERSION}_linux_$ARCH"
	_base="https://github.com/juanfont/headscale/releases/download/v$HEADSCALE_VERSION"
	info "Lade Headscale $HEADSCALE_VERSION"
	if fetch "$_base/$_f" "$TMP/$_f" && fetch "$_base/checksums.txt" "$TMP/hs-checksums.txt"; then
		_sum="$(awk -v f="$_f" '$2==f || $2=="*"f {print $1}' "$TMP/hs-checksums.txt")"
		[ -n "$_sum" ] || die "Keine Prüfsumme für $_f gefunden"
		verify_sha256 "$TMP/$_f" "$_sum"
		install -m 0755 "$TMP/$_f" "$LIBDIR/headscale"
	else
		warn "Headscale-Release nicht ladbar – baue aus dem Quellcode"
		ensure_go
		GOBIN="$TMP/hsbin" CGO_ENABLED=0 GOFLAGS=-mod=mod "$GO" install -trimpath \
			"github.com/juanfont/headscale/cmd/headscale@v$HEADSCALE_VERSION" || die "Headscale-Build fehlgeschlagen"
		install -m 0755 "$TMP/hsbin/headscale" "$LIBDIR/headscale"
	fi
	ok "Headscale $HEADSCALE_VERSION installiert ($LIBDIR/headscale)"
}
install_headscale

# ---------------------------------------------------------------- user, dirs, config
if ! getent passwd "$SVC_USER" >/dev/null 2>&1; then
	useradd --system --home-dir "$DATA" --no-create-home --shell /usr/sbin/nologin --user-group "$SVC_USER" ||
		die "Systembenutzer $SVC_USER konnte nicht angelegt werden"
	ok "Systembenutzer $SVC_USER angelegt"
fi
mkdir -p "$ETC" "$DATA"
chown root:"$SVC_USER" "$ETC"
chmod 0750 "$ETC"
chown "$SVC_USER":"$SVC_USER" "$DATA"
chmod 0750 "$DATA"

if [ ! -f "$ETC/ohg.env" ]; then
	printf '\n%sKonfiguration%s\n' "$C_B" "$C_0"
	printf 'Für die Verwaltungsoberfläche wird eine eigene (Sub-)Domain benötigt, deren DNS-Eintrag\n'
	printf 'auf diesen Server zeigt (z. B. admin.example.com). Das TLS-Zertifikat kommt automatisch von Let'"'"'s Encrypt.\n\n'
	[ -n "$DOMAIN" ] || DOMAIN="$(ask "Domain der Verwaltung" "")"
	[ -n "$DOMAIN" ] || die "Keine Domain angegeben (--domain admin.example.com)"
	case "$DOMAIN" in *[!a-zA-Z0-9.-]* | *..* | .* | *.) die "Ungültige Domain: $DOMAIN" ;; esac
	[ -n "$EMAIL" ] || EMAIL="$(ask "E-Mail für Let's Encrypt" "")"
	[ -n "$EMAIL" ] || die "Keine E-Mail angegeben (--email …)"
	case "$EMAIL" in *[!a-zA-Z0-9.@_+-]* | *@*@* | @* | *@) die "Ungültige E-Mail: $EMAIL" ;; *@*) ;; *) die "Ungültige E-Mail: $EMAIL" ;; esac
	ALLOW="$(ask "Admin-Oberfläche nur von diesen IPs/Netzen erlauben (leer = überall)" "")"
	if [ -f "$PKG/deploy/ohg.env.example" ]; then
		cp "$PKG/deploy/ohg.env.example" "$TMP/ohg.env"
	else
		printf 'OHG_ADMIN_DOMAIN=\nOHG_ACME_EMAIL=\nOHG_TLS_MODE=acme\nOHG_DATA_DIR=%s\nOHG_HEADSCALE_BIN=%s/headscale\n' "$DATA" "$LIBDIR" >"$TMP/ohg.env"
	fi
	sed -i "s|^OHG_ADMIN_DOMAIN=.*|OHG_ADMIN_DOMAIN=$DOMAIN|; s|^OHG_ACME_EMAIL=.*|OHG_ACME_EMAIL=$EMAIL|" "$TMP/ohg.env"
	if [ -n "$ALLOW" ]; then
		case "$ALLOW" in *[!0-9a-fA-F:./,\ ]*) die "Ungültige Allowlist: $ALLOW" ;; esac
		sed -i "s|^#OHG_ADMIN_ALLOW_CIDRS=.*|OHG_ADMIN_ALLOW_CIDRS=$ALLOW|" "$TMP/ohg.env"
	fi
	install -m 0640 -o root -g "$SVC_USER" "$TMP/ohg.env" "$ETC/ohg.env"
	ok "Konfiguration geschrieben: $ETC/ohg.env"
else
	ok "Bestehende Konfiguration bleibt: $ETC/ohg.env"
	chown root:"$SVC_USER" "$ETC/ohg.env"
	chmod 0640 "$ETC/ohg.env"
fi
DOMAIN="$(sed -n 's/^OHG_ADMIN_DOMAIN=//p' "$ETC/ohg.env" | tail -n1)"

# ---------------------------------------------------------------- binary + service
if [ "$UPGRADE" = 1 ]; then systemctl stop ohg >/dev/null 2>&1 || true; fi
install -m 0755 "$PKG/ohg" "$BIN"
ok "ohg installiert: $BIN ($("$BIN" version 2>/dev/null || echo ?))"

if [ -f "$PKG/deploy/ohg.service" ]; then
	install -m 0644 "$PKG/deploy/ohg.service" "$UNIT"
else
	die "systemd-Unit fehlt im Paket"
fi
systemctl daemon-reload
systemctl enable ohg >/dev/null 2>&1

OHG_ENV_FILE="$ETC/ohg.env" runuser -u "$SVC_USER" -- "$BIN" check || warn "ohg check meldet Probleme – siehe oben"

# ---------------------------------------------------------------- firewall
PORTS_TCP="80 443"
PORTS_UDP="3478 41641:41740"
open_firewall() {
	if command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -q "Status: active"; then
		if confirm "UFW ist aktiv. Ports 80/443 (TCP), 3478 (UDP, STUN) und 41641-41740 (UDP, WireGuard) freigeben?" y; then
			for p in $PORTS_TCP; do ufw allow "$p/tcp" >/dev/null; done
			for p in $PORTS_UDP; do ufw allow "$p/udp" >/dev/null; done
			ok "Firewall-Regeln (UFW) hinzugefügt"
		fi
	elif command -v firewall-cmd >/dev/null 2>&1 && firewall-cmd --state >/dev/null 2>&1; then
		if confirm "firewalld ist aktiv. Ports 80/443 (TCP), 3478 und 41641-41740 (UDP) freigeben?" y; then
			for p in $PORTS_TCP; do firewall-cmd --permanent --add-port="$p/tcp" >/dev/null; done
			firewall-cmd --permanent --add-port=3478/udp >/dev/null
			firewall-cmd --permanent --add-port=41641-41740/udp >/dev/null
			firewall-cmd --reload >/dev/null
			ok "Firewall-Regeln (firewalld) hinzugefügt"
		fi
	else
		info "Keine aktive Host-Firewall erkannt. Benötigte Ports: 80/443 TCP, 3478 UDP, 41641-41740 UDP (+ Ports für TCP/UDP-Forwards)"
	fi
}
open_firewall

# ---------------------------------------------------------------- start
systemctl restart ohg
info "Starte Dienst …"
i=0
while [ $i -lt 30 ]; do
	systemctl is-active --quiet ohg && break
	sleep 1
	i=$((i + 1))
done
if ! systemctl is-active --quiet ohg; then
	journalctl -u ohg -n 30 --no-pager || true
	die "Der Dienst konnte nicht gestartet werden (siehe Log oben)"
fi
ok "Dienst läuft (systemctl status ohg)"

TOKEN=""
i=0
while [ $i -lt 15 ]; do
	[ -f "$DATA/setup-token" ] && TOKEN="$(cat "$DATA/setup-token")" && break
	[ "$UPGRADE" = 1 ] && break
	sleep 1
	i=$((i + 1))
done

printf '\n%s──────────────────────────────────────────────────────────────%s\n' "$C_G" "$C_0"
if [ -n "$TOKEN" ]; then
	printf '%sFertig!%s Öffne jetzt die Ersteinrichtung:\n\n' "$C_B" "$C_0"
	printf '   URL:              %shttps://%s/setup%s\n' "$C_B" "$DOMAIN" "$C_0"
	printf '   Einrichtungs-Code: %s%s%s\n\n' "$C_B" "$TOKEN" "$C_0"
	printf 'Voraussetzung: Der DNS-Eintrag von %s zeigt auf diesen Server und Port 80/443 ist erreichbar.\n' "$DOMAIN"
	printf 'Code erneut anzeigen: sudo ohg setup-token\n'
else
	printf '%sFertig!%s Verwaltung: %shttps://%s%s\n' "$C_B" "$C_0" "$C_B" "$DOMAIN" "$C_0"
fi
printf '\nNützlich:\n  sudo journalctl -u ohg -f      Logs\n  sudo systemctl restart ohg     Neustart\n  sudo nano %s/ohg.env      Konfiguration\n' "$ETC"
printf '  curl -fsSL https://raw.githubusercontent.com/%s/main/install.sh | sudo sh   Update\n' "$REPO"
printf '%s──────────────────────────────────────────────────────────────%s\n\n' "$C_G" "$C_0"
