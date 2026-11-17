#!/bin/sh
# OpenHeadscaleGUI – Installer / Updater / Uninstaller
#
#   curl -fsSL https://raw.githubusercontent.com/testbild-media/openHeadscaleGUI/main/install.sh | sudo sh
#
# Optionen (als Argumente nach "sh -s --" oder als Umgebungsvariablen):
#   --domain admin.example.com   Domain der Verwaltungsoberfläche   (OHG_ADMIN_DOMAIN)
#   --email  admin@example.com   E-Mail für Let's Encrypt            (OHG_ACME_EMAIL)
#   --version v1.2.3             bestimmte Version statt der neuesten (OHG_VERSION)
#   --behind-proxy               hinter vorhandenem Reverse-Proxy (z. B. Caddy) betreiben: ohg
#                                lauscht nur lokal, TLS und Ports 80/443 übernimmt der Proxy
#   --listen 127.0.0.1:8480      lokale Adresse im Proxy-Modus                 (OHG_LISTEN)
#   --no-firewall-sync           Ports der TCP/UDP-Forwards nicht automatisch in UFW/firewalld öffnen
#   --enable-ufw                 ohne Rückfrage UFW einrichten, falls keine Server-Firewall aktiv ist
#                                (erlaubt SSH und die Ports von ohg, sperrt den Rest)
#   --no-ufw                     nicht anbieten, UFW einzurichten
#   --from-source                aus dem Quellcode bauen (lädt bei Bedarf Go herunter)
#   --yes                        keine Rückfragen
#   --uninstall [--purge]        entfernen (--purge löscht auch Konfiguration und Daten)
#
# Beispiel ohne Rückfragen:
#   curl -fsSL …/install.sh | sudo sh -s -- --yes --domain admin.example.com --email ich@example.com
# Hinter Caddy:
#   curl -fsSL …/install.sh | sudo sh -s -- --behind-proxy --domain admin.example.com
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
UNITDIR=/etc/systemd/system
FW_UNITS="ohg-firewall.service ohg-firewall.path ohg-firewall.timer"
SVC_USER=ohg

MODE=install
PURGE=0
FROM_SOURCE=0
ASSUME_YES=0
DOMAIN="${OHG_ADMIN_DOMAIN:-}"
EMAIL="${OHG_ACME_EMAIL:-}"
PROXY=0
LISTEN="${OHG_LISTEN:-127.0.0.1:8480}"
FW_SYNC=1
UFW_SETUP="" # "": ask on new installations, yes: --enable-ufw, no: --no-ufw

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

# set_env FILE KEY VALUE: sets KEY (also a commented "#KEY=" line) or appends it
set_env() {
	if grep -q "^#\{0,1\}$2=" "$1"; then
		sed -i "s|^#\{0,1\}$2=.*|$2=$3|" "$1"
	else
		printf '%s=%s\n' "$2" "$3" >>"$1"
	fi
}

# port_busy PORT: a TCP listener exists; port_prog PORT: name of its program
port_busy() { command -v ss >/dev/null 2>&1 && [ -n "$(ss -ltnH "sport = :$1" 2>/dev/null)" ]; }
port_prog() { ss -ltnpH "sport = :$1" 2>/dev/null | sed -n 's/.*users:(("\([^"]*\)".*/\1/p' | head -n1; }

# proxy_env FILE: configure ohg for a TLS terminating reverse proxy
proxy_env() {
	set_env "$1" OHG_TLS_MODE off
	set_env "$1" OHG_HTTP_ADDR "$LISTEN"
	set_env "$1" OHG_TRUSTED_PROXIES "127.0.0.1/32,::1/128"
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
	--behind-proxy) PROXY=1 ;;
	--listen) LISTEN="${2:-}"; shift ;;
	--no-firewall-sync) FW_SYNC=0 ;;
	--enable-ufw) UFW_SETUP=yes ;;
	--no-ufw) UFW_SETUP=no ;;
	-h | --help)
		sed -n '2,24p' "$0" 2>/dev/null || true
		exit 0
		;;
	*) die "Unbekannte Option: $1" ;;
	esac
	shift
done

# ---------------------------------------------------------------- checks
[ "$(uname -s)" = Linux ] || die "OpenHeadscaleGUI läuft nur unter Linux"
case "$LISTEN" in "" | *[!0-9a-zA-Z.:\[\]-]* | *:) die "Ungültige Adresse für --listen: $LISTEN (z. B. 127.0.0.1:8480)" ;; esac
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
	# remove the firewall rules the sync created for port forwards
	systemctl disable --now ohg-firewall.path ohg-firewall.timer >/dev/null 2>&1 || true
	if [ -x "$BIN" ]; then OHG_ENV_FILE="$ETC/ohg.env" "$BIN" firewall-sync --remove-all >/dev/null 2>&1 || true; fi
	for _u in $FW_UNITS; do rm -f "$UNITDIR/$_u"; done
	rm -rf /var/lib/ohg-firewall
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
	# Ports 80/443 already taken (e.g. by Caddy)? Then run behind that proxy.
	if [ "$PROXY" = 0 ] && { port_busy 443 || port_busy 80; }; then
		_p="$(port_prog 443)"
		[ -n "$_p" ] || _p="$(port_prog 80)"
		warn "Port 80/443 ist bereits belegt${_p:+ (von $_p)}."
		if confirm "OpenHeadscaleGUI hinter diesem Reverse-Proxy betreiben (lauscht nur lokal auf $LISTEN)?" y; then
			PROXY=1
		else
			die "Port 80/443 wird benötigt – den anderen Dienst beenden oder mit --behind-proxy installieren"
		fi
	fi
	printf '\n%sKonfiguration%s\n' "$C_B" "$C_0"
	printf 'Für die Verwaltungsoberfläche wird eine eigene (Sub-)Domain benötigt, deren DNS-Eintrag\n'
	if [ "$PROXY" = 1 ]; then
		printf 'auf diesen Server zeigt (z. B. admin.example.com). TLS-Zertifikate besorgt der Reverse-Proxy.\n\n'
	else
		printf 'auf diesen Server zeigt (z. B. admin.example.com). Das TLS-Zertifikat kommt automatisch von Let'"'"'s Encrypt.\n\n'
	fi
	[ -n "$DOMAIN" ] || DOMAIN="$(ask "Domain der Verwaltung" "")"
	[ -n "$DOMAIN" ] || die "Keine Domain angegeben (--domain admin.example.com)"
	case "$DOMAIN" in *[!a-zA-Z0-9.-]* | *..* | .* | *.) die "Ungültige Domain: $DOMAIN" ;; esac
	if [ "$PROXY" = 0 ]; then
		[ -n "$EMAIL" ] || EMAIL="$(ask "E-Mail für Let's Encrypt" "")"
		[ -n "$EMAIL" ] || die "Keine E-Mail angegeben (--email …)"
		case "$EMAIL" in *[!a-zA-Z0-9.@_+-]* | *@*@* | @* | *@) die "Ungültige E-Mail: $EMAIL" ;; *@*) ;; *) die "Ungültige E-Mail: $EMAIL" ;; esac
	fi
	ALLOW="$(ask "Admin-Oberfläche nur von diesen IPs/Netzen erlauben (leer = überall)" "")"
	if [ -f "$PKG/deploy/ohg.env.example" ]; then
		cp "$PKG/deploy/ohg.env.example" "$TMP/ohg.env"
	else
		printf 'OHG_ADMIN_DOMAIN=\nOHG_ACME_EMAIL=\nOHG_TLS_MODE=acme\nOHG_DATA_DIR=%s\nOHG_HEADSCALE_BIN=%s/headscale\n' "$DATA" "$LIBDIR" >"$TMP/ohg.env"
	fi
	set_env "$TMP/ohg.env" OHG_ADMIN_DOMAIN "$DOMAIN"
	set_env "$TMP/ohg.env" OHG_ACME_EMAIL "$EMAIL"
	if [ "$PROXY" = 1 ]; then proxy_env "$TMP/ohg.env"; fi
	if [ -n "$ALLOW" ]; then
		case "$ALLOW" in *[!0-9a-fA-F:./,\ ]*) die "Ungültige Allowlist: $ALLOW" ;; esac
		set_env "$TMP/ohg.env" OHG_ADMIN_ALLOW_CIDRS "$ALLOW"
	fi
	install -m 0640 -o root -g "$SVC_USER" "$TMP/ohg.env" "$ETC/ohg.env"
	ok "Konfiguration geschrieben: $ETC/ohg.env"
else
	ok "Bestehende Konfiguration bleibt: $ETC/ohg.env"
	chown root:"$SVC_USER" "$ETC/ohg.env"
	chmod 0640 "$ETC/ohg.env"
	if [ "$PROXY" = 1 ] && [ "$(sed -n 's/^OHG_TLS_MODE=//p' "$ETC/ohg.env" | tail -n1)" != off ]; then
		proxy_env "$ETC/ohg.env"
		ok "Auf Betrieb hinter Reverse-Proxy umgestellt (lauscht auf $LISTEN)"
	fi
fi
DOMAIN="$(sed -n 's/^OHG_ADMIN_DOMAIN=//p' "$ETC/ohg.env" | tail -n1)"
if [ "$(sed -n 's/^OHG_TLS_MODE=//p' "$ETC/ohg.env" | tail -n1)" = off ]; then
	PROXY=1
	_l="$(sed -n 's/^OHG_HTTP_ADDR=//p' "$ETC/ohg.env" | tail -n1)"
	if [ -n "$_l" ]; then LISTEN="$_l"; fi
fi

# ---------------------------------------------------------------- binary + service
if [ "$UPGRADE" = 1 ]; then systemctl stop ohg >/dev/null 2>&1 || true; fi
install -m 0755 "$PKG/ohg" "$BIN"
ok "ohg installiert: $BIN ($("$BIN" version 2>/dev/null || echo ?))"

if [ -f "$PKG/deploy/ohg.service" ]; then
	install -m 0644 "$PKG/deploy/ohg.service" "$UNIT"
else
	die "systemd-Unit fehlt im Paket"
fi
# firewall automation for TCP/UDP forwards (root helper, see ohg-firewall.service);
# keep it off when the administrator disabled it before
FW_EXISTED=0
FW_WAS_ENABLED=0
if [ -f "$UNITDIR/ohg-firewall.path" ]; then
	FW_EXISTED=1
	systemctl is-enabled --quiet ohg-firewall.path 2>/dev/null && FW_WAS_ENABLED=1
fi
for _u in $FW_UNITS; do
	if [ -f "$PKG/deploy/$_u" ]; then install -m 0644 "$PKG/deploy/$_u" "$UNITDIR/$_u"; fi
done
systemctl daemon-reload
systemctl enable ohg >/dev/null 2>&1

OHG_ENV_FILE="$ETC/ohg.env" runuser -u "$SVC_USER" -- "$BIN" check || warn "ohg check meldet Probleme – siehe oben"

# ---------------------------------------------------------------- firewall
PORTS_TCP="80 443"
PORTS_DESC="80/443 (TCP), 3478 (UDP, STUN) und 41641-41740 (UDP, WireGuard)"
if [ "$PROXY" = 1 ]; then
	PORTS_TCP=""
	PORTS_DESC="3478 (UDP, STUN) und 41641-41740 (UDP, WireGuard) – 80/443 gehören dem Reverse-Proxy"
fi
FW_HINT="Benötigte Ports: $PORTS_DESC (+ Ports für TCP/UDP-Forwards)"
UFW_ENABLED=0
SSH_PORTS=""
TS_IF=0
OTHER=""
DOCKER_PORTS=""

# ufw_base_rules: the ports ohg needs. Always the same comments: "ufw allow"
# without a comment would remove them again. Never the comment of the forward
# sync ("ohg-forward") – the sync would delete such rules.
ufw_base_rules() {
	_rc=0
	for p in $PORTS_TCP; do ufw allow "$p/tcp" comment "OpenHeadscaleGUI" >/dev/null || _rc=1; done
	ufw allow 3478/udp comment "OpenHeadscaleGUI STUN" >/dev/null || _rc=1
	ufw allow 41641:41740/udp comment "OpenHeadscaleGUI WireGuard" >/dev/null || _rc=1
	return $_rc
}

# ssh_ports: TCP ports of the SSH server – configured, socket activated,
# listening, and the port of the connection this installer runs in
ssh_ports() {
	_sshd="$(command -v sshd 2>/dev/null || true)"
	if [ -z "$_sshd" ] && [ -x /usr/sbin/sshd ]; then _sshd=/usr/sbin/sshd; fi
	{
		if [ -n "$_sshd" ]; then
			"$_sshd" -T 2>/dev/null | awk '$1 == "port" { print $2 } $1 == "listenaddress" { n = split($2, a, ":"); print a[n] }'
		fi
		for _s in ssh.socket sshd.socket; do
			if systemctl is-active --quiet "$_s" 2>/dev/null; then
				systemctl show -p Listen "$_s" 2>/dev/null | grep -o ':[0-9][0-9]* (Stream)' | tr -cd '0-9\n'
			fi
		done
		ss -H -ltnp 2>/dev/null | awk '/\("sshd/ { n = split($4, a, ":"); print a[n] }'
		ss -H -tnp state established 2>/dev/null | awk '/\("sshd/ { n = split($3, a, ":"); print a[n] }'
		if [ -n "${SSH_CONNECTION:-}" ]; then printf '%s\n' "$SSH_CONNECTION" | awk '{ print $4 }'; fi
	} | awk '/^[0-9]+$/ && $1 > 0 && $1 < 65536' | sort -un
}

# listeners: "PROTO PORT PROGRAM" of every socket other hosts can reach
# (not bound to loopback, link-local or tailnet addresses)
listeners() {
	ss -H -lntup 2>/dev/null | awk '{
		n = split($5, a, ":"); port = a[n]; addr = substr($5, 1, length($5) - length(port) - 1)
		if (port !~ /^[0-9]+$/) next
		if (addr ~ /^127\./ || addr == "[::1]" || addr ~ /^\[::ffff:127\./ || addr ~ /^\[fe80:/ || addr ~ /%lo$/) next
		if (addr ~ /^100\.(6[4-9]|[7-9][0-9]|1[01][0-9]|12[0-7])\./ || addr ~ /^\[fd7a:115c:a1e0:/) next
		prog = "?"
		if (match($7, /\(\("[^"]*"/)) prog = substr($7, RSTART + 3, RLENGTH - 4)
		print $1, port, prog
	}' | sort -u
}

# ufw_covered PROTO PORT PROGRAM: still reachable once UFW is on
ufw_covered() {
	case "$1:$2" in
	udp:68 | udp:546 | udp:5353) return 0 ;; # DHCP, mDNS: allowed by UFW's built-in rules
	*:5355) return 0 ;;                      # LLMNR of systemd-resolved, not needed on a server
	tcp:80 | tcp:443 | udp:3478) return 0 ;;
	udp:443) if [ "$PROXY" = 1 ]; then return 0; fi ;;
	esac
	if [ "$1" = udp ] && [ "$2" -ge 41641 ] && [ "$2" -le 41740 ]; then return 0; fi
	if [ "$1" = tcp ]; then
		for _p in $SSH_PORTS; do
			if [ "$_p" = "$2" ]; then return 0; fi
		done
	fi
	[ "$3" = ohg ]
}

# other_firewall: a firewall that is neither UFW nor firewalld
other_firewall() {
	for _s in nftables netfilter-persistent iptables shorewall; do
		if systemctl is-active --quiet "$_s.service" 2>/dev/null; then
			printf '%s ist aktiv' "$_s.service"
			return 0
		fi
	done
	if command -v nft >/dev/null 2>&1 && nft list ruleset 2>/dev/null | grep -q 'hook input.*policy drop'; then
		printf 'eine eigene nftables-Firewall ist aktiv'
	elif command -v iptables >/dev/null 2>&1 && iptables -S INPUT 2>/dev/null | grep -q -- '^-P INPUT DROP'; then
		printf 'eine eigene iptables-Firewall ist aktiv'
	fi
}

ensure_ufw() {
	if command -v ufw >/dev/null 2>&1; then return 0; fi
	if ! command -v apt-get >/dev/null 2>&1; then return 1; fi
	info "Installiere UFW"
	if DEBIAN_FRONTEND=noninteractive apt-get install -y -qq ufw >/dev/null 2>&1; then return 0; fi
	apt-get update -qq >/dev/null 2>&1 || true
	DEBIAN_FRONTEND=noninteractive apt-get install -y -qq ufw >/dev/null 2>&1
}

docker_note() {
	if command -v docker >/dev/null 2>&1 || [ -S /var/run/docker.sock ]; then
		warn "Docker ist installiert: Mit -p veröffentlichte Container-Ports umgehen UFW und bleiben von außen erreichbar${DOCKER_PORTS:+ (hier:$DOCKER_PORTS)}. Nur lokal veröffentlichen (-p 127.0.0.1:PORT:PORT) oder in der iptables-Kette DOCKER-USER sperren."
	fi
}

# scan_ufw: what UFW would let through (SSH_PORTS, TS_IF) and block (OTHER)
scan_ufw() {
	SSH_PORTS="$(ssh_ports | tr '\n' ' ')"
	if [ -z "$SSH_PORTS" ] && { command -v sshd >/dev/null 2>&1 || [ -x /usr/sbin/sshd ]; }; then SSH_PORTS="22 "; fi
	TS_IF=0
	if ip link show tailscale0 >/dev/null 2>&1; then TS_IF=1; fi
	OTHER=""
	DOCKER_PORTS=""
	_ls="$(listeners)"
	while read -r _pr _po _prog; do
		if [ -z "$_pr" ] || ufw_covered "$_pr" "$_po" "$_prog"; then continue; fi
		if [ "$_prog" = docker-proxy ]; then
			DOCKER_PORTS="$DOCKER_PORTS $_po/$_pr"
			continue
		fi
		if [ "$_prog" = "?" ]; then _prog="(ohne Prozess, z. B. WireGuard im Kernel)"; fi
		OTHER="$OTHER$(printf '      %-12s %s' "$_po/$_pr" "$_prog")
"
	done <<EOF
$_ls
EOF
}

# enable_ufw: allow SSH and the ports of ohg, then switch UFW on
enable_ufw() {
	if ! ensure_ufw; then
		warn "UFW konnte nicht installiert werden (apt-get install ufw). $FW_HINT"
		return 0
	fi
	_err=0
	for _p in $SSH_PORTS; do ufw allow "$_p/tcp" comment "SSH" >/dev/null || _err=1; done
	if [ "$PROXY" = 1 ]; then
		for _r in 80/tcp 443/tcp 443/udp; do ufw allow "$_r" comment "Reverse-Proxy" >/dev/null || _err=1; done
	fi
	ufw_base_rules || _err=1
	if [ "$TS_IF" = 1 ]; then ufw allow in on tailscale0 comment "Tailnet" >/dev/null || _err=1; fi
	if [ "$_err" = 1 ]; then
		warn "UFW-Regeln konnten nicht angelegt werden – UFW bleibt aus. $FW_HINT"
		return 0
	fi
	if ufw --force enable >/dev/null 2>&1 && ufw status 2>/dev/null | grep -q "Status: active"; then
		UFW_ENABLED=1
		_d="$(for _p in $SSH_PORTS; do printf '%s/tcp, ' "$_p"; done)"
		ok "UFW eingeschaltet: eingehend alles gesperrt außer ${_d:+SSH (${_d%, }) und }den Ports von OpenHeadscaleGUI"
		info "Weitere Ports: sudo ufw allow PORT/tcp · Übersicht: sudo ufw status · Ausschalten: sudo ufw disable"
	else
		ufw --force disable >/dev/null 2>&1 || true
		warn "UFW ließ sich nicht einschalten (sudo ufw enable) – der Server bleibt ohne Firewall. $FW_HINT"
	fi
}

# offer_ufw: no host firewall active. New installations ask (default "yes"
# only when nothing but SSH and ohg is reachable); updates, --yes and runs
# without a terminal only print a hint unless --enable-ufw was given.
offer_ufw() {
	_why="$(other_firewall)"
	if [ -n "$_why" ]; then
		info "Keine UFW/firewalld aktiv, aber $_why. $FW_HINT"
		return 0
	fi
	_can=1
	command -v ss >/dev/null 2>&1 || _can=0
	if ! command -v ufw >/dev/null 2>&1 && ! command -v apt-get >/dev/null 2>&1; then _can=0; fi
	if [ "$UFW_SETUP" = no ] || [ "$_can" = 0 ]; then
		if [ "$UFW_SETUP" = yes ]; then warn "UFW kann hier nicht eingerichtet werden (ufw bzw. apt-get oder ss fehlt)"; fi
		info "Keine aktive Server-Firewall erkannt. $FW_HINT"
		return 0
	fi
	if [ "$UFW_SETUP" != yes ] && { [ "$UPGRADE" = 1 ] || ! have_tty; }; then
		info "Keine aktive Server-Firewall erkannt. $FW_HINT"
		info "UFW einrichten (sperrt alles außer SSH und ohg): curl -fsSL https://raw.githubusercontent.com/$REPO/main/install.sh | sudo sh -s -- --enable-ufw"
		return 0
	fi
	scan_ufw
	printf '\n%sServer-Firewall%s\n' "$C_B" "$C_0"
	printf 'Auf diesem Server ist keine Firewall aktiv. UFW würde eingehend alles sperren außer:\n'
	if [ -n "$SSH_PORTS" ]; then
		_d="$(for _p in $SSH_PORTS; do printf '%s/tcp, ' "$_p"; done)"
		printf '      %-18s %s\n' "SSH" "${_d%, }"
	else
		printf '      %-18s %s\n' "SSH" "kein SSH-Server gefunden"
	fi
	if [ "$PROXY" = 1 ]; then
		printf '      %-18s %s\n' "Reverse-Proxy" "80/tcp, 443/tcp, 443/udp"
		printf '      %-18s %s\n' "OpenHeadscaleGUI" "3478/udp (STUN), 41641-41740/udp (WireGuard)"
	else
		printf '      %-18s %s\n' "OpenHeadscaleGUI" "80/tcp, 443/tcp, 3478/udp (STUN), 41641-41740/udp (WireGuard)"
	fi
	if [ "$FW_SYNC" = 1 ]; then printf '      %-18s %s\n' "Port-Forwards" "öffnet die Firewall-Automatik von ohg selbst"; fi
	if [ "$TS_IF" = 1 ]; then printf '      %-18s %s\n' "tailscale0" "alles aus dem Tailnet, wie bisher"; fi
	_def=y
	if [ -n "$OTHER" ]; then
		_def=n
		printf '%sDiese Dienste sind ebenfalls von außen erreichbar und wären danach gesperrt:%s\n%s' "$C_Y" "$C_0" "$OTHER"
		printf 'Später freigeben mit: sudo ufw allow PORT/tcp (bzw. PORT/udp)\n'
	else
		printf 'Sonst ist auf diesem Server nichts von außen erreichbar.\n'
	fi
	docker_note
	if [ "$UFW_SETUP" = yes ] || confirm "UFW jetzt einrichten und einschalten?" "$_def"; then
		enable_ufw
	else
		info "UFW nicht eingerichtet. $FW_HINT"
	fi
}

open_firewall() {
	if command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -q "Status: active"; then
		if confirm "UFW ist aktiv. Ports $PORTS_DESC freigeben?" y; then
			if ufw_base_rules; then
				ok "Firewall-Regeln (UFW) hinzugefügt"
			else
				warn "Nicht alle Firewall-Regeln (UFW) konnten angelegt werden (sudo ufw status)"
			fi
		fi
	elif command -v firewall-cmd >/dev/null 2>&1 && firewall-cmd --state >/dev/null 2>&1; then
		if confirm "firewalld ist aktiv. Ports $PORTS_DESC freigeben?" y; then
			for p in $PORTS_TCP; do firewall-cmd --permanent --add-port="$p/tcp" >/dev/null; done
			firewall-cmd --permanent --add-port=3478/udp >/dev/null
			firewall-cmd --permanent --add-port=41641-41740/udp >/dev/null
			firewall-cmd --reload >/dev/null
			ok "Firewall-Regeln (firewalld) hinzugefügt"
		fi
	else
		offer_ufw
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

if [ -f "$UNITDIR/ohg-firewall.service" ]; then
	if [ "$FW_SYNC" = 0 ]; then
		systemctl disable --now ohg-firewall.path ohg-firewall.timer >/dev/null 2>&1 || true
		info "Firewall-Automatik für Port-Forwards ist aus (--no-firewall-sync)"
		if [ "$UFW_ENABLED" = 1 ]; then warn "Ports von TCP/UDP-Forwards selbst freigeben: sudo ufw allow PORT/tcp"; fi
	elif [ "$FW_EXISTED" = 1 ] && [ "$FW_WAS_ENABLED" = 0 ]; then
		info "Firewall-Automatik für Port-Forwards bleibt aus (war deaktiviert; einschalten: systemctl enable --now ohg-firewall.path ohg-firewall.timer)"
	elif systemctl enable --now ohg-firewall.path ohg-firewall.timer >/dev/null 2>&1; then
		# ohg wrote its port list before the path unit was watching: sync once now
		systemctl start --no-block ohg-firewall.service >/dev/null 2>&1 || true
		ok "Firewall-Automatik für Port-Forwards aktiv (öffnet TCP/UDP-Forward-Ports in UFW/firewalld)"
	else
		warn "Firewall-Automatik konnte nicht aktiviert werden (systemctl status ohg-firewall.path)"
	fi
fi

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
	if [ "$PROXY" = 1 ]; then
		printf 'Voraussetzung: Der DNS-Eintrag von %s zeigt auf diesen Server und der Reverse-Proxy leitet weiter (siehe unten).\n' "$DOMAIN"
	else
		printf 'Voraussetzung: Der DNS-Eintrag von %s zeigt auf diesen Server und Port 80/443 ist erreichbar.\n' "$DOMAIN"
	fi
	printf 'Code erneut anzeigen: sudo ohg setup-token\n'
else
	printf '%sFertig!%s Verwaltung: %shttps://%s%s\n' "$C_B" "$C_0" "$C_B" "$DOMAIN" "$C_0"
fi
if [ "$PROXY" = 1 ]; then
	printf '\n%sBetrieb hinter Reverse-Proxy:%s ohg lauscht auf %shttp://%s%s\n' "$C_B" "$C_0" "$C_B" "$LISTEN" "$C_0"
	printf 'Caddy (Caddyfile) – holt Zertifikate automatisch für alle Domains, die ohg kennt:\n\n'
	printf '  {\n      on_demand_tls {\n          ask http://%s/_ohg/tls-ask\n      }\n  }\n\n' "$LISTEN"
	printf '  https:// {\n      tls {\n          on_demand\n      }\n      reverse_proxy %s\n  }\n\n' "$LISTEN"
	printf 'Der Block { … } gehört zu den globalen Optionen ganz am Anfang des Caddyfiles.\n'
	printf 'Danach: sudo systemctl reload caddy\n'
fi
printf '\nNützlich:\n  sudo journalctl -u ohg -f      Logs\n  sudo systemctl restart ohg     Neustart\n  sudo nano %s/ohg.env      Konfiguration\n' "$ETC"
printf '  curl -fsSL https://raw.githubusercontent.com/%s/main/install.sh | sudo sh   Update\n' "$REPO"
printf '%s──────────────────────────────────────────────────────────────%s\n\n' "$C_G" "$C_0"
