# OpenHeadscaleGUI

**Selbst gehostete Verwaltung für mehrere Tailscale-Netze** – auf Basis von
[Headscale](https://github.com/juanfont/headscale), mit eigener WebGUI, zentralem DERP-Server,
Port-Forwarding und Monitoring. Ein einziges Binary, Installation per Einzeiler auf Debian/Ubuntu.

```bash
curl -fsSL https://raw.githubusercontent.com/testbild-media/openHeadscaleGUI/main/install.sh | sudo sh
```

## Funktionen

| Bereich | Was geht |
|---|---|
| **Instanzen** | Beliebig viele vollständig getrennte Tailnets, jedes mit eigenem Headscale-Prozess, eigener Domain/Subdomain, eigenem IP-Netz, DNS/MagicDNS und ACL-Policy |
| **Server im VPN** | Der Server ist in jeder Instanz selbst Mitglied – immer mit der reservierten IP **`.1`** (z. B. `100.64.0.1`) – und kann jederzeit **Exit-Node** sein |
| **Clients** | Interaktive Anmeldung mit **Freigabe (Approve)** in der GUI, Pre-Auth-Keys (einmalig/mehrfach/ephemer), Umbenennen, Tags, Ablauf, Abmelden, Entfernen |
| **Feste IPs** | Pro Gerät frei wählbar; **Client-Profile** reservieren IP, Name und Freigaben schon vor der ersten Anmeldung |
| **Routen** | Exit-Nodes und jedes beworbene Subnetz **einzeln** freigeben/entziehen, optional automatisch per Profil |
| **Port-Forwarding** | HTTPS per Domain → Gerät:Port (WebSocket, HTTPS-Ziele, Host-Header, IP-Allowlist, Basic-Auth) sowie TCP/UDP-Ports → Gerät:Port. Ziele folgen automatisch der IP des Geräts |
| **DERP** | Zentraler, eingebetteter DERP- + STUN-Server unter eigener Domain für alle Instanzen – mit **Client-Verifikation** gegen alle registrierten Geräte, Allow-/Denylist und Statistik |
| **Monitoring** | Online-Status, **Ping/Latenz** vom Server zu jedem Gerät (direkt oder über welches Relay), Verfügbarkeit, **Live-Traffic** je Gerät, Forward und DERP mit Verlaufsgrafen |
| **Benutzer** | Rollen *Superadmin* (alles) und *Benutzer* (nur eigene Instanzen), Quoten, erlaubte Domain-Endungen, Audit-Log |
| **Sicherheit** | Argon2id, TOTP-2FA + Recovery-Codes, Rate-Limits und Lockout, CSRF-Schutz, strikte CSP, HSTS, Admin-IP-Allowlist, verschlüsselte Secrets, gehärteter systemd-Dienst – Details in [SECURITY.md](SECURITY.md) |

## Voraussetzungen

* Debian 12/13 oder Ubuntu 22.04+ (amd64 oder arm64) mit systemd
* Öffentliche IPv4-Adresse (IPv6 optional)
* DNS-Einträge (A/AAAA) für alle verwendeten Domains auf diesen Server, z. B.:

  | Zweck | Beispiel |
  |---|---|
  | Verwaltung | `admin.example.com` |
  | DERP-Relay | `derp.example.com` |
  | je Instanz | `vpn-firma.example.com`, `vpn-privat.example.com` |
  | je HTTPS-Forward | `nas.example.com` |

  Tipp: Ein Wildcard-Eintrag `*.vpn.example.com` deckt alle Instanzen und Forwards ab.
* Offene Ports: **80/tcp, 443/tcp** (Web, ACME, Clients, DERP), **3478/udp** (STUN),
  **41641–41740/udp** (WireGuard des Server-Nodes, eine pro Instanz) sowie die Ports eigener TCP/UDP-Forwards.

## Installation

```bash
curl -fsSL https://raw.githubusercontent.com/testbild-media/openHeadscaleGUI/main/install.sh | sudo sh
```

Der Installer

1. lädt `ohg` und Headscale (v0.29.7) als Release-Binaries und **prüft die SHA256-Summen**
   (gibt es noch kein Release, wird automatisch aus dem Quellcode gebaut),
2. legt den Systembenutzer `ohg`, `/etc/ohg/ohg.env` und `/var/lib/ohg` an,
3. fragt Admin-Domain, E-Mail für Let's Encrypt und optional eine Admin-IP-Allowlist ab,
4. installiert und startet den gehärteten systemd-Dienst `ohg`,
5. öffnet auf Wunsch die Firewall (UFW/firewalld) und
6. zeigt die URL der **Ersteinrichtung** samt Einrichtungs-Code.

Ohne Rückfragen:

```bash
curl -fsSL https://raw.githubusercontent.com/testbild-media/openHeadscaleGUI/main/install.sh \
  | sudo sh -s -- --yes --domain admin.example.com --email ich@example.com
```

Danach `https://admin.example.com/setup` öffnen, Code eingeben, Superadmin anlegen und 2FA einrichten.
Den Code jederzeit erneut anzeigen: `sudo ohg setup-token`.

**Update:** denselben Befehl erneut ausführen – Konfiguration und Daten bleiben erhalten.
**Deinstallation:** `… | sudo sh -s -- --uninstall` (mit `--purge` zusätzlich Konfiguration und Daten löschen).

## Schnellstart in der GUI

1. **DERP-Server** (Administration → DERP-Server): Domain eintragen, aktivieren. Client-Verifikation ist standardmäßig an.
2. **Neue Instanz**: Name, Kurzname und Domain (z. B. `vpn-firma.example.com`). Headscale und der Server-Node (`100.64.0.1`) starten automatisch.
3. **Geräte verbinden**
   * *Mit Freigabe:* `tailscale up --reset --force-reauth --login-server https://vpn-firma.example.com` (Linux mit `sudo`, Windows als Administrator) – die angezeigte URL öffnen, das Gerät erscheint unter **Freigaben**, dort Benutzer, Name und optional feste IP wählen und freigeben.
   * *Automatisch mit fester IP:* unter **Clients & Keys** einen Client mit Name und IP anlegen und den angezeigten Befehl mit Schlüssel auf dem Gerät ausführen.
     Solange der Schlüssel gültig ist, holt **Befehl anzeigen** den Befehl jederzeit wieder hervor. Für eine erneute Anmeldung –
     z. B. nach einem Wechsel in ein anderes Tailnet und zurück – erzeugt **Neuer Schlüssel** einen frischen Einmal-Schlüssel;
     Name und feste IP des Profils bleiben erhalten.
   * *Apps (iOS/Android/macOS):* in den Einstellungen „alternativer Server“ = Instanz-URL.
4. **Exit-Node / Subnetze:** Auf der Geräteseite jede beworbene Route einzeln freigeben. Den Server als Exit-Node nutzen: `tailscale set --exit-node=100.64.0.1`.
5. **Port-Forwarding:** z. B. `nas.example.com` → Gerät „nas“ Port 5000 (HTTPS-Ziel, Zertifikat nicht prüfen) oder TCP-Port 20022 → Gerät:22.
6. **Monitoring:** Erreichbarkeit, Latenz und Traffic pro Gerät, live aktualisiert.

> Hinweis zum Traffic: Gemessen wird alles, was über den Server läuft (Port-Forwards, Exit-Node, DERP-Relay).
> Direkte Verbindungen zwischen zwei Geräten sind Ende-zu-Ende verschlüsselt und für den Server nicht sichtbar.

## Kommandozeile

```text
ohg serve                         Server starten (macht systemd)
ohg check                         Konfiguration und Headscale prüfen
ohg setup-token                   Einrichtungs-Code für den ersten Superadmin
ohg user list | add | passwd | reset-2fa | unlock
ohg headscale SLUG ARGS...        headscale-CLI einer Instanz, z. B.: sudo ohg headscale firma nodes list
```

## Konfiguration (`/etc/ohg/ohg.env`)

| Variable | Standard | Bedeutung |
|---|---|---|
| `OHG_ADMIN_DOMAIN` | – | Domain der Verwaltung (Pflicht) |
| `OHG_ACME_EMAIL` | – | E-Mail für Let's Encrypt (Pflicht bei `acme`) |
| `OHG_TLS_MODE` | `acme` | `acme`, `selfsigned` oder `off` (hinter eigenem TLS-Proxy) |
| `OHG_ADMIN_ALLOW_CIDRS` | leer | Admin-GUI nur aus diesen Netzen (sehr empfohlen) |
| `OHG_TRUSTED_PROXIES` | leer | Proxies, deren `X-Forwarded-For` vertraut wird |
| `OHG_REQUIRE_2FA` | `false` | 2FA für alle erzwingen |
| `OHG_SESSION_IDLE` / `OHG_SESSION_MAX` | `30m` / `12h` | Sitzungsdauer |
| `OHG_HTTPS_ADDR` / `OHG_HTTP_ADDR` | `:443` / `:80` | Listener |
| `OHG_INTERNAL_PORT_BASE` | `42000` | Loopback-Ports der Headscale-Prozesse |
| `OHG_GATEWAY_PORT_BASE` | `41641` | UDP-Ports der Server-Nodes |
| `OHG_PUBLIC_IPV4` / `OHG_PUBLIC_IPV6` | leer | optionale IPs für die DERP-Map |
| `OHG_DATA_DIR` | `/var/lib/ohg` | Daten |
| `OHG_HEADSCALE_BIN` | `/usr/local/lib/ohg/headscale` | Headscale-Binary |
| `OHG_LOG_LEVEL` | `info` | `debug`, `info`, `warn`, `error` |

Weitere Einstellungen (Quoten, Domain-Endungen, Port-Bereich für Forwards, 2FA-Pflicht, Audit-Aufbewahrung)
werden in der GUI unter **Einstellungen** gepflegt.

## Backup

Alles Wichtige liegt in `/var/lib/ohg` (Datenbank, Master-Key, Headscale-Datenbanken und -Schlüssel,
Zertifikate) und `/etc/ohg/ohg.env`. Für ein konsistentes Backup kurz `systemctl stop ohg`.

## Release veröffentlichen

```bash
git tag v0.1.0
git push origin v0.1.0
```

Der GitHub-Workflow baut `ohg_linux_amd64.tar.gz` und `ohg_linux_arm64.tar.gz` inkl. `checksums.txt`
und hängt sie an das Release – genau diese Dateien lädt der Installer.

## Entwicklung

```bash
go test ./...
go build -o dist/ohg ./cmd/ohg
# lokal ohne TLS (Domains unter *.localhost lösen im Browser automatisch auf):
OHG_DEV=1 OHG_TLS_MODE=off OHG_HTTP_ADDR=127.0.0.1:18480 OHG_ADMIN_DOMAIN=admin.localhost \
  OHG_DATA_DIR=./dev-data OHG_HEADSCALE_BIN=/pfad/zu/headscale ./dist/ohg serve
```

Architektur und Designentscheidungen: [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).
Lizenzhinweise der verwendeten Komponenten: [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).
