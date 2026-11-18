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
| **Port-Forwarding** | HTTPS per Domain → Gerät:Port (WebSocket, HTTPS-Ziele, Host-Header, IP-Allowlist, Basic-Auth, Weiterleitungen des Ziels auf sich selbst werden auf die öffentliche Domain umgeschrieben) sowie TCP/UDP-Ports → Gerät:Port. Ziele folgen automatisch der IP des Geräts. Superadmins geben unter **Server-Freigaben** auch **Dienste auf dem Server selbst** frei (`127.0.0.1`, Docker) – ohne Instanz. Die Ports von TCP/UDP-Forwards öffnet ohg bei aktiver **UFW/firewalld automatisch** (und schließt sie wieder) |
| **Brücken** | Geräte einer Instanz in einer anderen Instanz erreichbar machen, **nur für ausgewählte Geräte**: als **ganzer Host** (alle Ports, TCP/UDP) unter eigener Adresse aus dem Brücken-Netz (z. B. `198.18.0.1`) samt DNS-Name, oder als einzelner Port auf der Server-Adresse `.1`; die Tailnets bleiben getrennt |
| **Isolation** | Pro Instanz „Geräte voneinander isolieren“: Clients sehen sich gegenseitig nicht und erreichen nur den Server (Brücken, Port-Forwards, Exit-Node) |
| **Weiterleitungen** | Eigener Menüpunkt: Domain → andere Subdomain, andere Domain oder bestimmte Seite (301/302/307/308, optional mit Pfad und Parametern), z. B. `alt.example.com` → `https://neu.example.com`; TLS-Zertifikat automatisch, `http://` geht direkt zum Ziel |
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
  **41641–41740/udp** (WireGuard des Server-Nodes, eine pro Instanz) sowie die Ports eigener TCP/UDP-Forwards
  (in UFW/firewalld auf dem Server öffnet ohg diese automatisch, siehe „Firewall-Automatik“).
  **Auch in der Firewall des Hosters freigeben** (Cloud-Panel), nicht nur auf dem Server. Fehlt UDP, finden die
  Geräte keine direkten Wege und hängen komplett am DERP-Relay. ohg erkennt das (keine einzige STUN-Anfrage von
  außen) und warnt in der Übersicht und auf der DERP-Seite.

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
5. öffnet auf Wunsch die Firewall (UFW/firewalld) für die Grundports – ist keine aktiv, **bietet er an, UFW
   einzurichten** (siehe unten) –, richtet die **Firewall-Automatik** für TCP/UDP-Forwards ein (abschaltbar mit
   `--no-firewall-sync`) und
6. zeigt die URL der **Ersteinrichtung** samt Einrichtungs-Code.

### Server-Firewall (UFW) einrichten

Ist auf dem Server weder UFW noch firewalld (noch eine eigene nftables/iptables-Firewall) aktiv, fragt der
Installer bei einer **Neuinstallation**, ob er UFW einrichten soll. Vorher zeigt er, was danach noch erreichbar ist
und was gesperrt würde:

* **erlaubt** werden SSH (alle Ports des SSH-Servers samt dem Port der laufenden Verbindung), die Ports von ohg
  (80/443/tcp, 3478/udp, 41641–41740/udp; hinter einem Reverse-Proxy dessen 80/tcp, 443/tcp und 443/udp) und, falls
  vorhanden, alles über `tailscale0`; die Ports von TCP/UDP-Forwards öffnet anschließend die Firewall-Automatik;
* **aufgelistet** werden alle übrigen von außen erreichbaren Dienste (z. B. `5432/tcp postgres`). Gibt es keine,
  ist „Ja“ vorgegeben, sonst „Nein“ – damit nichts unbemerkt wegbricht;
* ist **Docker** installiert, weist er darauf hin, dass mit `-p` veröffentlichte Container-Ports an UFW vorbeigehen.

Bei Updates, mit `--yes` oder ohne Terminal fragt er nicht, sondern nennt nur den Befehl. Gezielt einrichten bzw.
die Frage abschalten:

```bash
curl -fsSL https://raw.githubusercontent.com/testbild-media/openHeadscaleGUI/main/install.sh | sudo sh -s -- --enable-ufw
```

(`--no-ufw` unterdrückt das Angebot.) Die Firewall des Hosters ersetzt das nicht – und umgekehrt.

### Firewall-Automatik für TCP/UDP-Forwards

ohg selbst läuft ohne Root-Rechte und darf die Firewall nicht ändern. Es legt nur die Liste der benötigten
Forward-Ports in `/var/lib/ohg/firewall/ports.json` ab. Der kleine root-Dienst `ohg-firewall` (systemd, ausgelöst
bei jeder Änderung der Liste und alle 2 Minuten) setzt sie in **UFW** bzw. **firewalld** um:

* geöffnet wird ein Port nur, **solange ohg selbst darauf lauscht** – ein kompromittiertes ohg kann so keinen anderen
  Dienst des Servers freigeben; Ports unter 1024 fasst er nie an;
* er entfernt **nur Regeln, die er selbst angelegt hat** (UFW-Kommentar `ohg-forward`); eigene Regeln bleiben
  unberührt, ein Port mit eingeschränkter eigener Regel (z. B. nur aus `10.0.0.0/8`) wird nicht für alle geöffnet;
* Deaktivieren oder Löschen eines Forwards schließt den Port wieder; während ohg neu startet, bleibt alles, wie es ist.

Den Stand zeigt die Port-Forwards-Seite je Forward („Server-Firewall offen“, „eigene Regel“, „ohg lauscht nicht“ …).
Die **Firewall des Hosters** (Cloud-Panel) erreicht ohg nicht – dort Ports selbst freigeben. Abschalten:
`sudo systemctl disable --now ohg-firewall.path ohg-firewall.timer` (bleibt bei Updates aus).

Ohne Rückfragen:

```bash
curl -fsSL https://raw.githubusercontent.com/testbild-media/openHeadscaleGUI/main/install.sh \
  | sudo sh -s -- --yes --domain admin.example.com --email ich@example.com
```

Danach `https://admin.example.com/setup` öffnen, Code eingeben, Superadmin anlegen und 2FA einrichten.
Den Code jederzeit erneut anzeigen: `sudo ohg setup-token`.

### Hinter Caddy (oder einem anderen Reverse-Proxy)

Läuft auf dem Server schon ein Webserver auf Port 80/443, betreibt man ohg dahinter: ohg lauscht dann nur lokal
(`127.0.0.1:8480`), TLS-Zertifikate und die Ports 80/443 übernimmt der Proxy. Der Installer erkennt belegte Ports
und bietet das von selbst an, oder direkt:

```bash
curl -fsSL https://raw.githubusercontent.com/testbild-media/openHeadscaleGUI/main/install.sh \
  | sudo sh -s -- --behind-proxy --domain admin.example.com
```

Caddyfile – Caddy holt mit *On-Demand-TLS* automatisch Zertifikate für **alle Domains, die ohg kennt** (Verwaltung,
DERP, Instanzen, HTTPS-Forwards; auch später angelegte) und für keine anderen:

```caddyfile
{
	on_demand_tls {
		ask http://127.0.0.1:8480/_ohg/tls-ask
	}
}

https:// {
	tls {
		on_demand
	}
	reverse_proxy 127.0.0.1:8480
}
```

* Der `{ … }`-Block gehört zu den globalen Optionen ganz oben im Caddyfile (mit vorhandenen globalen Optionen zusammenführen).
* `https://` ist ein Auffang-Block: Eigene Sites mit konkretem Hostnamen haben Vorrang und laufen unverändert weiter.
  Gibt es schon einen anderen Auffang-Block (`https://` oder `:443`), stattdessen die ohg-Domains explizit auflisten.
* Tailscale-Anmeldung, DERP und WebSockets laufen über HTTP-Upgrades – Caddy reicht sie ohne weitere Einstellungen durch.
* Leitet der Proxy auch unverschlüsseltes HTTP an ohg weiter (`X-Forwarded-Proto: http`), leitet ohg selbst auf `https://` um.
  Die Verwaltung muss genau unter `https://<OHG_ADMIN_DOMAIN>` aufgerufen werden – ohne anderen Host oder Port.
* Direkt an ohg (nicht über Caddy) gehen weiterhin: **3478/udp** (STUN), **41641–41740/udp** (WireGuard des Server-Nodes)
  und die Ports eigener TCP/UDP-Forwards.
* Bestehende Installation umstellen: Installer mit `--behind-proxy` erneut ausführen
  (setzt `OHG_TLS_MODE=off`, `OHG_HTTP_ADDR=127.0.0.1:8480`, `OHG_TRUSTED_PROXIES=127.0.0.1/32,::1/128`).

**Update:** denselben Befehl erneut ausführen – Konfiguration und Daten bleiben erhalten.
**Deinstallation:** `… | sudo sh -s -- --uninstall` (mit `--purge` zusätzlich Konfiguration und Daten löschen).
Dabei verschwinden auch die UFW-Regeln von ohg: die der Firewall-Automatik (`ohg-forward`) und die vom Installer
angelegten Grundports (`OpenHeadscaleGUI …`). Die SSH-Regeln, Regeln für Reverse-Proxy/Tailnet und eigene Regeln
bleiben, UFW bleibt eingeschaltet. Bei firewalld nennt der Installer nur die Befehle zum Entfernen.

## Schnellstart in der GUI

1. **DERP-Server** (Administration → DERP-Server): Domain eintragen, aktivieren. Client-Verifikation ist standardmäßig an.
2. **Neue Instanz**: Name, Kurzname und Domain (z. B. `vpn-firma.example.com`). Headscale und der Server-Node (`100.64.0.1`) starten automatisch.
3. **Geräte verbinden**
   * *Mit Freigabe:* `tailscale up --reset --force-reauth --accept-routes --login-server https://vpn-firma.example.com` (Linux mit `sudo`, Windows als Administrator) – die angezeigte URL öffnen, das Gerät erscheint unter **Freigaben**, dort Benutzer, Name und optional feste IP wählen und freigeben.
   * *Automatisch mit fester IP:* unter **Clients & Keys** einen Client mit Name und IP anlegen und den angezeigten Befehl mit Schlüssel auf dem Gerät ausführen.
     Solange der Schlüssel gültig ist, holt **Befehl anzeigen** den Befehl jederzeit wieder hervor. Für eine erneute Anmeldung –
     z. B. nach einem Wechsel in ein anderes Tailnet und zurück – erzeugt **Neuer Schlüssel** einen frischen Einmal-Schlüssel;
     Name und feste IP des Profils bleiben erhalten.
   * *Apps (iOS/Android/macOS):* in den Einstellungen „alternativer Server“ = Instanz-URL.
4. **Exit-Node / Subnetze:** Auf der Geräteseite jede beworbene Route einzeln freigeben. Den Server als Exit-Node nutzen: `tailscale set --exit-node=100.64.0.1`.
5. **Port-Forwarding:** z. B. `nas.example.com` → Gerät „nas“ Port 5000 (HTTPS-Ziel, Zertifikat nicht prüfen) oder TCP-Port 20022 → Gerät:22.
   Dienste auf dem Server selbst gibt ein Superadmin unter **Administration → Server-Freigaben** frei, z. B.
   `os.example.com` → `127.0.0.1:9000` oder TCP/UDP 25565 → Docker-Container `172.17.0.2:25565` (die Ports von ohg
   selbst sind gesperrt). Dafür braucht es **keine Instanz**; Deaktivieren oder Löschen einer Instanz berührt
   Server-Freigaben nicht. Frühere Forwards mit Ziel „Dieser Server“ ziehen beim Update automatisch dorthin um.
   **Weiterleitungen** (eigener Menüpunkt): z. B. `alt.example.com` → `https://neu.example.com` oder `shop.example.com` →
   `https://www.example.org/shop` – unabhängig von den Instanzen; Benutzer nur unter den erlaubten Domain-Endungen.
6. **Brücken & Isolation:** Beispiel „Server in Instanz *Systeme*, PCs in Instanz *Personen*“: in *Personen*
   unter Einstellungen „Geräte voneinander isolieren“ einschalten, dann unter **Brücken** „Ganzer Host“:
   *Server A* → *Personen*, erlaubt für Person A. Server A ist in *Personen* dann unter z. B. `198.18.0.1` bzw.
   `server-a.<MagicDNS-Domain>` (nur mit eingeschaltetem MagicDNS, Standard: aus) mit **allen Ports** erreichbar – aber nur für Person A; die PCs sehen sich untereinander
   nicht. Windows, Android und iOS nehmen die nötige Route automatisch an, Linux-Clients brauchen `--accept-routes`
   (steht im angezeigten Befehl). Ping (ICMP) wird nicht weitergeleitet. Alternativ „Einzelner Port“ auf `.1:Port`.
7. **Monitoring:** Erreichbarkeit, Latenz und Traffic pro Gerät, live aktualisiert.

> Hinweis zum Traffic: Gemessen wird alles, was über den Server läuft (Port-Forwards, Exit-Node, DERP-Relay).
> Direkte Verbindungen zwischen zwei Geräten sind Ende-zu-Ende verschlüsselt und für den Server nicht sichtbar.

## Fehlersuche

**Gerät ist online, aber nicht erreichbar** (Ping ✗, Port-Forwards und Brücken enden mit `context deadline exceeded`):
Die Monitoring-Seite zeigt dann unter „DERP-Relay“ meist **„fehlt“**, die Geräteliste **„ohne Relay“**. Das Gerät
ist mit der Steuerung verbunden, aber nicht mit dem Relay, und damit nur direkt per UDP erreichbar. Abhilfe auf
dem Gerät: Tailscale neu starten (`sudo systemctl restart tailscaled`, unter Windows/macOS Tailscale beenden und
neu öffnen, auf dem Handy das VPN aus- und einschalten). ohg meldet das nur bei Instanzen, die ausschließlich den
zentralen DERP nutzen, und erst nach zwei Minuten (Neuverbindung nach einem Neustart von ohg).

**`lookup derp.… on [::1]:53: … connection refused` im Log von tailscaled:** Der DNS-Resolver des Geräts fehlt
oder ist ausgefallen (z. B. `/etc/resolv.conf` ohne `nameserver`). Die Steuerung läuft dank Cache weiter, der
Relay aber nicht. ohg trägt deshalb die öffentlichen Adressen der DERP-Domain automatisch in die DERP-Map ein
(DERP-Seite, Felder IPv4/IPv6: leer = automatisch, `none` = Adressfamilie aus); die Geräte erreichen Relay und
STUN dann ohne eigene DNS-Abfrage. Den Resolver auf dem Gerät trotzdem reparieren.

**`/etc/resolv.conf` enthält nur noch `search <basis-domain>`:** Das schreibt tailscale auf Linux-Geräten ohne
systemd-resolved, wenn die Instanz eine Suchdomain verteilt, aber weder MagicDNS noch eigene DNS-Server – alle
DNS-Abfragen auf dem Gerät schlagen dann fehl. ohg verteilt die Basis-Domain deshalb nur noch zusammen mit MagicDNS
(ab v0.4.3, neue Instanzen starten außerdem ohne MagicDNS); nach dem Update stellt tailscale die ursprüngliche
`resolv.conf` selbst wieder her.

**Warnung „Von außen kommt kein UDP an“:** Geräte nutzen den Relay, aber am STUN-Port kommt seit dem Start keine
einzige Anfrage von außen an. Fast immer blockiert die Firewall des Hosters eingehendes UDP. Dort **3478/udp** und
die UDP-Ports der Server-Nodes (ab **41641/udp**, einer je Instanz; die Warnung nennt die genauen Ports)
freigeben. Die Warnung verschwindet mit der ersten Anfrage von außen.

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
| `OHG_PUBLIC_IPV4` / `OHG_PUBLIC_IPV6` | leer | feste IPs für die DERP-Map (Vorbelegung; sonst ermittelt ohg die öffentlichen Adressen der DERP-Domain selbst) |
| `OHG_DATA_DIR` | `/var/lib/ohg` | Daten |
| `OHG_HEADSCALE_BIN` | `/usr/local/lib/ohg/headscale` | Headscale-Binary |
| `OHG_LOG_LEVEL` | `info` | `debug`, `info`, `warn`, `error` |

Weitere Einstellungen (Name der Installation, Quoten, Domain-Endungen, Port-Bereich für Forwards, 2FA-Pflicht, Audit-Aufbewahrung)
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
