# OpenHeadscaleGUI – Architektur & Umsetzungsplan

OpenHeadscaleGUI (`ohg`) ist eine Multi-Mandanten-Verwaltung für selbst gehostete
Tailscale-Netze (Tailnets) auf Basis von [Headscale](https://github.com/juanfont/headscale).
Es läuft als **ein einziges Binary** unter Linux/Debian (systemd) und wird – ähnlich wie
Tailscale – per Einzeiler installiert.

## Ziele

| Anforderung | Umsetzung |
|---|---|
| Mehrere Tailscale-Instanzen | Jede Instanz = eigener Headscale-Prozess (eigene DB, eigene Noise-Keys, eigene Domain) |
| Eigene Domains/Subdomains | Edge-Server auf :443 mit automatischem Let's-Encrypt (ACME, TLS-ALPN-01 + HTTP-01), Routing per SNI/Host |
| Clients hinzufügen/ändern/entfernen | Pre-Auth-Keys (verschlüsselt gespeichert, Befehl erneut abrufbar), „Client-Profile“ (Name, feste IP, Auto-Approve, neuer Schlüssel für erneute Anmeldung), Umbenennen, Ablauf, Löschen |
| Approve | Interaktive Registrierungen werden abgefangen und als „Ausstehend“ in der GUI zur Freigabe angezeigt |
| Feste Tailscale-IPs | IP pro Node frei wählbar (Validierung gegen Präfix + Kollisionen), Profile reservieren IPs vor der Registrierung |
| Einzel-Approve von Subnetzen | Jede beworbene Route einzeln freigeben/entziehen, Exit-Node separat |
| Optionaler Exit-Node | Client-Exit-Nodes freigeben **und** optional den Server selbst (Gateway) als Exit-Node anbieten |
| Port-Forwarding pro Client/Domain | HTTP(S) per Domain → Client:Port (inkl. WebSocket, TLS-Upstream, IP-Allowlist, Basic-Auth) sowie TCP/UDP-Ports → Client:Port |
| Benutzerverwaltung | Rollen `superadmin` (alles) und `user` (nur eigene Instanzen), Quoten, Domain-Suffix-Beschränkung |
| Zentraler DERP mit Client-Verifikation | Eingebetteter DERP- + STUN-Server, eigene Domain, Admission-Controller prüft Node-Keys aller Instanzen |
| Sicher im Internet | Argon2id, TOTP-2FA + Recovery-Codes, Rate-Limits, Lockout, CSRF, strikte CSP, HSTS, Audit-Log, IP-Allowlist |
| Einfache Installation | `curl -fsSL …/install.sh \| sudo sh` – lädt Binaries (SHA256-geprüft), richtet systemd ein |

## Komponenten (alle im Prozess `ohg`)

```
                    Internet
                       │
          ┌────────────┴─────────────┐
   :80/tcp│  :443/tcp          :3478/udp      TCP/UDP-Forward-Ports
          ▼                         ▼                 ▼
 ┌──────────────────────────────────────────────────────────────┐
 │ Edge (TLS/ACME, Host-Routing, Rate-Limits)                    │
 │  ├─ admin.example.com   → WebGUI (Auth, RBAC, CSRF, CSP)      │
 │  ├─ derp.example.com    → eingebetteter DERP  ◄── STUN        │
 │  ├─ vpn1.example.com    → Reverse-Proxy → headscale #1        │
 │  ├─ vpn2.example.com    → Reverse-Proxy → headscale #2        │
 │  └─ app.example.com     → HTTP-Forward → Gateway #1 → Client  │
 │                                                              │
 │ Supervisor  ── startet/überwacht headscale-Prozesse (127.0.0.1)│
 │ Gateways    ── je Instanz ein tsnet-Node (Userspace, kein TUN) │
 │ Forwarder   ── TCP/UDP-Listener → Gateway-Dial                 │
 │ Reconciler  ── Node-Cache, Profile, Auto-Approve, DERP-Index   │
 │ Store       ── SQLite (WAL) für GUI-Daten                      │
 └──────────────────────────────────────────────────────────────┘
```

### Edge
* Ein `net/http`-Server für :443 mit `autocert`; `HostPolicy` erlaubt nur bekannte Domains
  (Admin, DERP, Instanzen, HTTP-Forwards). Unbekannte SNI → TLS-Handshake schlägt fehl.
* :80 beantwortet nur ACME-HTTP-01 und leitet bekannte Hosts auf HTTPS um.
* Instanz-Proxy: `/ts2021` (Noise-Upgrade) und Long-Polls werden durchgereicht
  (`FlushInterval=-1`). Gesperrt nach außen: `/api/`, `/swagger`, `/verify`, `/metrics`, `/debug`.
* `GET /register/{auth_id}` wird abgefangen → Eintrag „Ausstehend“ + eigene Warteseite.
* Modi: `acme` (Produktion), `selfsigned` (Test), `off` (nur HTTP hinter externem Proxy/Dev).

### Headscale-Supervisor
* Pro Instanz Verzeichnis `/var/lib/ohg/instances/<slug>/` mit `config.yaml`, `db.sqlite`,
  `noise_private.key`, `derpmap.yaml`, `headscale.sock`, `gateway/`.
* Headscale lauscht nur auf `127.0.0.1:<port>`; Metrics und Remote-gRPC sind deaktiviert.
* API-Zugriff über REST (`/api/v1`) mit API-Key, der beim ersten Start per CLI erzeugt und
  AES-GCM-verschlüsselt gespeichert wird.
* Automatischer Neustart mit Backoff, Log-Ringpuffer pro Instanz in der GUI.
* Policy-Modus `database` → ACL-Editor in der GUI ohne Neustart.
* DNS: Die Basis-Domain geht nur zusammen mit MagicDNS an Headscale. Ohne MagicDNS käme sie als Suchdomain ohne
  Nameserver bei den Geräten an, und tailscale schreibt auf Linux ohne systemd-resolved („direct“-Modus) dann eine
  `/etc/resolv.conf`, die nur `search <domain>` enthält.

### Feste IPs
Headscale hat keine API zum Setzen einer IP. `ohg` stoppt die Instanz kurz, schreibt die IP
in die Headscale-DB (`nodes.ipv4/ipv6`) und startet neu (~1–2 s). Clients übernehmen die neue
Adresse automatisch. Client-Profile reservieren eine IP; sobald sich der Client mit dem
Profil-Key registriert, setzt der Reconciler Name, IP und freigegebene Routen.

### Gateway & Port-Forwarding
* Pro Instanz ein eingebetteter Tailscale-Node (`tsnet`, Userspace-Netzwerk), registriert
  über einen Einmal-Key unter dem Tailnet-Benutzer `ohg-gateway`.
* Exit-Node: tsnet verwirft standardmäßig alle Verbindungen ohne eigenen Listener. ohg hängt sich in die
  Netstack-Hooks (`GetTCPHandlerForFlow`/`GetUDPHandlerForFlow`) und übergibt Verbindungen zu öffentlichen
  Zielen an die Netstack-Weiterleitung (wie `tailscaled --tun=userspace-networking`); interne Ziele
  (Loopback, privat, Link-Local, Tailnet) bleiben gesperrt.
* HTTP-Forward: `domain → (Node | freie IP/Subnetz-Ziel):port`, HTTP oder HTTPS-Upstream,
  optional Host-Header beibehalten, IP-Allowlist, Basic-Auth. `Location`/`Content-Location` des Ziels, die auf
  die Ziel-Adresse (IP:Port) oder auf die öffentliche Domain mit anderem Schema/Port zeigen (z. B. den eigenen
  HTTPS-Port des Ziels), werden wie bei nginx `proxy_redirect default` auf die öffentliche URL umgeschrieben.
* TCP/UDP-Forward: öffentlicher Port (aus freigegebenem Bereich) → Ziel:Port.
* Weiterleitungen: eigene Tabelle `redirects` (gehören einem Benutzer, nicht einer Instanz); der Router liefert für
  ihre Domains einen Redirect-Handler, auf Port 80 bzw. bei `X-Forwarded-Proto: http` direkt zum Ziel.
* Host-Brücke: Gerät aus Instanz A bekommt in Instanz B eine Adresse aus deren Brücken-Netz (Standard 198.18.0.0/24);
  das Gateway von B bietet das Netz als Route an (von ohg freigegeben), nimmt in den Netstack-Hooks jeden TCP/UDP-Flow zu
  diesen Adressen an, prüft das Quellgerät und verbindet über das Gateway von A zum echten Host (gleicher Port).
  DNS-Namen über die `extra_records_path`-Datei von Headscale (wird ohne Neustart neu gelesen).
* Port-Brücke: Dienst eines Geräts in Instanz A → Listener des Gateways von Instanz B auf `.1:Port` (tsnet `Listen`),
  Verbindung über das Gateway von A; zugelassen nur die ausgewählten Geräte von B (Prüfung der Quell-Tailnet-IP).
  Gleiche Relay-Logik wie TCP/UDP-Forwards (`forward.Manager` mit eigenem Listener, Admit-Funktion und Scope je Instanz).
* Isolation: ohg schreibt die ACL `ohg-system@ → *:*`, `* → .1:*`, `* → autogroup:internet:*` – Geräte erhalten sich
  gegenseitig gar nicht erst als Peers.
* Ziel „Dieser Server“ (nur Superadmin): direkte Verbindung über das Netz des Servers statt über das Tailnet
  (Loopback/private Netze, ohg-eigene Ports gesperrt). Typ „redirect“: Domain → URL mit 301/302/307/308.
* Ziel „Node“ wird dynamisch über die aktuelle Node-IP aufgelöst (IP-Wechsel bricht nichts).
* Optional: Gateway bewirbt `0.0.0.0/0, ::/0` → der Server wird Exit-Node der Instanz.

### DERP
* `derpserver` + `stunserver` aus `tailscale.com` eingebettet, eigene Domain über den Edge.
* Client-Verifikation über internen Admission-Controller (nur Loopback): erlaubt Node-Keys,
  die in einer Instanz mit aktiviertem „zentralem DERP“ registriert sind (+ Allow-/Denylist).
* DERP-Map wird pro Instanz als `derpmap.yaml` generiert; öffentliche Tailscale-DERPs optional.
* Adressen in der DERP-Map: eingetragene IPv4/IPv6 (oder `none`) haben Vorrang; sonst löst ohg die DERP-Domain beim
  Start, beim Speichern und alle 5 min selbst auf und übernimmt die erste öffentliche Adresse je Familie (private,
  CGNAT-, Doku- und Benchmark-Netze nie – Schutz vor Split-DNS). Die Geräte wählen den Relay und STUN dann ohne
  eigene DNS-Abfrage an (TLS weiter mit dem Hostnamen). Ändert sich eine Adresse, bekommen die betroffenen
  Instanzen die neue Map (Headscale-Neustart); ein fehlgeschlagener Lookup behält das letzte Ergebnis.
* STUN: eigener kleiner Server (Paketformat aus `tailscale.com/net/stun`), der Anfragen von außen je
  Adressfamilie zählt; Anfragen von den eigenen Adressen des Servers (Gateways) zählen nicht. Sind Relay-Clients
  von außen verbunden, aber kam 5 min nach dem Start keine einzige STUN-Anfrage dieser Adressfamilie an, warnt
  die GUI „UDP von außen blockiert“ (typisch: Firewall des Hosters) und nennt die freizugebenden Ports.

### Server als Mitglied jedes Tailnets
* Der Gateway-Node registriert sich als erstes Gerät jeder Instanz (Benutzer `ohg-system`) und erhält die
  reservierte erste Adresse des Netzes (`.1`, z. B. `100.64.0.1`). Weicht sie ab (z. B. bei zufälliger
  Vergabe), verschiebt der Reconciler sie – notfalls per Tausch mit dem belegenden Gerät. Die `.1` kann
  keinem anderen Gerät zugewiesen werden.
* Der Gateway-Node bewirbt immer `0.0.0.0/0` und `::/0`; die Freigabe als Exit-Node steuert die
  Instanz-Einstellung (Standard: an). Userspace-Netstack → keine TUN-Rechte nötig.

### Monitoring
* Alle 10 s: WireGuard-Zähler des Gateways je Peer (Traffic zwischen Gerät und Server), Zähler der
  Port-Forwards und des DERP-Relays (inkl. Traffic je verbundenem Client) → Raten und 1-h-Verlauf.
* Alle 30 s: Disco-Ping vom Gateway zu jedem online gemeldeten Gerät → Latenz, Pfad (direkt/DERP/Peer-Relay),
  Verfügbarkeit.
* Darstellung als serverseitig gerenderte SVG-Sparklines, Live-Aktualisierung per `fetch` ohne Inline-JS.
* Direkter Gerät-zu-Gerät-Traffic ist Ende-zu-Ende verschlüsselt und wird bewusst nicht gemessen.
* Relay-Prüfung: Bei Instanzen, die ausschließlich den zentralen DERP nutzen, muss jedes online gemeldete Gerät
  mit dem Relay verbunden sein. Fehlt die Verbindung länger als 2 min, markiert die GUI das Gerät „ohne Relay“
  (Geräteliste, Monitoring, Geräteseite, Übersicht, DERP-Seite) mit Abhilfe. Server-Nodes zählen nicht.

### Installation
* `install.sh` (POSIX sh): lädt Release-Archiv + Headscale mit SHA256-Prüfung (Fallback: Build aus Quellcode
  inkl. temporärer Go-Toolchain), legt Benutzer/Verzeichnisse/Konfiguration an, installiert die gehärtete
  systemd-Unit, öffnet optional UFW/firewalld und zeigt den Einrichtungs-Code. Gleiches Skript für Updates
  und `--uninstall [--purge]`.
* GitHub-Workflow `release.yml` erzeugt bei Tags `v*` die Archive `ohg_linux_{amd64,arm64}.tar.gz`.

### Sicherheit WebGUI
* Server-seitiges Rendering (`html/template`, Auto-Escaping), keine Inline-Skripte, keine CDNs.
* CSP `default-src 'none'`, HSTS, `frame-ancestors 'none'`, `no-store`, COOP/CORP.
* Sessions: 256-bit Zufallstoken, nur SHA-256 in der DB, Cookie `__Host-` + Secure + HttpOnly +
  SameSite=Strict, Idle- und absolutes Timeout, Rotation beim Login, Sitzungsübersicht.
* CSRF: Token pro Session + Origin/Sec-Fetch-Site-Prüfung.
* Login: Argon2id (begrenzte Parallelität), Dummy-Hash gegen User-Enumeration, Rate-Limit
  pro IP, exponentielles Account-Lockout, TOTP (Replay-Schutz) + Recovery-Codes, 2FA-Pflicht optional.
* Optionale IP-Allowlist für die Admin-Domain; vertrauenswürdige Proxies explizit konfigurierbar.
* Audit-Log aller Änderungen; Secrets (API-Keys, TOTP, Pre-Auth-Keys) verschlüsselt mit Master-Key (0600).
* systemd-Härtung: eigener User, `NoNewPrivileges`, `ProtectSystem=strict`, nur
  `CAP_NET_BIND_SERVICE`.

### Rechte
| Aktion | user | superadmin |
|---|---|---|
| Eigene Instanzen anlegen/verwalten | ✔ (Quote, Domain-Suffixe) | ✔ |
| Fremde Instanzen | ✘ (404) | ✔ |
| DERP-Einstellungen | ✘ | ✔ |
| Benutzerverwaltung, globale Einstellungen | ✘ | ✔ |
| Audit-Log | eigene Instanzen | alles |

## Umsetzungsschritte
1. Git-Repo, Go-Modul, Projektstruktur
2. Kern: Konfiguration, SQLite-Store + Migrationen, Krypto (Argon2id, AES-GCM, TOTP)
3. Headscale: REST-Client, Config-Generator, Prozess-Supervisor, IP-Änderung
4. Gateway (tsnet), TCP/UDP/HTTP-Forwarding, eingebetteter DERP + STUN + Admission
5. Edge: TLS/ACME, Host-Routing, Instanz-Proxy, Registrierungs-Abfang
6. App-Orchestrierung, Reconciler (Node-Cache, Profile, Auto-Approve, DERP-Index)
7. WebGUI: Login/2FA/Setup, Dashboard, Instanzen (Nodes, Ausstehend, Clients/Keys,
   Tailnet-Benutzer, Forwards, Policy, Einstellungen, Logs), DERP, Benutzer, Audit, Profil
8. `install.sh`, systemd-Unit, GitHub-Actions-Release, Dockerfile (optional), Doku
9. Build, Unit-Tests, lokaler End-to-End-Test

## Verzeichnisstruktur
```
cmd/ohg/                 Einstiegspunkt + CLI (serve, user, setup-token, headscale …)
internal/config/         Umgebungs-/Dateikonfiguration
internal/store/          SQLite-Store, Migrationen, Modelle
internal/secure/         Argon2id, AES-GCM, TOTP, Tokens, QR
internal/headscale/      REST-Client, Config-Generator, Supervisor, IP-Änderung
internal/gateway/        tsnet-Gateways, TCP/UDP-Forwarder
internal/derp/           DERP-/STUN-Server, Admission
internal/edge/           TLS/ACME, Host-Routing, Proxies
internal/app/            Orchestrierung, Reconciler, Validierung
internal/web/            Handler, Middleware, Templates, Static
deploy/                  systemd-Unit, Beispiel-Env
install.sh               Installer/Updater/Uninstaller
```
