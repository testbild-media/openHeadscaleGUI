# Sicherheit

OpenHeadscaleGUI ist dafür gebaut, direkt im Internet zu laufen. Dieses Dokument beschreibt die Schutzmaßnahmen
und Empfehlungen für den Betrieb.

## Empfehlungen für den Betrieb

1. **Admin-IP-Allowlist** setzen (`OHG_ADMIN_ALLOW_CIDRS`), z. B. auf die Büro-IP oder das Tailnet des
   Superadmins. Nicht erlaubte Adressen erhalten auf der Admin-Domain nur „404“.
2. **2FA für alle** erzwingen (`OHG_REQUIRE_2FA=true` oder GUI → Einstellungen).
3. **Domain-Endungen für Benutzer** einschränken (GUI → Einstellungen), damit Benutzer keine fremden
   Domains für Zertifikate anfragen können.
4. Server aktuell halten und den Installer regelmäßig erneut ausführen (Updates von ohg und Headscale).
5. Backups von `/var/lib/ohg` verschlüsselt ablegen – dort liegen Master-Key und Headscale-Schlüssel.

## Umgesetzte Maßnahmen

### Netzwerk & TLS
* Ein einziger Edge-Listener auf 443 mit TLS ≥ 1.2 und modernen AEAD-Ciphern; Zertifikate per ACME
  (TLS-ALPN-01/HTTP-01) nur für **bekannte** Domains – unbekannte SNI-Namen scheitern beim Handshake.
* SNI und Host-Header müssen übereinstimmen (kein Domain-Fronting zwischen Admin-, Instanz- und Forward-Domains).
* Headscale lauscht ausschließlich auf `127.0.0.1`; Metrics und Remote-gRPC sind abgeschaltet.
  `/api`, `/swagger`, `/verify`, `/metrics`, `/debug`, `/version` sind von außen gesperrt.
* Der DERP-Admission-Endpunkt läuft nur auf Loopback unter einem zufälligen Pfad.
* Eingebettete Tailscale-Nodes senden keine Logs an Tailscale Inc. (`TS_NO_LOGS_NO_SUPPORT`).

### WebGUI
* Server-seitiges Rendering mit kontextabhängigem Escaping (`html/template`), keine Inline-Skripte,
  keine Fremd-CDNs: `Content-Security-Policy: default-src 'none'; script-src 'self'; style-src 'self'; …;
  frame-ancestors 'none'; form-action 'self'; base-uri 'none'`.
* `Strict-Transport-Security`, `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff`,
  `Referrer-Policy: same-origin`, `Cross-Origin-Opener-Policy`, `Cross-Origin-Resource-Policy`,
  `Permissions-Policy`, `Cache-Control: no-store`.
* CSRF: Token pro Sitzung (Double-Submit-Cookie vor dem Login) **und** Prüfung von `Origin`/`Sec-Fetch-Site`.
* Request-Body-Limit 1 MiB, Header-Timeouts gegen Slowloris, Rate-Limit pro IP.
* Offene Weiterleitungen nach dem Login sind auf relative Pfade beschränkt.

### Authentifizierung
* Passwörter mit **Argon2id** (64 MiB, t=3, p=2), begrenzte Parallelität gegen Speicher-DoS,
  Mindestlänge 12 und Komplexitäts-/Blocklisten-Prüfung.
* Gleiche Antwortzeit und Meldung für unbekannte Benutzer und falsche Passwörter (keine User-Enumeration).
* Sperre pro IP (10 Fehlversuche / 15 min) und exponentielles Konto-Lockout (ab 5 Fehlversuchen, bis 60 min).
* **TOTP-2FA** (RFC 6238) mit Replay-Schutz, 10 Einmal-Recovery-Codes (nur gehasht gespeichert).
* Sitzungen: 256-bit-Zufallstoken, in der Datenbank nur als SHA-256; Cookie `__Host-…` mit
  `Secure`, `HttpOnly`, `SameSite=Strict`; Leerlauf- und absolutes Timeout; neue Sitzung bei jedem Login;
  Passwortänderung beendet alle anderen Sitzungen; Sitzungsübersicht mit Widerruf.
* Ersteinrichtung nur mit einmaligem Einrichtungs-Code aus dem Server-Log.

### Autorisierung
* Benutzer sehen und verwalten ausschließlich eigene Instanzen; fremde IDs liefern „404“ (keine Existenz-Leaks).
* Superadmin-Bereiche (DERP, Benutzer, Einstellungen) sind für Benutzer unsichtbar.
* Der letzte Superadmin kann weder gelöscht noch herabgestuft werden.
* Alle Änderungen landen im **Audit-Log** (Benutzer, IP, Instanz, Aktion).

### Daten
* Headscale-API-Keys, TOTP-Geheimnisse und in der GUI erzeugte Pre-Auth-Keys sind mit **AES-256-GCM** verschlüsselt (Master-Key `0600`).
  Pre-Auth-Keys werden nur so lange aufbewahrt, wie sie noch verwendbar sind (gelöscht bei Ablauf, Widerruf oder Verwendung eines
  Einmal-Schlüssels); jedes erneute Anzeigen landet im Audit-Log (`key.show`).
* SQLite mit `secure_delete`, Dateirechte `0750`/`0640`.
* Basic-Auth-Passwörter von Forwards als Argon2id-Hash; erfolgreiche Prüfungen werden nur als HMAC kurz gecacht;
  Fehlversuche pro Forward werden gesperrt.

### Server als Exit-Node
* Der Server leitet Exit-Node-Traffic nur zu **öffentlichen Adressen** weiter. Loopback, private Netze (RFC 1918, ULA),
  Link-Local (u. a. Cloud-Metadaten `169.254.169.254`), Tailnet-Adressen (`100.64.0.0/10`, `fd7a:115c:a1e0::/48`),
  Multicast und reservierte Bereiche werden abgewiesen – Clients erreichen über den Exit-Node also keine Dienste auf dem
  Server selbst oder im Netz des Hosters.
* Die Weiterleitung ist nur aktiv, solange der Exit-Node der Instanz freigegeben ist; ACLs der Policy gelten zusätzlich.

### Prozess
* Eigener Systembenutzer ohne Login-Shell; einzige Capability `CAP_NET_BIND_SERVICE`.
* systemd-Härtung: `NoNewPrivileges`, `ProtectSystem=strict`, `ProtectHome`, `PrivateTmp`, `PrivateDevices`,
  `RestrictAddressFamilies`, `SystemCallFilter=@system-service`, `MemoryDenyWriteExecute` u. a.
* CLI-Befehle, die als root aufgerufen werden, geben die Rechte an den Dienstbenutzer ab.
* Downloads im Installer werden per SHA256 verifiziert.

## Schwachstellen melden

Bitte Sicherheitslücken nicht öffentlich als Issue melden, sondern über die private
„Report a vulnerability“-Funktion von GitHub (Security → Advisories) im Repository.
