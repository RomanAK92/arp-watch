# ARP Watch

A self-hosted IPv4 conflict detector with a dashboard, persistent incident evidence, read-only switch-port tracing, and Uptime Kuma notifications.

ARP Watch actively asks selected addresses who owns their IP, compares the replies with explicitly approved MAC addresses, and stores conflicts for investigation. It does not depend on switch duplicate-IP logs.

## Features

- Duplicate-IP and unexpected-MAC detection on configured addresses.
- Automatic MAC tracing through an explicitly maintained switch-link map.
- Comware 5, AOS-S/ProCurve, AOS-CX, and HPE OfficeConnect 1820 web adapters.
- Immediate incident storage, timestamps, packet headers, and saved MAC-table evidence.
- Incidents remain open after disconnection until an administrator selects **Resolve**.
- Resolve is blocked while the conflict is observed or monitoring is unhealthy.
- Dashboard login, username/password settings, session invalidation, and CSRF protection.
- Updated passwords stored as salted PBKDF2-SHA256 hashes.
- Configurable resolved-incident retention: 30 days by default, counted from resolution; 0 keeps history indefinitely. Unresolved incidents never expire.
- Detailed Uptime Kuma push messages with MACs, last confirmed switch, port, VLAN, and path. Kuma can deliver Telegram notifications and reminders.

## Requirements

Linux, Docker Compose, and Layer 2 access to the monitored network. The included image uses Python 3.12 because the legacy Telnet adapter requires `telnetlib`. Use read-only switch accounts where supported. Credentials and push tokens must remain private.

## Quick start

```sh
git clone https://github.com/RomanAK92/arp-watch.git
cd arp-watch
python3 initialize.py
# Edit config.json privately before starting.
mkdir -p data
chmod 700 data
chmod 600 config.json
docker compose up -d --build
```

Open `http://<linux-host>:8096/` and sign in using the username and generated password in `config.json`. Set `interface` to the physical LAN interface, configure `bind`, and replace every documentation-only example address and credential. Set `dashboard_url` to the URL operators can reach.

Each target has an IP, name, VLAN, and `approved_macs`. Confirm approved MACs from trusted device configuration before enabling monitoring. Never approve a MAC merely because it answered a probe.

`switches` maps management IPs to `name`, `family`, `transport`, `username`, and `password`. Supported families are `comware`, `procurve`, `cx`, and `officeconnect`. OfficeConnect uses `http`; CLI families use `ssh` or legacy `telnet`. The OfficeConnect adapter logs in, reads the MAC-table page, and logs out; it does not call switch configuration endpoints.

`links` contains directed uplink/downlink mappings with `a`, `a_port`, `b`, and `b_port`. Add both directions when appropriate. Keep this map current: a stale map can stop tracing or misidentify the downstream branch. Aggregate ports without a verified mapping are reported as incomplete, not physical access ports.

## Uptime Kuma and Telegram

Create a **Push** monitor. Set its heartbeat interval to 120 seconds, retries to 0, and reminder interval to 15. Enable your existing Telegram notification profile. Add the secret URL to private `config.json`:

```json
{"kuma_push_url":"http://kuma-host:3001/api/push/YOUR_PRIVATE_TOKEN"}
```

ARP Watch sends heartbeats every 60 seconds. A conflict or unavailable monitoring sends DOWN. Healthy monitoring with no unresolved incidents sends UP. Reminders repeat approximately every 15 failed heartbeats. Missing heartbeats also alert. Only push tokens are needed by ARP Watch; Telegram bot credentials remain in Kuma.

Alerts include known approved names and optional explicit `device_labels`. Unknown device names remain unknown. A bounded 10-second wait allows quick tracing to finish before sending; incomplete or pending traces are labelled and subsequent heartbeats contain updated evidence. A final port cannot be guaranteed if the MAC ages out, switch management is unreachable, a device is unsupported, or an unmanaged switch sits downstream.

## Settings, storage, and backup

Use **Settings** to change the account or retention policy. The current password is required. Credential changes sign out all sessions without stopping monitoring. Overrides persist in `data/settings.json`; they take precedence over the initial account in read-only `config.json`.

Incident data is stored in `data/incidents.sqlite3` with SQLite WAL and synchronous FULL. Resolved incidents older than the configured retention and their evidence are permanently removed on settings save and during hourly cleanup. Use 0 to disable expiration. Operational container logs rotate separately at 2 MB x 3.

Back up the database with SQLite's backup API, plus `config.json` and `data/settings.json`. Do not simply copy a live SQLite file while WAL is active. Keep backups private. Restore only with the service stopped and preserve file permissions.

## Security and limitations

The container uses host networking and only the added NET_RAW capability, with a read-only root filesystem and limits of 0.25 CPU, 192 MiB RAM, and 64 processes. Use HTTPS through an authenticated/trusted internal reverse proxy and set `cookie_secure` to true when serving exclusively over HTTPS. Do not expose this management application directly to the Internet. Legacy Telnet and OfficeConnect HTTP transmit credentials without encryption; limit their use to trusted management networks. The SSH adapter currently accepts an unknown host key; validate management endpoints out of band.

The probe implementation and tracer currently support **VLAN 1 on the sensor's local Layer 2 segment**. Other VLANs require local visibility and additional implementation. It monitors selected addresses, not an entire subnet. Silent devices, very short connections, MAC cloning, and unreachable management can limit detection. It does not block devices or replace DHCP snooping, Dynamic ARP Inspection, or network access control.

The green dashboard wording is **No unresolved conflicts detected**, not a guarantee that the whole network is safe.

## Tests

Use Python 3.12:

```sh
python -m pip install -r requirements.txt
python -m unittest discover -s . -p test_app.py
python test_http.py
```

Tests use temporary storage and loopback HTTP; they send no ARP probes, switch logins, or notifications. Production configurations, incident exports, and credentials are excluded from this repository.

## License

No reuse license has been selected yet.
