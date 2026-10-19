# ARP Watch

A self-hosted IPv4 conflict detector with a dashboard, persistent incident evidence, read-only switch-port tracing, and Uptime Kuma notifications.

ARP Watch actively asks selected addresses who owns their IP, compares the replies with explicitly approved MAC addresses, and stores conflicts for investigation. It does not depend on switch duplicate-IP logs.

## Why this project exists

Duplicate IP addresses can interrupt access to critical services. Switch logs alone may not provide timely alerts or identify a device's final port. ARP Watch probes independently, traces MAC addresses through supported switches, retains evidence after disconnection, and sends actionable notifications through a separate Uptime Kuma service.

## Features

- Browser setup wizard for the local interface, subnet, trusted IP/MAC devices, optional tracing, and optional Kuma.
- Duplicate-IP and unexpected-MAC detection on configured trusted addresses.
- Optional paced subnet discovery: two extra addresses per cycle, maximum 4094 hosts. A single unfamiliar MAC does not raise a conflict alert.
- Automatic MAC tracing through an explicitly maintained switch-link map.
- Comware 5, AOS-S/ProCurve, AOS-CX, and HPE OfficeConnect 1820 web adapters.
- Immediate incident storage, timestamps, packet headers, and saved MAC-table evidence.
- Incidents remain open after disconnection until an administrator selects **Resolve**.
- Resolve is blocked while the conflict is observed or monitoring is unhealthy.
- Dashboard login, username/password settings, session invalidation, and CSRF protection.
- Updated passwords stored as salted PBKDF2-SHA256 hashes.
- Configurable resolved-incident retention: 30 days by default, counted from resolution; 0 keeps history indefinitely. Unresolved incidents never expire.
- Detailed Uptime Kuma push messages with MACs, last confirmed switch, port, VLAN, and path. Kuma can deliver Telegram notifications and reminders.

## Windows startup compatibility — 19 October 2026

**Upgrade older installations before continuing active monitoring.** Earlier versions sent repeated ARP probes with sender IPv4 `0.0.0.0`. If a probe arrives while Windows is checking its address during startup or DHCP configuration, Windows can interpret it as a competing address probe and reject its own IP. [Microsoft describes this duplicate-address detection behavior](https://learn.microsoft.com/en-us/troubleshoot/windows-server/networking/event-4199-windows-client-cannot-get-ip-address-dhcp-server).

ARP Watch now sends normal ARP requests using the IPv4 address assigned to the selected Linux interface and its real MAC. If a usable interface IPv4 address is unavailable, it reports monitoring unavailable and sends no requests; it never falls back to `0.0.0.0`. Saved packet evidence records the actual sender IP. Duplicate-IP detection, approved-MAC comparisons, saved incidents, switch tracing, and Kuma integration remain available.

From the existing installation directory:

```sh
docker compose stop arp-watch
git pull --ff-only
docker compose up -d --build
```

Keep your private configuration and persistent data. If an older version has already caused Windows to reject its address, first stop ARP Watch, then use the affected machine's local or hypervisor console to restart its network adapter and verify recovery. Keep Windows duplicate-address detection enabled.

Regression tests check the request's source/target fields and reject unspecified, loopback, link-local, multicast, broadcast, and IPv6 sender addresses. A corrected request was also tested against two responders in an isolated Ethernet network, including retained evidence and manual resolution. These checks do not guarantee that every operating system, network design, or future reboot condition has been tested.

## Requirements

Linux, Docker Compose, and Layer 2 access to the monitored network. The included image uses Python 3.12 because the legacy Telnet adapter requires `telnetlib`. Use read-only switch accounts where supported. Credentials and push tokens must remain private.

## Quick start

```sh
git clone https://github.com/RomanAK92/arp-watch.git
cd arp-watch
python3 initialize.py
mkdir -p data
chmod 700 data
chmod 600 config.json
docker compose up -d --build
```

Open `http://<linux-host>:8096/`. Find the generated initial username/password locally in `config.json`, then sign in. The application directs you to **Setup wizard**; monitoring remains unavailable and sends no probes until you save a valid setup.

1. **Network:** select the Linux interface connected to your devices. Its IPv4 address and suggested subnet are displayed. Enter the dashboard URL your browser can reach (not `localhost` if using another computer).
2. **Trusted devices:** use **Add trusted device** to enter each device name, stable IP, and approved MAC. Find the router's LAN MAC in its own settings or a known device inventory. Multiple legitimate MACs for one IP can be entered comma-separated. Do not use an automatically observed MAC as an approval without verifying it.
3. **Optional services:** leave switch tracing off for unmanaged home switches. For a supported managed switch, enter its management address, model family, login and transport, then choose the starting switch. Connections between multiple switches must be mapped explicitly by their port names. Enable Kuma only if you already run a separate instance.
4. **Review:** confirm the selected scope and enter your current password. Saved settings apply on the next monitoring cycle without a container restart. Existing incident evidence is retained.

You can return to the wizard from the dashboard to add/edit/remove trusted devices. Passwords and push tokens are not shown back to the browser; blank secret fields keep previously saved secrets. An open incident's IP cannot be removed from coverage until it is resolved.

### Trusted monitoring versus subnet discovery

With discovery off, only your explicitly trusted IPs are checked. With discovery on, trusted checks still run each cycle, plus two additional addresses from the subnet. The sensor's own address, network/broadcast addresses, and trusted IPs are excluded from the discovery queue. The subnet must be on the selected interface and contain no more than 4094 usable addresses.

A single new or unfamiliar MAC in discovery mode is **not** called rogue. Two MACs responding for the same IP create a duplicate-IP incident. An unexpected MAC responding for a trusted IP creates an identity-change incident even if only one reply is observed. Unused/silent discovery addresses do not make monitoring unavailable; a silent trusted target does.

Discovery is not instantaneous. A /24 with about 250 discovery addresses requires roughly 125 cycles. At a 15-second cycle that is about 31 minutes; adding many trusted devices lengthens the cycle. A /21 may take several hours. The dashboard shows checked/total addresses and each observation timestamp. Short-lived conflicts can be missed between visits. Select trusted gateway/server IPs for frequent checks. Once a discovery conflict is detected, up to 64 open discovery incident IPs receive priority checks each cycle; you do not need to wait for another full sweep to confirm their removal.

The subnet is a monitoring scope, **not a DHCP pool**. ARP Watch never assigns IP addresses or changes your router's DHCP settings.

Each target has an IP, name, VLAN, and `approved_macs`. Confirm approved MACs from trusted device configuration before enabling monitoring. Never approve a MAC merely because it answered a probe.

`switches` maps management IPs to `name`, `family`, `transport`, `username`, and `password`. Supported families are `comware`, `procurve`, `cx`, and `officeconnect`. OfficeConnect uses `http`; CLI families use `ssh` or legacy `telnet`. The OfficeConnect adapter logs in, reads the MAC-table page, and logs out; it does not call switch configuration endpoints.

`links` contains directed uplink/downlink mappings with `a`, `a_port`, `b`, and `b_port`. Add both directions when appropriate. Keep this map current: a stale map can stop tracing or misidentify the downstream branch. Aggregate ports without a verified mapping are reported as incomplete, not physical access ports.

## Uptime Kuma and Telegram

Uptime Kuma is a separate, optional application. ARP Watch does not install it or bundle Telegram credentials. Detection, the dashboard, and incident storage work without Kuma.

Create a **Push** monitor. Set its heartbeat interval to 120 seconds, retries to 0, and reminder interval to 15. Enable your existing Telegram notification profile. Enter the secret URL in wizard step 3, or add it to private `config.json`:

```json
{"kuma_push_url":"http://kuma-host:3001/api/push/YOUR_PRIVATE_TOKEN"}
```

ARP Watch sends heartbeats every 60 seconds. A conflict or unavailable monitoring sends DOWN. Healthy monitoring with no unresolved incidents sends UP. Reminders repeat approximately every 15 failed heartbeats. Missing heartbeats also alert. Only push tokens are needed by ARP Watch; Telegram bot credentials remain in Kuma.

Alerts include known approved names and optional explicit `device_labels`. Unknown device names remain unknown. A bounded 10-second wait allows quick tracing to finish before sending; incomplete or pending traces are labelled and subsequent heartbeats contain updated evidence. A final port cannot be guaranteed if the MAC ages out, switch management is unreachable, a device is unsupported, or an unmanaged switch sits downstream.

## Monitoring availability diagnostics

When checks become unavailable, logs and Uptime Kuma messages include the monitored IP addresses without ARP replies, their names and last successful reply when known, probe errors and the target being checked, or stale-result age and threshold. A missing ARP reply means the sensor did not observe a reply; it does not prove a device is offline.

Recovery messages include the outage duration and earlier failure details for 15 minutes after recovery. These summaries reset when the process restarts; persisted logs remain available. Heartbeats still run every 60 seconds, so very short failures can appear in logs or a later heartbeat without causing a separate Kuma status-change notification. Monitoring availability errors are separate from duplicate-IP incidents and do not automatically resolve incidents.

Diagnostics are written to Docker stdout and `data/availability.jsonl`. The private file survives container recreation and rotates at 2 MiB, keeping three rotated files plus the current file. This size-based rotation is independent of incident retention. It does not guarantee 30 days of diagnostic history. Repeated unchanged probe failures are logged at most once every five minutes; changed reasons and recovery are logged immediately when observed.

Kuma delivery errors and subsequent recovery are logged locally. Passwords, configured tokens and HTTP URLs are redacted from error text. No alert can be delivered to Kuma while its connection is unavailable. Telegram notification routing remains in your separate Uptime Kuma installation.

For example, a monitoring-availability alert can report:

```text
ARP Watch monitoring unavailable. Detection cannot be confirmed.
Interface: eth0
192.0.2.10 (Lab server): No ARP reply observed
Last reply: 2026-01-01T12:00:00+00:00
```

After updating, rebuild and recreate the service with `docker compose up -d --build`. Existing configuration and incident data are retained. Back up private configuration and data before upgrading.

## Settings, storage, and backup

Use **Settings** to change the account or retention policy. The current password is required. Credential changes sign out all sessions without stopping monitoring. Account and wizard configuration overrides persist atomically in private `data/settings.json`; they take precedence over the read-only initial `config.json`. This private file can contain switch secrets and the Kuma push token, as well as password hashes. Never publish it.

Incident data is stored in `data/incidents.sqlite3` with SQLite WAL and synchronous FULL. Resolved incidents older than the configured retention and their evidence are permanently removed on settings save and during hourly cleanup. Use 0 to disable expiration. Operational container logs rotate separately at 2 MB x 3.

Back up the database with SQLite's backup API, plus `config.json` and `data/settings.json`. Do not simply copy a live SQLite file while WAL is active. Keep backups private. Restore only with the service stopped and preserve file permissions.

## Security and limitations

The container uses host networking and only the added NET_RAW capability, with a read-only root filesystem and limits of 0.25 CPU, 192 MiB RAM, and 64 processes. Use HTTPS through an authenticated/trusted internal reverse proxy and set `cookie_secure` to true when serving exclusively over HTTPS. Do not expose this management application directly to the Internet. Legacy Telnet and OfficeConnect HTTP transmit credentials without encryption; limit their use to trusted management networks. The SSH adapter currently accepts an unknown host key; validate management endpoints out of band.

The probe implementation and tracer currently support **VLAN 1 on the sensor's local Layer 2 segment**. Other VLANs require local visibility and additional implementation. Trusted monitoring checks selected addresses. Optional subnet discovery covers a bounded configured subnet over time, not instantaneously. Silent devices, very short connections, MAC cloning, and unreachable management can limit detection. It does not block devices or replace DHCP snooping, Dynamic ARP Inspection, or network access control.

The green dashboard wording is **No unresolved conflicts detected**, not a guarantee that the whole network is safe.

## Tests

Use Python 3.12:

```sh
python -m pip install -r requirements.txt
python -m unittest discover -s . -p 'test_*.py'
python test_http.py
```

Tests use temporary storage and loopback HTTP; they send no ARP probes, switch logins, or notifications. Production configurations, incident exports, and credentials are excluded from this repository.

## License

No reuse license has been selected yet.
