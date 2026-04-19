# Firewall Component

The firewall component provides device-level inbound TCP filtering for ESP32 devices. It silently drops unsolicited inbound TCP connections from sources not in a configurable trusted list, while leaving all outbound traffic and UDP completely unaffected.

## When you need this

ESPHome's default security model assumes devices operate on trusted networks (home WiFi, VLANs) protected by perimeter firewalls and network segmentation. This is a sound assumption for the vast majority of deployments, and ESPHome provides application-level protections (`api: encryption`, `web_server: auth`) that work well in that context.

However, some deployment scenarios fall outside the trusted-network assumption:

- **Cellular / 4G modems** on carrier networks where other CGNAT pool users can reach your device (see the [modem component PR](https://github.com/esphome/esphome/pull/6721) for PPP/cellular support)
- **Shared office or retail WiFi** where you don't control the network
- **Flat IoT VLANs** without per-device ACLs
- **Any network** where you want defense-in-depth beyond perimeter controls

This component is an **additive layer** for those cases. It does not replace or conflict with ESPHome's existing security measures. If you're on a well-segmented home network with a proper firewall, you don't need this component.

## Basic Configuration

```yaml
# Minimal -- block all unsolicited inbound TCP
firewall:
```

```yaml
# With trusted sources
firewall:
  trusted:
    - 10.0.0.0/24        # WireGuard subnet (v4)
    - 192.168.1.0/24     # home LAN (v4)
    - fd00:abcd::/48     # WireGuard subnet (v6)
    - 2001:db8::/32      # trusted v6 prefix
  log_dropped: true
```

## Configuration Variables

- **trusted** (*Optional*, list of CIDR strings): IP subnets allowed to make inbound TCP connections. Supports both IPv4 and IPv6 in the same list, specified in CIDR notation (e.g. `10.0.0.0/24`, `192.168.1.100/32`, `fd00::/48`, `2001:db8:1234::/48`). If omitted or empty, all unsolicited inbound TCP is blocked with no exceptions.

- **block_icmp** (*Optional*, boolean): Also block inbound ICMP/ICMPv6 echo (ping) from untrusted sources. Defaults to `false`. Useful for hiding the device from ping sweeps, but makes network debugging harder. IPv6 Neighbour Discovery (NDP, ICMPv6 types 133--137) is always allowed regardless of this setting, as blocking it would break IPv6 networking.

- **log_dropped** (*Optional*, boolean): Log dropped packets at DEBUG level. Defaults to `false`. Logs are rate-limited to one entry per 5 seconds with a count of drops in the interval, so port scans don't flood the log buffer.

- **allow_runtime_changes** (*Optional*, boolean): Enable runtime modification of the trusted list via ESPHome actions. Defaults to `false`. When disabled, the trusted list is fixed at compile time and cannot be changed without reflashing. See [Runtime Changes](#runtime-changes).

- **runtime_slots** (*Optional*, integer, 1--32): Number of extra pre-allocated slots for runtime trusted-subnet additions. Only used when `allow_runtime_changes` is `true`. Defaults to `8`. No heap allocation occurs -- slots are pre-allocated at compile time.

- **runtime_ttl** (*Optional*, time period): How long runtime-added trusted subnets remain active before auto-expiring. Only used when `allow_runtime_changes` is `true`. Defaults to `0s` (no expiry). Example: `30min` means runtime entries are automatically removed after 30 minutes. Compile-time `trusted:` entries never expire regardless of this setting.

## How It Works

The component registers two lwIP input hooks:
- **IPv4**: `LWIP_HOOK_IP4_INPUT` — called for every inbound IPv4 packet
- **IPv6**: `LWIP_HOOK_IP6_INPUT` (via `CONFIG_LWIP_HOOK_IP6_INPUT_CUSTOM`) — called for every inbound IPv6 packet

Both hooks apply the same rule:

**Block TCP SYN packets (without ACK) from sources not in the trusted list.**

This blocks new unsolicited inbound connections while allowing:

| Traffic | Result |
|---|---|
| Outbound TCP (MQTT, HTTP requests) | Allowed (SYN goes out, SYN+ACK comes back with ACK set) |
| Inbound TCP from trusted source (v4 or v6) | Allowed |
| Inbound TCP SYN from untrusted source | **Dropped** |
| All UDP (DNS, NTP, WireGuard tunnel) | Allowed |
| ICMPv4 ping | Allowed (unless `block_icmp: true`) |
| ICMPv6 echo (ping6) | Allowed (unless `block_icmp: true`) |
| ICMPv6 NDP (types 133--137) | **Always allowed** (required for IPv6 networking) |
| Established TCP (responses to your connections) | Allowed (ACK flag set) |

## WireGuard Integration

WireGuard traffic arrives on the PPP/WiFi/Ethernet interface as **encrypted UDP** -- which the firewall allows through. The WireGuard component decrypts it and presents the inner packets on a separate WireGuard network interface.

This means services accessed through a WireGuard tunnel **bypass the firewall entirely** because the decrypted packets never arrive on the filtered interface. The firewall only sees the outer UDP envelope, which it passes.

To allow management access only via WireGuard:

```yaml
wireguard:
  address: 10.0.0.2
  # ... peer config ...

firewall:
  trusted:
    - 10.0.0.0/24     # WireGuard subnet -- allows tunneled connections
  log_dropped: true

web_server:
  port: 80            # accessible via WG at 10.0.0.2:80, blocked from LAN/cellular
```

**Result:**
- `curl http://10.0.0.2/` from a WG peer: loads the web panel
- `curl http://<lan-ip>/` from the local network: connection timeout (SYN dropped)
- MQTT, DNS, NTP: work normally (outbound TCP / UDP)

## Runtime Changes

When `allow_runtime_changes: true`, two actions become available:

### `firewall.allow` Action

Adds a subnet to the trusted list at runtime. The entry is ephemeral -- lost on reboot.

```yaml
firewall:
  trusted:
    - 10.0.0.0/24
  allow_runtime_changes: true
  runtime_slots: 8
  runtime_ttl: 30min    # auto-expire after 30 minutes

# Example: grant temporary access from a button press
binary_sensor:
  - platform: gpio
    pin: GPIO5
    on_press:
      - firewall.allow:
          ip: 192.168.1.100/32
```

### `firewall.reset_runtime` Action

Removes all runtime-added entries. Compile-time `trusted:` entries are unaffected.

```yaml
button:
  - platform: template
    name: Reset Firewall
    on_press:
      - firewall.reset_runtime
```

### TTL Expiry

When `runtime_ttl` is set to a non-zero value, runtime entries automatically expire after the specified duration. Expired entries are cleaned up once per second in the main loop. Expiry is logged:

```
[I][firewall]: Runtime subnet expired: 192.168.1.100/255.255.255.255
```

Compile-time `trusted:` entries have `runtime_ttl` has no effect on them -- they are permanent.

### Security Note

The `firewall.allow` action is triggered via ESPHome automations (buttons, MQTT `on_message`, lambdas). Ensure the trigger mechanism is itself secured. Exposing `firewall.allow` via an unauthenticated MQTT topic would defeat the purpose of the firewall.

## Limitations

- **ESP-IDF only.** The lwIP hook mechanism (`LWIP_HOOK_IP4_INPUT`) is not available under the Arduino framework. The component validates this at config time with `cv.only_with_esp_idf`.

- **Dual-stack.** Both IPv4 and IPv6 are filtered. IPv6 Neighbour Discovery (NDP) is always allowed to avoid breaking IPv6 connectivity.

- **No per-port rules.** The filter operates on source IP only. You cannot allow port 80 from one subnet and port 6053 from another. This is intentional -- per-port ACLs add complexity inappropriate for embedded devices.

- **No UDP filtering.** All inbound UDP is allowed. See [Why no UDP filtering](#why-no-udp-filtering) below.

- **Not stateful.** There is no connection tracking (like iptables conntrack). The filter uses TCP flags as a proxy: SYN without ACK = new connection. A sophisticated attacker could craft non-SYN packets, but they cannot establish a real TCP connection without the three-way handshake.

- **Single hook owner.** `LWIP_HOOK_IP4_INPUT` can only be defined once per build. If another component also defines this hook, the build will fail. No current ESPHome component uses it.

- **Implicit function declaration warning.** The component suppresses `-Wno-error=implicit-function-declaration` because lwIP's `ip4.c` (compiled in ESP-IDF's own build context) cannot see the hook function's prototype. The function links correctly. This matches the pattern used by other ESPHome components that suppress IDF-level warnings (e.g. `esp32` core uses `-Wno-error=format`).

## Why No UDP Filtering

TCP filtering works cleanly because TCP has a handshake: SYN without ACK unambiguously identifies a new, unsolicited connection. UDP has no equivalent signal -- every inbound UDP packet looks identical regardless of whether it's a wanted response or an unwanted probe.

A standard ESPHome device has very few open UDP ports:

| Port | Service | Always open? |
|---|---|---|
| 5353 | mDNS (device discovery) | Yes, by default |
| 68 | DHCP (IP acquisition) | Briefly at boot |
| Ephemeral | DNS client responses | Milliseconds per query |

DNS responses arrive on ephemeral source ports (not port 53), DHCP is essential for boot, and mDNS is intentionally public. Additional UDP ports only open when you explicitly add components like `wireguard:` (port 51820) or `udp:` transport (port 18511).

Filtering UDP would require either a static port allowlist (fragile, breaks when ports change) or stateful connection tracking (complex, memory-intensive, inappropriate for a device with 320KB RAM). Neither approach provides proportional security benefit given that ESPHome's real attack surface is TCP services (`web_server:`, `api:`), which this firewall already covers.

## Hardening: Disable mDNS on Untrusted Networks

mDNS is built on the assumption that the local network is trusted. It broadcasts the device's hostname, IP address, and advertised services (e.g. `_http._tcp port 80`) to all devices on the network. On a home LAN, this enables convenient discovery by Home Assistant. On a cellular carrier network or shared WiFi, it unnecessarily discloses the device's presence and services.

The correct control is to disable mDNS entirely rather than filtering it at the packet level -- stopping the service is cleaner than filtering traffic to a running service:

```yaml
mdns:
  disabled: true
```

This prevents the mDNS responder from binding to UDP port 5353 and stops all service advertisements. The device remains fully functional -- MQTT, WireGuard, and all outbound connections continue to work. Only mDNS-based discovery (e.g. `hostname.local` resolution) is lost, which is typically not needed on untrusted networks where you access the device via WireGuard tunnel IP anyway.

## Hardening: Encrypt Packet Transport

If using ESPHome's [UDP Packet Transport](https://esphome.io/components/packet_transport/udp) component on an untrusted network, enable encryption and rolling code. Without encryption, sensor data broadcasts are sent in cleartext and can be read or spoofed by any device on the network. Encryption is configured at the `packet_transport:` level (not `udp:`):

```yaml
packet_transport:
  - platform: udp
    encryption: !secret udp_key
    rolling_code_enable: true
```

The component uses XXTEA encryption with an optional monotonic rolling code for replay protection. While not modern authenticated encryption (no AEAD, no forward secrecy), it is appropriate for the threat model of broadcasting sensor values between ESPHome devices and is dramatically better than cleartext on a shared network.

## Example Configurations

### Cellular device with WireGuard management

```yaml
modem:
  model: SIM7600
  tx_pin: GPIO10
  rx_pin: GPIO9
  apn: my.carrier.apn

wireguard:
  address: 10.0.0.2
  private_key: !secret wg_private_key
  peer_endpoint: vpn.example.com
  peer_public_key: !secret wg_peer_key
  peer_preshared_key: !secret wg_psk
  peer_persistent_keepalive: 25s

firewall:
  trusted:
    - 10.0.0.0/24
  log_dropped: true

web_server:
  port: 80

mqtt:
  broker: broker.example.com
```

### Semi-trusted LAN with WireGuard-only management

```yaml
wifi:
  ssid: !secret wifi_ssid
  password: !secret wifi_password

wireguard:
  address: 10.0.0.2
  private_key: !secret wg_private_key
  peer_endpoint: vpn.example.com
  peer_public_key: !secret wg_peer_key

firewall:
  trusted:
    - 10.0.0.0/24       # management only via WG

web_server:
  port: 80

api:
  encryption:
    key: !secret api_key
```

### Minimal -- block everything inbound

```yaml
wifi:
  ssid: !secret wifi_ssid
  password: !secret wifi_password

firewall:

mqtt:
  broker: broker.example.com
```

No `trusted:` list, no `web_server:`, no `api:`. The device publishes via MQTT (outbound) and accepts no inbound connections at all.

## See Also

- [Modem Component PR #6721](https://github.com/esphome/esphome/pull/6721) -- PPP/cellular connectivity (the primary motivation for this component)
- [WireGuard Component](https://esphome.io/components/wireguard)
- [Network Component](https://esphome.io/components/network)
- [Web Server Component](https://esphome.io/components/web_server)
- [Native API Component](https://esphome.io/components/api)
- [ESPHome Security Best Practices](https://esphome.io/guides/security_best_practices/)
