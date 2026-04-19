# ESPHome Firewall Component

Device-level inbound TCP filtering for ESP32 devices running ESPHome with ESP-IDF.

ESPHome's security model assumes devices operate on trusted networks protected by perimeter firewalls. This is sound for the majority of deployments. However, some scenarios fall outside that assumption: cellular/4G modems on carrier networks, devices on shared office or retail WiFi, flat IoT VLANs without ACLs. This component is an additive layer for those cases. It does not replace ESPHome's existing security measures -- it extends coverage to deployments where the trusted-network assumption does not hold.

The component uses lwIP's `LWIP_HOOK_IP4_INPUT` to silently drop unsolicited inbound TCP connections (SYN packets) from sources not in a configurable trusted list. Outbound traffic, UDP (DNS, NTP, WireGuard), and traffic from trusted sources are unaffected. When not included in a configuration, there is zero overhead.

## Installation

```yaml
external_components:
  - source: github://vitriltd/esphome-firewall
    components: [firewall]
```

## Quick Start

```yaml
# Block all unsolicited inbound TCP. No exceptions.
firewall:
```

```yaml
# Allow inbound TCP from specific subnets only.
firewall:
  trusted:
    - 10.0.0.0/24        # WireGuard subnet
    - 192.168.1.0/24     # home LAN
  log_dropped: true
```

## Requirements

- ESP32 with `framework: esp-idf` (the lwIP hook mechanism is not available under Arduino)
- ESPHome 2025.2.0 or later

## Documentation

Full configuration reference, traffic behaviour table, WireGuard integration guide, and example configurations: [docs/firewall.md](docs/firewall.md)

## License

MIT
