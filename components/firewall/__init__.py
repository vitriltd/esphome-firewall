import ipaddress

import esphome.codegen as cg
import esphome.config_validation as cv
from esphome.components.esp32 import add_idf_sdkconfig_option
from esphome.const import CONF_ID

CODEOWNERS = ["@fibble"]
DEPENDENCIES = ["esp32", "network"]

CONF_TRUSTED = "trusted"
CONF_BLOCK_ICMP = "block_icmp"
CONF_LOG_DROPPED = "log_dropped"
CONF_ALLOW_RUNTIME = "allow_runtime_changes"
CONF_RUNTIME_SLOTS = "runtime_slots"
CONF_RUNTIME_TTL = "runtime_ttl"

firewall_ns = cg.esphome_ns.namespace("firewall")
FirewallComponent = firewall_ns.class_("FirewallComponent", cg.Component)


def _validate_cidr(value):
    try:
        ipaddress.ip_network(value, strict=False)
    except ValueError as err:
        raise cv.Invalid(f"Invalid CIDR subnet: {err}")
    return value


CONFIG_SCHEMA = cv.All(
    cv.Schema(
        {
            cv.GenerateID(): cv.declare_id(FirewallComponent),
            cv.Optional(CONF_TRUSTED, default=[]): cv.ensure_list(_validate_cidr),
            cv.Optional(CONF_BLOCK_ICMP, default=False): cv.boolean,
            cv.Optional(CONF_LOG_DROPPED, default=False): cv.boolean,
            cv.Optional(CONF_ALLOW_RUNTIME, default=False): cv.boolean,
            cv.Optional(CONF_RUNTIME_SLOTS, default=8): cv.int_range(min=1, max=32),
            cv.Optional(
                CONF_RUNTIME_TTL, default="0s"
            ): cv.positive_time_period_milliseconds,
        }
    ).extend(cv.COMPONENT_SCHEMA),
    # cv.only_with_esp_idf deprecated in 2026.1 — use cv.only_on_esp32
    # since the lwIP hook mechanism requires ESP-IDF (not available under Arduino).
    cv.only_on_esp32,
)


async def to_code(config):
    var = cg.new_Pvariable(config[CONF_ID])
    await cg.register_component(var, config)

    # IPv4 hook — no Kconfig option exists in ESP-IDF for LWIP_HOOK_IP4_INPUT,
    # so we define the macro directly. lwIP's ip4.c (compiled as C in IDF's own
    # CMake context) cannot see our C++ header, producing an implicit-function-
    # declaration warning. The function IS provided and links correctly; we
    # demote the warning to avoid -Werror failures. This matches the pattern
    # used by esp32 core (-Wno-error=format) and heatpumpir (-Wno-error=
    # overloaded-virtual). The flag is global but only affects TUs that
    # reference the undefined symbol — no other code triggers this warning.
    cg.add_build_flag("-DLWIP_HOOK_IP4_INPUT=firewall_hook_ip4_input")
    cg.add_build_flag("-Wno-error=implicit-function-declaration")

    # IPv6 — proper Kconfig support. lwip_default_hooks.h declares
    # lwip_hook_ip6_input() when CUSTOM is set. No warning suppression needed.
    add_idf_sdkconfig_option("CONFIG_LWIP_IPV6", True)
    add_idf_sdkconfig_option("CONFIG_LWIP_HOOK_IP6_INPUT_CUSTOM", True)

    # Parse and separate v4 vs v6 subnets, collapse each independently
    all_nets = [ipaddress.ip_network(ip, strict=False) for ip in config[CONF_TRUSTED]]
    trusted_v4 = list(
        ipaddress.collapse_addresses(
            [n for n in all_nets if isinstance(n, ipaddress.IPv4Network)]
        )
    )
    trusted_v6 = list(
        ipaddress.collapse_addresses(
            [n for n in all_nets if isinstance(n, ipaddress.IPv6Network)]
        )
    )

    for subnet in trusted_v4:
        cg.add(
            var.add_trusted_subnet(
                str(subnet.network_address),
                str(subnet.netmask),
            )
        )

    for subnet in trusted_v6:
        cg.add(
            var.add_trusted_subnet6(
                str(subnet.network_address),
                int(subnet.prefixlen),
            )
        )

    cg.add(var.set_block_icmp(config[CONF_BLOCK_ICMP]))
    cg.add(var.set_log_dropped(config[CONF_LOG_DROPPED]))

    allow_runtime = config[CONF_ALLOW_RUNTIME]
    extra_slots = config[CONF_RUNTIME_SLOTS] if allow_runtime else 0
    v4_capacity = max(len(trusted_v4) + extra_slots, 1)
    v6_capacity = max(len(trusted_v6) + extra_slots, 1)

    cg.add_define("FIREWALL_MAX_TRUSTED", v4_capacity)
    cg.add_define("FIREWALL_MAX_TRUSTED6", v6_capacity)

    if allow_runtime:
        cg.add_define("FIREWALL_RUNTIME_CHANGES")
        cg.add(var.set_static_count(len(trusted_v4)))
        cg.add(var.set_static_count6(len(trusted_v6)))
        cg.add(var.set_runtime_ttl(config[CONF_RUNTIME_TTL]))
