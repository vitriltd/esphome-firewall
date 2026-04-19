#pragma once
#ifdef USE_ESP32

#include "esphome/core/component.h"
#include "esphome/core/defines.h"
#include <array>
#include "lwip/ip4_addr.h"
#include "lwip/ip6_addr.h"

#ifdef FIREWALL_RUNTIME_CHANGES
#include <atomic>
#endif

namespace esphome::firewall {

struct TrustedSubnet {
  ip4_addr_t network;
  ip4_addr_t netmask;
  uint32_t expires_at_ms;  // 0 = permanent (compile-time entry)
};

struct TrustedSubnet6 {
  ip6_addr_t network;
  uint8_t prefix_len;       // 0-128
  uint32_t expires_at_ms;   // 0 = permanent
};

class FirewallComponent : public Component {
 public:
  // Set global pointer in constructor so filtering is active before setup()
  FirewallComponent();

  void setup() override;
  void dump_config() override;
  float get_setup_priority() const override { return setup_priority::AFTER_WIFI; }

  void add_trusted_subnet(const char *network, const char *netmask);
  void add_trusted_subnet6(const char *network, uint8_t prefix_len);
  void set_block_icmp(bool block) { this->block_icmp_ = block; }
  void set_log_dropped(bool log) { this->log_dropped_ = log; }

  bool get_block_icmp() const { return this->block_icmp_; }
  bool get_log_dropped() const { return this->log_dropped_; }

#ifdef FIREWALL_RUNTIME_CHANGES
  void set_static_count(size_t count) { this->static_count_ = count; }
  void set_static_count6(size_t count) { this->static_count6_ = count; }
  void set_runtime_ttl(uint32_t ttl_ms) { this->runtime_ttl_ms_ = ttl_ms; }
  bool add_runtime_subnet(const char *network, const char *netmask);
  bool add_runtime_subnet6(const char *network, uint8_t prefix_len);
  void reset_runtime();
  void loop() override;
#endif

  bool is_trusted(const ip4_addr_t *src_addr);
  bool is_trusted6(const ip6_addr_t *src_addr);

 protected:
  static bool match_ip6_prefix(const ip6_addr_t *addr, const ip6_addr_t *network, uint8_t prefix_len);

  bool block_icmp_{false};
  bool log_dropped_{false};

  std::array<TrustedSubnet, FIREWALL_MAX_TRUSTED> trusted_{};
  std::array<TrustedSubnet6, FIREWALL_MAX_TRUSTED6> trusted6_{};
#ifdef FIREWALL_RUNTIME_CHANGES
  std::atomic<size_t> trusted_count_{0};
  std::atomic<size_t> trusted6_count_{0};
  size_t static_count_{0};
  size_t static_count6_{0};
  uint32_t runtime_ttl_ms_{0};
#else
  size_t trusted_count_{0};
  size_t trusted6_count_{0};
#endif
};

extern FirewallComponent *global_firewall;  // NOLINT(cppcoreguidelines-avoid-non-const-global-variables)

}  // namespace esphome::firewall

// IPv4 hook — declared here because lwIP has no Kconfig for it.
extern "C" int firewall_hook_ip4_input(struct pbuf *pbuf, struct netif *input_netif);

// IPv6 hook — declared by lwip_default_hooks.h when CONFIG_LWIP_HOOK_IP6_INPUT_CUSTOM is set.
// We just provide the implementation in firewall.cpp.

#endif
