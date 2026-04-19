#ifdef USE_ESP32

#include "firewall.h"
#include "esphome/core/log.h"
#include "esp_netif.h"
#include "lwip/pbuf.h"
#include "lwip/netif.h"
#include "lwip/ip.h"
#include "lwip/prot/ip4.h"
#include "lwip/prot/ip6.h"
#include "lwip/prot/tcp.h"
#include "lwip/ip4_addr.h"
#include "lwip/ip6_addr.h"
#include "lwip/inet.h"
#include "lwip/tcpip.h"

namespace esphome::firewall {

static const char *const TAG = "firewall";

FirewallComponent *global_firewall = nullptr;  // NOLINT(cppcoreguidelines-avoid-non-const-global-variables)

// Set global pointer in constructor so the hook filters from first packet
FirewallComponent::FirewallComponent() { global_firewall = this; }

void FirewallComponent::setup() {
  ESP_LOGI(TAG, "Firewall active: %zu IPv4 + %zu IPv6 trusted subnet(s), block_icmp=%s, log_dropped=%s",
           static_cast<size_t>(this->trusted_count_), static_cast<size_t>(this->trusted6_count_),
           YESNO(this->block_icmp_), YESNO(this->log_dropped_));
}

void FirewallComponent::dump_config() {
  ESP_LOGCONFIG(TAG, "Firewall:");
  size_t count4 = this->trusted_count_;
  size_t count6 = this->trusted6_count_;
  ESP_LOGCONFIG(TAG, "  Trusted IPv4 subnets: %zu", count4);
  for (size_t i = 0; i < count4; i++) {
    ESP_LOGCONFIG(TAG, "    - " IPSTR "/" IPSTR, IP2STR(&this->trusted_[i].network),
                  IP2STR(&this->trusted_[i].netmask));
  }
  ESP_LOGCONFIG(TAG, "  Trusted IPv6 subnets: %zu", count6);
  for (size_t i = 0; i < count6; i++) {
    // ip6addr_ntoa uses a static buffer — safe here because dump_config
    // runs only on the main thread and never concurrently with the hook's logging.
    ESP_LOGCONFIG(TAG, "    - %s/%u", ip6addr_ntoa(&this->trusted6_[i].network), this->trusted6_[i].prefix_len);
  }
  ESP_LOGCONFIG(TAG, "  Block ICMP: %s", YESNO(this->block_icmp_));
  ESP_LOGCONFIG(TAG, "  Log dropped: %s", YESNO(this->log_dropped_));
#ifdef FIREWALL_RUNTIME_CHANGES
  ESP_LOGCONFIG(TAG, "  Runtime changes: enabled (v4: %zu static/%zu capacity, v6: %zu static/%zu capacity)",
                this->static_count_, this->trusted_.size(), this->static_count6_, this->trusted6_.size());
  if (this->runtime_ttl_ms_ > 0) {
    ESP_LOGCONFIG(TAG, "  Runtime TTL: %us", this->runtime_ttl_ms_ / 1000);
  }
#else
  ESP_LOGCONFIG(TAG, "  Runtime changes: disabled");
#endif
}

// --- IPv4 ---

void FirewallComponent::add_trusted_subnet(const char *network, const char *netmask) {
  size_t count = this->trusted_count_;
  if (count >= this->trusted_.size()) {
    ESP_LOGW(TAG, "IPv4 trusted list full, ignoring %s/%s", network, netmask);
    return;
  }
  auto &entry = this->trusted_[count];
  ip4addr_aton(network, &entry.network);
  ip4addr_aton(netmask, &entry.netmask);
  entry.expires_at_ms = 0;
#ifdef FIREWALL_RUNTIME_CHANGES
  this->trusted_count_.store(count + 1, std::memory_order_release);
#else
  this->trusted_count_ = count + 1;
#endif
}

bool FirewallComponent::is_trusted(const ip4_addr_t *src_addr) {
#ifdef FIREWALL_RUNTIME_CHANGES
  size_t count = this->trusted_count_.load(std::memory_order_acquire);
  uint32_t now = esphome::millis();
#else
  size_t count = this->trusted_count_;
#endif
  for (size_t i = 0; i < count; i++) {
#ifdef FIREWALL_RUNTIME_CHANGES
    // Unsigned subtraction handles millis() wrap-around correctly
    if (this->trusted_[i].expires_at_ms > 0 && (now - this->trusted_[i].expires_at_ms) < 0x80000000UL)
      continue;
#endif
    if (ip4_addr_net_eq(src_addr, &this->trusted_[i].network, &this->trusted_[i].netmask)) {
      return true;
    }
  }
  return false;
}

// --- IPv6 ---

void FirewallComponent::add_trusted_subnet6(const char *network, uint8_t prefix_len) {
#ifdef FIREWALL_RUNTIME_CHANGES
  size_t count = this->trusted6_count_.load(std::memory_order_relaxed);
#else
  size_t count = this->trusted6_count_;
#endif
  if (count >= this->trusted6_.size()) {
    ESP_LOGW(TAG, "IPv6 trusted list full, ignoring %s/%u", network, prefix_len);
    return;
  }
  auto &entry = this->trusted6_[count];
  ip6addr_aton(network, &entry.network);
  entry.prefix_len = prefix_len;
  entry.expires_at_ms = 0;
#ifdef FIREWALL_RUNTIME_CHANGES
  this->trusted6_count_.store(count + 1, std::memory_order_release);
#else
  this->trusted6_count_ = count + 1;
#endif
}

bool FirewallComponent::match_ip6_prefix(const ip6_addr_t *addr, const ip6_addr_t *network, uint8_t prefix_len) {
  uint8_t full_words = prefix_len / 32;
  uint8_t remaining = prefix_len % 32;
  for (uint8_t i = 0; i < full_words && i < 4; i++) {
    if (addr->addr[i] != network->addr[i])
      return false;
  }
  if (remaining > 0 && full_words < 4) {
    uint32_t mask = htonl(0xFFFFFFFF << (32 - remaining));
    if ((addr->addr[full_words] & mask) != (network->addr[full_words] & mask))
      return false;
  }
  return true;
}

bool FirewallComponent::is_trusted6(const ip6_addr_t *src_addr) {
#ifdef FIREWALL_RUNTIME_CHANGES
  size_t count = this->trusted6_count_.load(std::memory_order_acquire);
  uint32_t now = esphome::millis();
#else
  size_t count = this->trusted6_count_;
#endif
  for (size_t i = 0; i < count; i++) {
#ifdef FIREWALL_RUNTIME_CHANGES
    if (this->trusted6_[i].expires_at_ms > 0 && (now - this->trusted6_[i].expires_at_ms) < 0x80000000UL)
      continue;
#endif
    if (match_ip6_prefix(src_addr, &this->trusted6_[i].network, this->trusted6_[i].prefix_len)) {
      return true;
    }
  }
  return false;
}

// --- Runtime changes ---

#ifdef FIREWALL_RUNTIME_CHANGES
bool FirewallComponent::add_runtime_subnet(const char *network, const char *netmask) {
  size_t count = this->trusted_count_.load(std::memory_order_relaxed);
  if (count >= this->trusted_.size()) {
    ESP_LOGW(TAG, "IPv4 trusted list full (%zu/%zu)", count, this->trusted_.size());
    return false;
  }
  auto &entry = this->trusted_[count];
  ip4addr_aton(network, &entry.network);
  ip4addr_aton(netmask, &entry.netmask);
  entry.expires_at_ms = (this->runtime_ttl_ms_ > 0) ? esphome::millis() + this->runtime_ttl_ms_ : 0;
  this->trusted_count_.store(count + 1, std::memory_order_release);
  if (entry.expires_at_ms > 0) {
    ESP_LOGI(TAG, "Runtime IPv4 subnet added: %s/%s (expires in %us)", network, netmask,
             this->runtime_ttl_ms_ / 1000);
  } else {
    ESP_LOGI(TAG, "Runtime IPv4 subnet added: %s/%s (no expiry)", network, netmask);
  }
  return true;
}

bool FirewallComponent::add_runtime_subnet6(const char *network, uint8_t prefix_len) {
  size_t count = this->trusted6_count_.load(std::memory_order_relaxed);
  if (count >= this->trusted6_.size()) {
    ESP_LOGW(TAG, "IPv6 trusted list full (%zu/%zu)", count, this->trusted6_.size());
    return false;
  }
  auto &entry = this->trusted6_[count];
  ip6addr_aton(network, &entry.network);
  entry.prefix_len = prefix_len;
  entry.expires_at_ms = (this->runtime_ttl_ms_ > 0) ? esphome::millis() + this->runtime_ttl_ms_ : 0;
  this->trusted6_count_.store(count + 1, std::memory_order_release);
  if (entry.expires_at_ms > 0) {
    ESP_LOGI(TAG, "Runtime IPv6 subnet added: %s/%u (expires in %us)", network, prefix_len,
             this->runtime_ttl_ms_ / 1000);
  } else {
    ESP_LOGI(TAG, "Runtime IPv6 subnet added: %s/%u (no expiry)", network, prefix_len);
  }
  return true;
}

void FirewallComponent::reset_runtime() {
  size_t old4 = this->trusted_count_.load(std::memory_order_relaxed);
  size_t old6 = this->trusted6_count_.load(std::memory_order_relaxed);
  this->trusted_count_.store(this->static_count_, std::memory_order_release);
  this->trusted6_count_.store(this->static_count6_, std::memory_order_release);
  ESP_LOGI(TAG, "Runtime subnets cleared (v4: %zu -> %zu, v6: %zu -> %zu)", old4, this->static_count_, old6,
           this->static_count6_);
}

void FirewallComponent::loop() {
  static uint32_t last_check_ms = 0;
  uint32_t now = esphome::millis();
  if (now - last_check_ms < 1000)
    return;
  last_check_ms = now;

  // Compact expired entries under the lwIP tcpip core lock to prevent
  // the hook from reading a partially-moved struct. The lock is held for
  // microseconds (just array element swaps). This is the same lock lwIP itself
  // uses for thread-safe netif/pcb access.
  LOCK_TCPIP_CORE();

  // Compact expired IPv4 entries
  size_t count4 = this->trusted_count_.load(std::memory_order_relaxed);
  bool any_expired = false;
  for (size_t i = this->static_count_; i < count4; i++) {
    if (this->trusted_[i].expires_at_ms > 0 && (now - this->trusted_[i].expires_at_ms) < 0x80000000UL) {
      ESP_LOGI(TAG, "IPv4 subnet expired: " IPSTR "/" IPSTR, IP2STR(&this->trusted_[i].network),
               IP2STR(&this->trusted_[i].netmask));
      if (i < count4 - 1)
        this->trusted_[i] = this->trusted_[count4 - 1];
      count4--;
      i--;
      any_expired = true;
    }
  }
  if (any_expired)
    this->trusted_count_.store(count4, std::memory_order_release);

  // Compact expired IPv6 entries
  size_t count6 = this->trusted6_count_.load(std::memory_order_relaxed);
  any_expired = false;
  for (size_t i = this->static_count6_; i < count6; i++) {
    if (this->trusted6_[i].expires_at_ms > 0 && (now - this->trusted6_[i].expires_at_ms) < 0x80000000UL) {
      ESP_LOGI(TAG, "IPv6 subnet expired: %s/%u", ip6addr_ntoa(&this->trusted6_[i].network),
               this->trusted6_[i].prefix_len);
      if (i < count6 - 1)
        this->trusted6_[i] = this->trusted6_[count6 - 1];
      count6--;
      i--;
      any_expired = true;
    }
  }
  if (any_expired)
    this->trusted6_count_.store(count6, std::memory_order_release);

  UNLOCK_TCPIP_CORE();
}
#endif

}  // namespace esphome::firewall

// --- Rate-limited drop logging ---
// These statics are only accessed from the lwIP tcpip thread (hook context).
// No thread-safety issue — both hooks run on the same lwIP thread, never concurrently.

static uint32_t fw_drop_count = 0;
static uint32_t fw_last_log_ms = 0;

static bool fw_should_log() {
  fw_drop_count++;
  uint32_t now = esphome::millis();
  if (now - fw_last_log_ms >= 5000) {
    fw_last_log_ms = now;
    return true;
  }
  return false;
}

static uint32_t fw_get_and_reset_count() {
  uint32_t c = fw_drop_count;
  fw_drop_count = 0;
  return c;
}

// --- IPv4 hook ---

extern "C" int firewall_hook_ip4_input(struct pbuf *pbuf, struct netif *input_netif) {
  auto *fw = esphome::firewall::global_firewall;
  if (fw == nullptr)
    return 0;

  auto *iphdr = static_cast<struct ip_hdr *>(pbuf->payload);
  uint8_t proto = IPH_PROTO(iphdr);
  ip4_addr_t src;
  ip4_addr_copy(src, iphdr->src);

  if (proto == IP_PROTO_ICMP && fw->get_block_icmp() && !fw->is_trusted(&src)) {
    if (fw->get_log_dropped() && fw_should_log()) {
      ESP_LOGD("firewall", "DROP ICMPv4 from " IPSTR " (%u drops in last 5s)", IP2STR(&src),
               fw_get_and_reset_count());
    }
    pbuf_free(pbuf);
    return 1;
  }

  if (proto != IP_PROTO_TCP)
    return 0;

  uint16_t iphdr_len = IPH_HL_BYTES(iphdr);
  if (pbuf->len < iphdr_len + sizeof(struct tcp_hdr)) {
    pbuf_free(pbuf);
    return 1;
  }
  auto *tcphdr = reinterpret_cast<struct tcp_hdr *>(static_cast<uint8_t *>(pbuf->payload) + iphdr_len);
  uint8_t flags = TCPH_FLAGS(tcphdr);

  if ((flags & (TCP_SYN | TCP_ACK)) != TCP_SYN)
    return 0;

  if (fw->is_trusted(&src))
    return 0;

  if (fw->get_log_dropped() && fw_should_log()) {
    ESP_LOGD("firewall", "DROP TCP SYN from " IPSTR " to port %u (%u drops in last 5s)", IP2STR(&src),
             lwip_ntohs(tcphdr->dest), fw_get_and_reset_count());
  }
  pbuf_free(pbuf);
  return 1;
}

// --- IPv6 hook ---

extern "C" int lwip_hook_ip6_input(struct pbuf *pbuf, struct netif *input_netif) {
  auto *fw = esphome::firewall::global_firewall;
  if (fw == nullptr)
    return 0;

  auto *ip6hdr = static_cast<struct ip6_hdr *>(pbuf->payload);
  uint8_t nexth = IP6H_NEXTH(ip6hdr);
  ip6_addr_t src;
  ip6_addr_copy_from_packed(src, ip6hdr->src);

  // ICMPv6 filtering — MUST allow NDP (types 133-137) or IPv6 networking breaks.
  if (nexth == IP6_NEXTH_ICMP6 && fw->get_block_icmp() && !fw->is_trusted6(&src)) {
    uint16_t ip6hdr_len = IP6_HLEN;
    if (pbuf->len >= ip6hdr_len + 1) {
      uint8_t icmp6_type = *(static_cast<uint8_t *>(pbuf->payload) + ip6hdr_len);
      // NDP types 133-137 must always pass. Block only echo request/reply (128/129).
      if (icmp6_type == 128 || icmp6_type == 129) {
        if (fw->get_log_dropped() && fw_should_log()) {
          // ip6addr_ntoa is safe here — both v4 and v6 hooks run on the
          // same lwIP tcpip thread, never concurrently with dump_config (main thread).
          ESP_LOGD("firewall", "DROP ICMPv6 echo from %s (%u drops in last 5s)", ip6addr_ntoa(&src),
                   fw_get_and_reset_count());
        }
        pbuf_free(pbuf);
        return 1;
      }
    }
    return 0;  // NDP and other ICMPv6 — always allow
  }

  if (nexth != IP6_NEXTH_TCP)
    return 0;

  uint16_t ip6hdr_len = IP6_HLEN;
  if (pbuf->len < ip6hdr_len + sizeof(struct tcp_hdr)) {
    pbuf_free(pbuf);
    return 1;
  }
  auto *tcphdr = reinterpret_cast<struct tcp_hdr *>(static_cast<uint8_t *>(pbuf->payload) + ip6hdr_len);
  uint8_t flags = TCPH_FLAGS(tcphdr);

  if ((flags & (TCP_SYN | TCP_ACK)) != TCP_SYN)
    return 0;

  if (fw->is_trusted6(&src))
    return 0;

  if (fw->get_log_dropped() && fw_should_log()) {
    ESP_LOGD("firewall", "DROP TCP6 SYN from %s to port %u (%u drops in last 5s)", ip6addr_ntoa(&src),
             lwip_ntohs(tcphdr->dest), fw_get_and_reset_count());
  }
  pbuf_free(pbuf);
  return 1;
}

#endif
