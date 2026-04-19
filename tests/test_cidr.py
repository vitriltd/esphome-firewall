"""Unit tests for CIDR validation and subnet separation logic."""
import ipaddress

import pytest


def _validate_cidr(value):
    """Mirror of components/firewall/__init__.py validator."""
    try:
        ipaddress.ip_network(value, strict=False)
    except ValueError as err:
        raise ValueError(f"Invalid CIDR subnet: {err}")
    return value


class TestCIDRValidation:
    def test_valid_v4_subnet(self):
        assert _validate_cidr("10.0.0.0/24") == "10.0.0.0/24"

    def test_valid_v4_host(self):
        assert _validate_cidr("192.168.1.100/32") == "192.168.1.100/32"

    def test_valid_v4_host_bits_set(self):
        # strict=False allows host bits — should not raise
        assert _validate_cidr("192.168.1.100/24") == "192.168.1.100/24"

    def test_valid_v6_subnet(self):
        assert _validate_cidr("fd00::/48") == "fd00::/48"

    def test_valid_v6_large_prefix(self):
        assert _validate_cidr("2001:db8::/32") == "2001:db8::/32"

    def test_valid_v6_host(self):
        assert _validate_cidr("2001:db8::1/128") == "2001:db8::1/128"

    def test_invalid_string(self):
        with pytest.raises(ValueError):
            _validate_cidr("not-an-ip")

    def test_invalid_v4_prefix_too_large(self):
        with pytest.raises(ValueError):
            _validate_cidr("10.0.0.0/33")

    def test_invalid_v6_prefix_too_large(self):
        with pytest.raises(ValueError):
            _validate_cidr("fd00::/129")

    def test_empty_string(self):
        with pytest.raises(ValueError):
            _validate_cidr("")


class TestSubnetSeparation:
    """Test that v4 and v6 subnets are correctly separated and collapsed."""

    @staticmethod
    def _separate_and_collapse(cidrs):
        all_nets = [ipaddress.ip_network(ip, strict=False) for ip in cidrs]
        v4 = list(
            ipaddress.collapse_addresses(
                [n for n in all_nets if isinstance(n, ipaddress.IPv4Network)]
            )
        )
        v6 = list(
            ipaddress.collapse_addresses(
                [n for n in all_nets if isinstance(n, ipaddress.IPv6Network)]
            )
        )
        return v4, v6

    def test_mixed_v4_v6(self):
        v4, v6 = self._separate_and_collapse(
            ["10.0.0.0/24", "fd00::/48", "192.168.1.0/24"]
        )
        assert len(v4) == 2
        assert len(v6) == 1

    def test_adjacent_v4_collapsed(self):
        v4, v6 = self._separate_and_collapse(["10.0.0.0/24", "10.0.1.0/24"])
        assert len(v4) == 1
        assert str(v4[0]) == "10.0.0.0/23"
        assert len(v6) == 0

    def test_adjacent_v6_collapsed(self):
        v4, v6 = self._separate_and_collapse(["fd00::/49", "fd00:0:0:8000::/49"])
        assert len(v6) == 1
        assert str(v6[0]) == "fd00::/48"
        assert len(v4) == 0

    def test_v4_only(self):
        v4, v6 = self._separate_and_collapse(["10.0.0.0/8"])
        assert len(v4) == 1
        assert len(v6) == 0

    def test_v6_only(self):
        v4, v6 = self._separate_and_collapse(["2001:db8::/32"])
        assert len(v4) == 0
        assert len(v6) == 1

    def test_empty(self):
        v4, v6 = self._separate_and_collapse([])
        assert len(v4) == 0
        assert len(v6) == 0
