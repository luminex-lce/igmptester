"""Configuration test
This test suite validates that the test configuration is valid.
"""
import pytest
from ipaddress import IPv4Address
from lib.utils import check_interface_up
from configuration import IFACE, MGROUP_1, MGROUP_2, SKIP_MANUAL  # noqa: F401


def test_interface():
    """This test validates that the network interface to use is configured correctly
    It also verifies that the network interface exists and is up.
    """

    assert IFACE, "Make sure to configure a valid network interface under the `IFACE` variable in configuration.py"

    print(f"Detect link up on interface {IFACE}")
    check_interface_up()


def validate_multicast_ip(address):
    low = IPv4Address('224.0.0.0')
    high = IPv4Address('239.255.255.255')

    test = IPv4Address(address)

    assert low <= test <= high, f"It looks like {address} is not a valid IPv4 multicast address"


def test_mgroup_1():
    """This test validates that the value for MGROUP_1 is configured
    """

    assert MGROUP_1, "Make sure to configure a valid IPv4 multicast address under the " \
                     "`MGROUP_1` variable in configuration.py"
    validate_multicast_ip(MGROUP_1)


@pytest.mark.skipif("SKIP_MANUAL")
def test_mgroup_2():
    """This test validates that the value for MGROUP_1 is configured
    """

    assert MGROUP_2, "Make sure to configure a valid IPv4 multicast address under the " \
                     "`MGROUP_2` variable in configuration.py"
    validate_multicast_ip(MGROUP_2)
    assert MGROUP_1 != MGROUP_2, "The value of MGROUP_1 shouldn't be equal to MGROUP_2"
