from configuration import IFACE
import psutil
import socket
import os


def check_interface_up(expected=True):
    interface_addrs = psutil.net_if_addrs().get(IFACE) or []
    up = socket.AF_INET in [snicaddr.family for snicaddr in interface_addrs]
    assert up == expected, f'Interface {IFACE} is not in the expected link state (up = {expected})'


def set_interface_link(up: bool):
    if up:
        os.system(f"ip link set dev {IFACE} up")
    else:
        os.system(f"ip link set dev {IFACE} down")
