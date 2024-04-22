from configuration import IFACE
import psutil
import socket
import os


def check_interface_up(expected=True):
    if os.environ.get('RUNNING_IN_DOCKER', False):
        # When running inside a Docker container, the interface is always up.
        return
    interface_addrs = psutil.net_if_addrs().get(IFACE) or []
    up = socket.AF_INET in [snicaddr.family for snicaddr in interface_addrs]
    assert up == expected, f'Interface {IFACE} is not in the expected link state (up = {expected})'
