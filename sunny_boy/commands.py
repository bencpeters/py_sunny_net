"""Command generators for SunnyNet Commands
https://256stuff.com/solar/scripts/swrnet_session_protocol.pdf

These command functions each generate a SunnyNetData object which can be used to send
the specified command over serial

Author: Ben Peters
Date: 8/23/2016
"""

from .protocol import SunnyNetData, SunnyNetAddress

def system_config_request():
    """Creates a SunnyNetData object to query for SunnyNet system config
    """
    cmd_get_net = b'\x01'
    address = SunnyNetAddress(0x0000, 0x0000, b'\x80', SunnyNetAddress.MSG_TYPE_REQUEST)
    return SunnyNetData(address, cmd_get_net)
