"""Implements the SunnyNet Session Protocol in Python
https://256stuff.com/solar/scripts/swrnet_session_protocol.pdf

Author: Ben Peters
Date: 8/23/2016
"""
from struct import unpack, pack

class SunnyNetAddress(object):
    """Wraps the addressing portion of a SunnyNet data message
    """
    ADDRESS_FORMAT = '>HH'

    ADDRESS_TYPE_MASK = 0x80
    ADDRESS_TYPE_GROUP = b'\x80'
    ADDRESS_TYPE_NETWORK = b'\x00'

    MSG_TYPE_MASK = 0x40
    MSG_TYPE_REQUEST = b'\x00'
    MSG_TYPE_RESPONSE = b'\x40'

    def __init__(self, sender, destination, address_type,
                 msg_type=SunnyNetAddress.MSG_TYPE_REQUEST):
        self._sender = sender
        self._destination = destination
        self._address_type = address_type
        self._msg_type = msg_type

    @property
    def addressing_bytes(self):
        """Generates the addressing component
        """
        return pack(self.ADDRESS_FORMAT, self._sender, self._destination) + self._control_byte

    @property
    def sender(self):
        """Sender address
        """
        return self._sender

    @property
    def destination(self):
        """Destination address
        """
        return self._destination

    @property
    def address_type(self):
        """Address type option
        """
        return self._address_type

    @property
    def msg_type(self):
        """Msg type option
        """
        return self._msg_type

    @property
    def _control_byte(self):
        """Control byte
        """
        return self._address_type | self._msg_type

    @classmethod
    def from_bytes(cls, bytes_):
        """Generates a SunnyNetAddress object from a byte string corresponding to a data packet
        """
        sender, destination = unpack(cls.ADDRESS_FORMAT, bytes_[4:8])
        msg_type = bytes([bytes_[8] & cls.MSG_TYPE_MASK])
        address_type = bytes([bytes_[8] & cls.ADDRESS_TYPE_MASK])
        return cls(sender, destination, address_type, msg_type)

class SunnyNetDataPacket(object):
    """Creates a data transmission packet
    """
    START_BYTE = b'\x68'
    STOP_BYTE = b'\x16'

    HEADER_FORMAT = '>BBBB'
    MAX_SIZE = 256

    def __init__(self, address, command, data=(), packet_num=1, num_packets=1):
        #pylint: disable-msg=too-many-arguments
        self._address = address
        self._command = command

        self._packet_num = packet_num
        self._num_packets = num_packets

        if len(data) > self.MAX_SIZE:
            raise ValueError("User data provided is too long ({} bytes, max is {})".format(
                len(data), self.MAX_SIZE))
        self._data = data

    def __str__(self):
        return "{type_} packet with command 0x{command} from {sender:04X} to {destination:04X}"\
            " (length: {byte_len}): {payload}".format(
                type_={
                    SunnyNetAddress.MSG_TYPE_REQUEST: "Request",
                    SunnyNetAddress.MSG_TYPE_RESPONSE: "Response",
                }[self.address.msg_type],
                command=self.command.hex().upper(),
                sender=self.address.sender,
                destination=self.address.destination,
                byte_len=len(self.data),
                payload=" ".join(["0x{:02X}".format(b) for b in self.data]),
            )

    def __bytes__(self):
        """Returns a bytes representation of this data packet
        """
        num_packets_remaining = self._num_packets - self._packet_num
        main_packet = self.address.addressing_bytes + pack('>H', num_packets_remaining) + \
             + self._command + self.data
        checksum = self.calculate_check_sum(main_packet)

        return self._header_bytes + main_packet + checksum + self.STOP_BYTE

    @property
    def address(self):
        """SunnyNetAddress object
        """
        return self._address

    @property
    def command(self):
        """Command
        """
        return self._command

    @property
    def data(self):
        """Bytes data array from this packet
        """
        return self._data

    @property
    def _header_bytes(self):
        """Generates the header, which contains start bytes & length info
        """
        return self.START_BYTE + pack('>BB', len(self.data), len(self.data)) + self.START_BYTE

    @staticmethod
    def calculate_check_sum(data):
        """Calculates the 2 byte checksum by adding all the bytes of the payload together
        """
        checksum = 0x00

        for byte in data:
            checksum += byte

        return pack('>H', checksum & 0xFFFF)

    @classmethod
    def from_bytes(cls, bytes_, total_packets=1):
        """Constructs a SunnyNetData object from bytes
        """
        check_sum = cls.calculate_check_sum(bytes_[4:-3])
        packet_check_sum = bytes_[-3:-1]

        if check_sum != packet_check_sum:
            raise ValueError("Packet checksum (0x{}) does not match calculated checksum (0X{})"
                             .format(packet_check_sum.hex().upper(), check_sum.hex().sum()))


        address = SunnyNetAddress.from_bytes(bytes_)
        packet_num = bytes_[9]
        cmd = bytes_[10:11]
        data = bytes_[12:-3]

        return cls(address, cmd, data, packet_num, total_packets)

class SunnyNetData(object):
    """Data wrapper class for a complete SunnyNet data message which may be sent/received in
    one or more data packets
    """

    def __init__(self, address, command, data=()):
        self._address = address
        self._command = command
        self._data = data

    def __len__(self):
        """Size in bytes of the user payload represented by this class
        """
        return len(self._data)

    @property
    def address(self):
        """Addressing info for this data
        """
        return self._address

    @property
    def command(self):
        """Command to send
        """
        return self._command

    @property
    def num_packets(self):
        """Number of data packets that this data message takes
        """
        return (len(self) / SunnyNetDataPacket.MAX_SIZE) + 1

    @property
    def packets(self):
        """Generator for data packets
        """
        max_size = SunnyNetDataPacket.MAX_SIZE

        for i in range(self.num_packets):
            yield SunnyNetDataPacket(self.address, self.command,
                                     self._data[i * max_size: (i + 1) * max_size],
                                     self.num_packets - i - 1)

    @classmethod
    def from_packets(cls, raw_packets):
        """Creates a SunnyNetData object from an array of packets
        """
        num_packets = len(raw_packets)
        address = None
        command = None

        user_bytes = []

        for bytes_ in raw_packets:
            packet = SunnyNetDataPacket.from_bytes(bytes_, num_packets)

            if address is None:
                address = packet.address

            if command is None:
                command = packet.command

            user_bytes.append(packet.data)

        return cls(address, command, user_bytes)
