import unittest
from scapy.compat import raw
from scapy.packet import Packet

from gptp.fields import PortIdentityField, TimestampField


class TimestampFieldTest(unittest.TestCase):

    class TestPacket(Packet):
        name = "TestPacket"
        fields_desc = [TimestampField("timestamp", 0)]

    def test_encoding(self):
        packet = self.TestPacket(timestamp=42.000001337)
        self.assertEqual(bytes.fromhex('00000000002a00000539'), raw(packet))

    def test_decoding(self):
        packet = self.TestPacket(bytes.fromhex('00000000002a00000539'))
        self.assertEqual(42.000001337, packet.timestamp)


class PortIdentityFieldTest(unittest.TestCase):

    class TestPacket(Packet):
        name = "TestPacket"
        fields_desc = [PortIdentityField("portId", None)]

    def test_encoding(self):
        packet = self.TestPacket(portId=PortIdentityField.from_mac("00:01:02:03:04:05", 42))
        self.assertEqual(bytes.fromhex('000102fffe030405002a'), raw(packet))

    def test_decoding(self):
        packet = self.TestPacket(bytes.fromhex('000102fffe030405002a'))
        self.assertEqual("00:01:02:03:04:05/42", packet.portId)
