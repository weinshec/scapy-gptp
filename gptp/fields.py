import struct
from scapy.fields import XStrFixedLenField, BitField


class TimestampField(BitField):
    def __init__(self, name, default):
        BitField.__init__(self, name, default, 80)

    def any2i(self, pkt, val):
        if val is None:
            return val
        ival = int(val)
        fract = int((val - ival) * 1e9)
        return (ival << 32) | fract

    def i2h(self, pkt, val):
        int_part = val >> 32
        frac_part = val & (1 << 32) - 1
        return int_part + frac_part * 1e-9


class PortIdentityField(XStrFixedLenField):
    encoding = "!BBBBBBBBh"

    @classmethod
    def from_mac(cls, mac, port):
        mac_bytes = mac.split(":")
        if len(mac_bytes) != 6:
            raise ValueError("Invalid MAC Address")

        return struct.pack(
            cls.encoding,
            int(mac_bytes[0], 16),
            int(mac_bytes[1], 16),
            int(mac_bytes[2], 16),
            0xFF,
            0xFE,
            int(mac_bytes[3], 16),
            int(mac_bytes[4], 16),
            int(mac_bytes[5], 16),
            port
        )

    def __init__(self, name, default):
        XStrFixedLenField.__init__(self, name, default, length=10)

    def i2h(self, pkt, val):
        if val is None:
            return "None"
        p = struct.unpack(self.encoding, val)
        return f"{p[0]:02x}:{p[1]:02x}:{p[2]:02x}:{p[5]:02x}:{p[6]:02x}:{p[7]:02x}/{p[8]}"

    def i2repr(self, pkt, x):
        return self.i2h(pkt, x)
