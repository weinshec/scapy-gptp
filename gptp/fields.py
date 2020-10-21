from scapy.fields import XStrFixedLenField
from .utils import portId2str, timestamp2str


class TimestampField(XStrFixedLenField):
    def __init__(self, name, default):
        XStrFixedLenField.__init__(self, name, default, length=10)

    def i2repr(self, pkt, x):
        return timestamp2str(x)


class PortIdField(XStrFixedLenField):
    def __init__(self, name, default):
        XStrFixedLenField.__init__(self, name, default, length=10)

    def i2repr(self, pkt, x):
        return portId2str(x)


class ReservedField(XStrFixedLenField):
    def __init__(self, name, default, length):
        XStrFixedLenField.__init__(self, name, default, length=length)


class TLVField(XStrFixedLenField):
    def __init__(self, name, default):
        XStrFixedLenField.__init__(self, name, default, length=32)
