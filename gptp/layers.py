from scapy.fields import BitEnumField, ByteField, ConditionalField, FlagsField, LongField, \
    ShortField, SignedByteField, XBitField, XByteField
from scapy.layers.l2 import Ether, Dot1Q
from scapy.packet import Packet, bind_layers
from .fields import PortIdField, ReservedField, TimestampField, TLVField


class PTP(Packet):
    name = "PTPv2"

    MSG_TYPES = {
        0x0: "Sync",
        0x2: "PdelayReqest",
        0x3: "PdelayResponse",
        0x8: "FollowUp",
        0xA: "PdelayResponseFollowUp",
    }

    FLAGS = [
        "LI61", "LI59", "UTC_REASONABLE", "TIMESCALE",
        "TIME_TRACEABLE", "FREQUENCY_TRACEABLE", "?", "?",
        "ALTERNATE_MASTER", "TWO_STEP", "UNICAST", "?",
        "?", "profileSpecific1", "profileSpecific2", "SECURITY",
    ]

    fields_desc = [
        XBitField("transport", 1, 4),
        BitEnumField("type", 0, 4, MSG_TYPES),
        XBitField("reserved0", 0, 4),
        XBitField("version", 2, 4),
        ShortField("length", 34),
        ByteField("domain", 0),
        ReservedField("reserved1", 0, 1),
        FlagsField("flags", 0, 16, FLAGS),
        LongField("correct", 0),
        ReservedField("reserved2", 0, 4),
        PortIdField("srcPortId", 0),
        ShortField("seqId", 0),
        XByteField("control", 0),
        SignedByteField("logMsgInt", -3),

        # Sync
        ConditionalField(ReservedField("reserved3", 0, 10), lambda pkt:pkt.is_sync),

        # FollowUp
        ConditionalField(TimestampField("origTime", 0), lambda pkt:pkt.is_followup),
        ConditionalField(TLVField("tlv", 0), lambda pkt:pkt.is_followup),

        # PdelayReq
        ConditionalField(ReservedField("reserved3", 0, 10), lambda pkt:pkt.is_pdelay_req),
        ConditionalField(ReservedField("reserved4", 0, 10), lambda pkt:pkt.is_pdelay_req),

        # PdelayResp
        ConditionalField(TimestampField("rcptTime", 0), lambda pkt:pkt.is_pdelay_resp),
        ConditionalField(PortIdField("reqPortId", 0), lambda pkt:pkt.is_pdelay_resp),

        # PdelayRespFollowUp
        ConditionalField(TimestampField("respTime", 0), lambda pkt:pkt.is_pdelay_resp_followup),
        ConditionalField(PortIdField("reqPortId", 0), lambda pkt:pkt.is_pdelay_resp_followup),

    ]

    @property
    def is_sync(self):
        return(self.type == 0x0)

    @property
    def is_followup(self):
        return(self.type == 0x8)

    @property
    def is_pdelay_req(self):
        return(self.type == 0x2)

    @property
    def is_pdelay_resp(self):
        return(self.type == 0x3)

    @property
    def is_pdelay_resp_followup(self):
        return(self.type == 0xA)

    def extract_padding(self, s):
        return "", s

    def mysummary(self):
        return self.sprintf("%type% %srcPortId% %seqId%")


bind_layers(Ether, Dot1Q, type=0x9100)
bind_layers(Dot1Q, PTP, type=0x88f7)
