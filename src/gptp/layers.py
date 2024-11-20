from scapy.fields import (
    BitEnumField,
    BitField,
    ByteField,
    ConditionalField,
    FlagsField,
    LongField,
    ShortField,
    SignedByteField,
    XBitField,
    XByteField,
    XIntField,
    XStrFixedLenField,
)
from scapy.layers.l2 import Ether
from scapy.packet import Packet, bind_layers

from .fields import PortIdentityField, TimestampField


class PTPv2(Packet):
    name = "PTPv2"

    MSG_TYPES = {
        0x0: "Sync",
        0x2: "PdelayReqest",
        0x3: "PdelayResponse",
        0x8: "FollowUp",
        0xA: "PdelayResponseFollowUp",
    }

    FLAGS = [
        "LI61",
        "LI59",
        "UTC_REASONABLE",
        "TIMESCALE",
        "TIME_TRACEABLE",
        "FREQUENCY_TRACEABLE",
        "?",
        "?",
        "ALTERNATE_MASTER",
        "TWO_STEP",
        "UNICAST",
        "?",
        "?",
        "profileSpecific1",
        "profileSpecific2",
        "SECURITY",
    ]

    fields_desc = [
        BitField("majorSdoId", 1, 4),
        BitEnumField("messageType", 0, 4, MSG_TYPES),
        XBitField("minorVersionPTP", 0, 4),
        BitField("versionPTP", 0x2, 4),
        ShortField("messageLength", 34),
        ByteField("domainNumber", 0),
        XByteField("minorSdoId", 0),
        FlagsField("flags", 0, 16, FLAGS),
        LongField("correctionField", 0),
        XIntField("messageTypeSpecific", 0),
        PortIdentityField("sourcePortIdentity", None),
        ShortField("sequenceId", 0),
        XByteField("controlField", 0),
        SignedByteField("logMessageInterval", -3),
        # Sync (twoStep flag set) or PdelayReq
        ConditionalField(
            BitField("reserved", 0, 80),
            lambda pkt: (pkt.is_sync and pkt.has_twostepflag_set) or pkt.is_pdelay_req,
        ),
        # Sync (twoStep flag not set)
        ConditionalField(
            TimestampField("originTimestamp", 0),
            lambda pkt: pkt.is_sync and not pkt.has_twostepflag_set,
        ),
        # FollowUp
        ConditionalField(
            TimestampField("preciseOriginTimestamp", 0), lambda pkt: pkt.is_followup
        ),
        # Sync (twoStep flag not set) or FollowUp
        ConditionalField(
            XStrFixedLenField("informationTlv", bytes(32), 32),
            lambda pkt: (pkt.is_sync and not pkt.has_twostepflag_set)
            or pkt.is_followup,
        ),
        # PdelayReq
        ConditionalField(BitField("reserved2", 0, 80), lambda pkt: pkt.is_pdelay_req),
        # PdelayResp
        ConditionalField(
            TimestampField("requestReceiptTimestamp", 0), lambda pkt: pkt.is_pdelay_resp
        ),
        # PdelayRespFollowUp
        ConditionalField(
            TimestampField("responseOriginTimestamp", 0),
            lambda pkt: pkt.is_pdelay_resp_followup,
        ),
        # PdelayResp or PdelayRespFollowUp
        ConditionalField(
            PortIdentityField("requestingPortIdentity", 0),
            lambda pkt: pkt.is_pdelay_resp or pkt.is_pdelay_resp_followup,
        ),
    ]

    @property
    def is_sync(self):
        return self.messageType == 0x0

    @property
    def is_followup(self):
        return self.messageType == 0x8

    @property
    def is_pdelay_req(self):
        return self.messageType == 0x2

    @property
    def is_pdelay_resp(self):
        return self.messageType == 0x3

    @property
    def is_pdelay_resp_followup(self):
        return self.messageType == 0xA

    @property
    def has_twostepflag_set(self):
        return "TWO_STEP" in self.flags

    def extract_padding(self, s):
        return "", s


bind_layers(Ether, PTPv2, type=0x88F7)
