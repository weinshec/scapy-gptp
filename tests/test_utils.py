import unittest

from gptp.layers import PTPv2
from gptp.fields import PortIdentityField
from gptp.utils import MatchedList

portId1 = PortIdentityField.from_mac("11:11:11:11:11:11", 1)
portId2 = PortIdentityField.from_mac("22:22:22:22:22:22", 2)

sync_p1_seq23 = PTPv2(messageType=0x0, sourcePortIdentity=portId1, sequenceId=23)
fup_p1_seq23 = PTPv2(messageType=0x8, sourcePortIdentity=portId1, sequenceId=23)

sync_p1_seq24 = PTPv2(messageType=0x0, sourcePortIdentity=portId1, sequenceId=24)
fup_p1_seq24 = PTPv2(messageType=0x8, sourcePortIdentity=portId1, sequenceId=24)

pdreq_p2_seq25 = PTPv2(messageType=0x2, sourcePortIdentity=portId2, sequenceId=25)
pdresp_p1_seq25 = PTPv2(
    messageType=0x3, sourcePortIdentity=portId1, sequenceId=25, requestingPortIdentity=portId2)
pdrespfup_p1_seq25 = PTPv2(
    messageType=0xA, sourcePortIdentity=portId1, sequenceId=25, requestingPortIdentity=portId2)

pdreq_p2_seq26 = PTPv2(messageType=0x2, sourcePortIdentity=portId2, sequenceId=26)
pdresp_p1_seq26 = PTPv2(
    messageType=0x3, sourcePortIdentity=portId1, sequenceId=26, requestingPortIdentity=portId2)
pdrespfup_p1_seq26 = PTPv2(
    messageType=0xA, sourcePortIdentity=portId1, sequenceId=26, requestingPortIdentity=portId2)


class MatchedListTest(unittest.TestCase):

    def test_finds_matching_sync_and_followup_messages(self):
        with self.subTest("adding single packets"):
            matcher = MatchedList()
            matcher.add(sync_p1_seq23)
            self.assertEqual(0, len(matcher.sync))
            matcher.add(fup_p1_seq23)
            self.assertEqual(1, len(matcher.sync))

        with self.subTest("adding as list"):
            matcher = MatchedList()
            matcher.add([sync_p1_seq24, fup_p1_seq24])
            self.assertEqual(1, len(matcher.sync))

        with self.subTest("wrong order"):
            matcher = MatchedList()
            matcher.add([fup_p1_seq24, sync_p1_seq24])
            self.assertEqual(1, len(matcher.sync))

    def test_finds_matching_pdelay_messages(self):
        with self.subTest("adding single packets"):
            matcher = MatchedList()
            matcher.add(pdreq_p2_seq25)
            self.assertEqual(0, len(matcher.pdelay))
            matcher.add(pdresp_p1_seq25)
            self.assertEqual(0, len(matcher.pdelay))
            matcher.add(pdrespfup_p1_seq25)
            self.assertEqual(1, len(matcher.pdelay))

        with self.subTest("wrong order"):
            matcher = MatchedList()
            matcher.add([
                pdreq_p2_seq26,
                pdresp_p1_seq25,
                pdrespfup_p1_seq25,
                pdrespfup_p1_seq26,
                pdresp_p1_seq26,
                pdreq_p2_seq25
            ])
            self.assertEqual(2, len(matcher.pdelay))

    def test_initialization_with_iterable(self):
        matcher = MatchedList([sync_p1_seq24, fup_p1_seq24])
        self.assertEqual(1, len(matcher.sync))
