#!/usr/bin/env python
# encoding: utf-8

import os
import sys

from gptp import PTP
from gptp.utils import portId2str, timestamp2str
from scapy.all import *


class SyncMessage:
    def __init__(self, srcPortId, seqId, tap_time):
        self._srcPortId = srcPortId
        self._seqId     = seqId
        self._ptp_time  = None
        self._tap_time  = tap_time

    @property
    def srcPortId(self):
        return self._srcPortId

    @property
    def seqId(self):
        return self._seqId

    @property
    def tap_time(self):
        return self._tap_time

    @property
    def ptp_time(self):
        return self._ptp_time

    @ptp_time.setter
    def ptp_time(self, t):
        self._ptp_time = t

    def matches(self, srcPortId, seqId):
        return (self._srcPortId == srcPortId) and (self._seqId == seqId)

    def __str__(self):
        return "{},{},{},{}".format(portId2str(self.srcPortId), self.seqId,
                                    timestamp2str(self.ptp_time) if self.ptp_time is not None else "NaN",
                                    self.tap_time)


if __name__ == '__main__':
    total_syncs = 0
    missing_followups = 0
    incomplete_messages = list()

    for file in sys.argv[1:]:
        pcap = rdpcap(file)

        for m in pcap:
            srcPort = m[PTP].srcPortId
            msgType = m[PTP].type
            seqId   = m[PTP].seqId

            if msgType == 0x0: # Sync
                total_syncs += 1
                incomplete_messages.append(SyncMessage(srcPort, seqId, m.time))
            elif msgType == 0x8: # FollowUp
                matching_message = None
                for i, message in enumerate(incomplete_messages):
                    if message.matches(srcPort, seqId):
                        matching_message = i
                        break
                if matching_message is not None:
                    message = incomplete_messages.pop(matching_message)
                    message.ptp_time = m[PTP].origTime
                    print(message)

        for m in incomplete_messages:
            print(m)
        missing_followups += len(incomplete_messages)
        incomplete_messages.clear()

    print("# total_syncs = {}".format(total_syncs))
    print("# missing_followups = {}".format(missing_followups))
