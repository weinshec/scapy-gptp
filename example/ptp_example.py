#!/usr/bin/env python
# encoding: utf-8

from gptp.layers import PTPv2
from gptp.utils import MatchedList
from scapy.utils import rdpcap

pcap = rdpcap("example/ptp_example.pcapng")

# Create a MatchedList, which will match tuples of (Sync, FollowUp)
# and (PdelayReq, PdelayResp, PdelayRespFollowUp)
matched_list = MatchedList([p for p in pcap if p.haslayer('PTPv2')])

# Show the first tuple
(sync, fup) = matched_list.sync[0]

sync.show()
fup.show()
