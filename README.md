# scapy-gptp - scapy layer definition and tools for GPTP (IEEE 802.1as)

This python module contains the layer definition for PTPv2 (GPTP) which includes custom
definitions for `Timestamp` and `ClockIdentity` fields. It further provide some handy utils when
analyzing PTPv2 traces.

## Usage

The `PTPv2` layer is automatically bound to the Ethernet layer based on its `type` field (`0x88F7`).
Just import the `PTPv2` layer definition to make scapy aware of this bond and for example read a
pcap file to dissect

```python
from gptp.layers import PTPv2
from scapy.utils import rdpcap

pcap = rdpcap("traces.pcap")

for p in pcap:
    if p.haslayer('PTPv2'):
        p.show()
```

which yields something like

```
###[ Ethernet ]###
  dst       = 01:83:b0:02:21:fe
  src       = 7a:1b:31:80:11:06
  type      = 0x88f7
###[ PTPv2 ]###
     transportSpecific= 1
     messageType= Sync
     reserved0 = 0x0
     versionPTP= 2
     messageLength= 44
     domainNumber= 0
     reserved1 = 0x0
     flags     = TIMESCALE+TWO_STEP
     correctionField= 0
     reserved2 = 0x0
     sourcePortIdentity= 7a:1b:31:80:11:06/1
     sequenceId= 2081
     control   = 0x0
     logMessageInterval= -3
     reserved3 = None
###[ Padding ]###
        load      = '\x00\x00\x00\x00\x00\x00'
```

A handy addition when analyzing PTP traces is the `MatchedList` from `utils` module. You can add PTP
packets to it and it will automatically find matching `(Sync, FollowUp)` message pairs as well as
`(PdelayReq, PdelayResp, PdelayRespFollowUp)` message triplets, providing them as lists for easy
processing and analysis.

```python
from gptp.utils import MatchedList

pcap = rdpcap("traces.pcap")
matched_list = MatchedList([p for p in pcap if p.haslayer('PTPv2')])

(sync, fup) = matched_list.sync[0]
assert sync.sequenceId == fup.sequenceId
print(fup.preciseOriginTimestamp)  # prints 1602135835.0758622
```
