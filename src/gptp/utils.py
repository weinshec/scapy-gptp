from .layers import PTPv2


def matching_sync(sync, fup):
    matching_portIds = (sync.sourcePortIdentity == fup.sourcePortIdentity)
    matching_seqIds = (sync.sequenceId == fup.sequenceId)
    return matching_portIds and matching_seqIds


def matching_pdelay(req, resp):
    matching_portIds = (req.sourcePortIdentity == resp.requestingPortIdentity)
    matching_seqIds = (req.sequenceId == resp.sequenceId)
    return matching_portIds and matching_seqIds


class MatchedList:

    def __init__(self, packets=[]):
        self._sync = []
        self._pdelay = []

        self._unmatched_sync = []
        self._unmatched_fup = []
        self._unmatched_pdreq = []
        self._unmatched_pdresp = []
        self._unmatched_pdresp_fup = []

        self.add(packets)

    def add(self, pkt):
        if type(pkt) == PTPv2:
            self._add_dispatch(pkt)
        elif iter(pkt):
            for p in pkt:
                self._add_dispatch(p)

    def _add_dispatch(self, p):
        if p.messageType == 0x0:
            self._add_sync(p)
        elif p.messageType == 0x2:
            self._add_pdelay_request(p)
        elif p.messageType == 0x3:
            self._add_pdelay_response(p)
        elif p.messageType == 0x8:
            self._add_followup(p)
        elif p.messageType == 0xA:
            self._add_pdelay_response_followup(p)

    def _add_sync(self, sync):
        for i, fup in enumerate(self._unmatched_fup):
            if matching_sync(sync, fup):
                self._sync.append((sync, self._unmatched_fup.pop(i)))
                return
        self._unmatched_sync.append(sync)

    def _add_followup(self, fup):
        for i, sync in enumerate(self._unmatched_sync):
            if matching_sync(sync, fup):
                self._sync.append((self._unmatched_sync.pop(i), fup))
                return
        self._unmatched_fup.append(fup)

    def _add_pdelay_request(self, req):
        for i, resp in enumerate(self._unmatched_pdresp):
            if matching_pdelay(req, resp):
                for j, respfup in enumerate(self._unmatched_pdresp_fup):
                    if matching_pdelay(req, respfup):
                        self._pdelay.append(
                            (req, self._unmatched_pdresp.pop(i), self._unmatched_pdresp_fup.pop(j)))
                        return
        self._unmatched_pdreq.append(req)

    def _add_pdelay_response(self, resp):
        for i, req in enumerate(self._unmatched_pdreq):
            if matching_pdelay(req, resp):
                for j, respfup in enumerate(self._unmatched_pdresp_fup):
                    if matching_pdelay(req, respfup):
                        self._pdelay.append(
                            (self._unmatched_pdreq.pop(i), resp, self._unmatched_pdresp_fup.pop(j)))
                        return
        self._unmatched_pdresp.append(resp)

    def _add_pdelay_response_followup(self, resp_fup):
        for i, req in enumerate(self._unmatched_pdreq):
            if matching_pdelay(req, resp_fup):
                for j, resp in enumerate(self._unmatched_pdresp):
                    if matching_pdelay(req, resp):
                        self._pdelay.append(
                            (self._unmatched_pdreq.pop(i), self._unmatched_pdresp.pop(j), resp_fup))
                        return
        self._unmatched_pdresp_fup.append(resp_fup)

    @property
    def sync(self):
        return self._sync

    @property
    def pdelay(self):
        return self._pdelay

    @property
    def unmatched(self):
        return {
            "sync": self._unmatched_sync,
            "followup": self._unmatched_fup,
            "pdelay_req": self._unmatched_pdreq,
            "pdelay_resp": self._unmatched_pdresp,
            "pdelay_resp_followup": self._unmatched_pdresp_fup,
        }

    def __repr__(self):
        return f"<MatchedList sync:{len(self.sync)} pdelay:{len(self.pdelay)}>"
