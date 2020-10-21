def timestamp2str(timestamp):
    seconds = int.from_bytes(timestamp[:-4], byteorder="big")
    nanoseconds = int.from_bytes(timestamp[-4:], byteorder="big")
    timestamp = nanoseconds * 1e-9 + seconds
    return "{:.9f}".format(timestamp)

def timestamp2float(timestamp):
    seconds = int.from_bytes(timestamp[:-4], byteorder="big")
    nanoseconds = int.from_bytes(timestamp[-4:], byteorder="big")
    return nanoseconds * 1e-9 + seconds

def portId2port(portId):
    return int.from_bytes(portId[9:], byteorder="big")


def portId2str(portId):
    mac = b"" + portId[:3] + portId[5:8]
    port = portId2port(portId)
    return "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}.{}".format(*mac, port)
