#!/usr/bin/env python
# encoding: utf-8

import matplotlib.pyplot as plt
import numpy as np
import sys
from scipy import stats

id_BCP = b"7c:fc:3c:73:cc:0e.0"
id_ENS1 = b"70:b3:d5:69:90:0a.1"

if __name__ == '__main__':

    data = np.loadtxt(
        sys.argv[1],
        dtype={
            'names': ('portId', 'seqId', 'ptp_time', 'tap_time'),
            'formats': ('S20', 'i4', np.float64, np.float64)
        },
        delimiter=',')

    data["tap_time"] -= np.min(data["tap_time"])

    BCP = tuple([data["portId"] == id_BCP])
    ENS = tuple([data["portId"] == id_ENS1])

    diffs = np.diff(data[ENS]['ptp_time'])

    # fig, ax = plt.subplots()
    # ax.hist(diffs, bins=200)
    # ax.set_yscale('log')
    # fig.savefig("diffs.png", bbox_inches="tight")

    fig, ax = plt.subplots()
    ax.plot(data[ENS]['tap_time'][:90], data[ENS]['ptp_time'][:90])
    ax.grid()
    fig.savefig("diffs.png", bbox_inches="tight")

    abnormal = np.where(np.abs(diffs - 0.125)  > 0.1)
    print(data[ENS]["seqId"][abnormal])
    print(diffs[abnormal])
