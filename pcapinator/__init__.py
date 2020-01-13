#!/usr/bin/env python3
'''
PCAPinator
By: Mike Spicer (@d4rkm4tter)

'''

from . import captools
from . import utils

__all__ = [
    'captools',
    'utils',
]

# TODO: Build a dossier about a mac address
# What is interesting now about a mac address?
# What networks are they probing? What other sites are they visiting?

# TODO: Process and return a list of everything encrypted and what encryption type
# IE: wlan.rsn.akms.type == psk

# TODO: Get a list of all the SSID's and unique it

# TODO: Build summary endpoint and conversation reports for IP, TCP, UDP
# tshark -r input.cap.pcapng -q -z conv,ip > output.txt
# tshark -r input.cap.pcapng -q -z endpoint,ip > output.txt
# Gotta parse the output reports and send to Graphistry


# TODO: Need to make mergeCSV handle the case where there are multiple pcaps but not split...
# I think the above is handled now because I copy a file over and prepend 'split' to it... need to double check.
