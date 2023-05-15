#!/usr/bin/env python3
from sniffer import Sniffer

s = Sniffer("./config.json")

s.start_rsync(10)