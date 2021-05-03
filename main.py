#!/usr/bin/env python3

from scapy.all import *
from args_parser import parse_args
from dhcp_lock import DHCPLock
from logger import set_logger
import logging


def main():
	set_logger()
	args = parse_args()
	if args.file:
		app = DHCPLock(filename=args.file)
	else:	
		app = DHCPLock(interfaces=args.iface)
	app.run()


if __name__ == '__main__':
	main()
