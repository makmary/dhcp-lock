import argparse


def parse_args():
	parser = argparse.ArgumentParser(description='DHCPLock', epilog='Lock dem baby!')
	parser.add_argument('-i', '--iface', type=str, help='Interface to use')
	parser.add_argument('-f', '--file', type=str, help='File with DHCP server settings')
	args = parser.parse_args()
	if args.file:
		print(f"This is the file you are using {args.file}")
	if args.iface:
		print(f"This is the interface you are using {args.iface}")	
	return args
	
