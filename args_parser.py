import argparse


def parse_args():
	parser = argparse.ArgumentParser(description='DHCPLock', epilog='Lock dem baby!')
	
	file_input = parser.add_argument_group("File settings")
	user_input = parser.add_argument_group("User settings")
	
	user_input.add_argument('-i', '--iface', type=str, default='', help='Interface to use')
	file_input.add_argument('-f', '--file', type=str, default='', help='File with DHCP server settings')
	args = parser.parse_args()
	if args.file:
		print(f"The file you are using --> {args.file}")
	if args.iface:
		print(f"The interface you are using --> {args.iface}")	
	return args
	
