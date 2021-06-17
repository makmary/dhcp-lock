import argparse


def parse_args():
	parser = argparse.ArgumentParser(description='DHCPLock', epilog='Lock dem baby!')
	
	file_input = parser.add_argument_group("File settings")

	file_input.add_argument('-f', '--file', type=str, default='', help='File with DHCP server settings')
	args = parser.parse_args()
	if args.file:
		print(f"The file you are using --> {args.file}")
	return args
	
