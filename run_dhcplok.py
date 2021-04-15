#!/usr/bin/env python3

from scapy.all import *

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
			print("[*] Got new DHCP DISCOVER from: " + mac_addr + " xid: " + hex(xid))
			hostname = get_option(resp[DHCP].options, 'hostname')
			print(f"Host {hostname} ({resp[Ether].src}) asked for an IP")

		if resp[DHCP].options[0][1] == 2:
			xid = resp[BOOTP].xid
			print("[*] Got new DHCP OFFER from: " + mac_addr + " xid: " + hex(xid))
			subnet_mask = get_option(packet[DHCP].options, 'subnet_mask')
			lease_time = get_option(packet[DHCP].options, 'lease_time')
			router = get_option(packet[DHCP].options, 'router')
			name_server = get_option(packet[DHCP].options, 'name_server')
			domain = get_option(packet[DHCP].options, 'domain')


			print(f"DHCP Server {packet[IP].src} ({packet[Ether].src}) "
			      f"offered {packet[BOOTP].yiaddr}")


			print(f"DHCP Options: subnet_mask: {subnet_mask}, lease_time: "
			      f"{lease_time}, router: {router}, name_server: {name_server}, "
			      f"domain: {domain}")

		if resp[DHCP].options[0][1] == 3:
			xid = resp[BOOTP].xid
			print("[*] Got new DHCP REQUEST from: " + mac_addr + " xid: " + hex(xid))
			requested_addr = get_option(resp[DHCP].options, 'requested_addr')
			hostname = get_option(resp[DHCP].options, 'hostname')
			print(f"Host {hostname} ({resp[Ether].src}) requested {requested_addr}")


interface = 'enp0s8'
dhcplock_filter = 'udp and (port 67 or 68)'
print("[*] Waiting for a DHCP Packets...")
sniff(iface=interface, filter=dhcplock_filter, prn=dhcp)
