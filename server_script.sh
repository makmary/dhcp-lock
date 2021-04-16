#!/bin/bash
echo "		Settings for server"

if [ "$(id -u)" != 0 ]; then 
	echo "This script must be run as root" >&2
	exit 1
else
	#Update and Upgrade
	echo "Updating and Upgrading..."
	apt-get update && sudo apt-get upgrade -y	
	
	#Install Net-Tools
	echo "Installing Net-Tools..."
	apt install -y net-tools
	
	#Install Wireshark
	echo "Installing Wireshark..."
	apt install -y wireshark
	
	#Install Dnsmasq
	echo "Installing DnsMasq..."
	apt install -y dnsmasq
	
	apt install software-properties-common
	add-apt-repository ppa:deadsnakes/ppa
	apt update
	
	apt install python3.8
	python3 ––version
	
	apt install python3-pip
	pip3 --version
	
	pip3 install scapy
	sudo apt-get install python3-scapy
fi	

read -p 'Interface: ' interfacevar
read -p 'Dhcp-range: ' dhcprangevar
read -p 'IP address for server' serveripvar

ifconfig $interfacevar $serveripvar
ifconfig $interfacevar up
systemstl start dnsmasq.service

echo"The end"
