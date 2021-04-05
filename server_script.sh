#!/bin/bash
echo "		Settings for server"

if ! [ $(id -u) = 0 ]; then 
	echo "This script must be run as root"
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
fi	

echo"The end"
