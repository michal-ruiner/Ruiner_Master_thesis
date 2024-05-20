#!/usr/bin/env python3

import argparse
import subprocess
import re
import os
import os.path
import sys
from pwd import getpwnam
import pandas as pd

#######################
# CLASSES
#######################
class Device:
	def __init__(self, macAddr):
		self.__macAddr = macAddr
		self.__ip_addresses = set()
		self.__possible_ip_addresses = set()

	# Getters
	def get_macAddr(self):
		return self.__macAddr
	def get_ip_addresses(self):
		return self.__ip_addresses
	def get_possible_ip_addresses(self):
		return self.__possible_ip_addresses
	
	#Setters
	def set_macAddr(self, macAddr):
		self.__macAddr = macAddr
		return
	def set_ip_addresses(self, ipAddr):
		self.__ip_addresses.add(ipAddr)
		return
	def set_possible_ip_addresses(self, ipAddr):
		self.__possible_ip_addresses.add(ipAddr)
		return
	def clear_possible_ip_addresses(self):
		self.__possible_ip_addresses.clear()

#######################
# GLOBAL VARIABLES
#######################
# The unique device objects from the packet capture
uniqDevObjCapt = {}

# The unique device objects from the ptnet output
uniqDevObjPtnet = {}

# Forbidden addresses
ignoreIPs = ['8.8.8.8', '0.0.0.0', 'ff05::2']

# Storage place for start time and end time of the ptnetinspector
times = []

#######################
# FUNCTIONS
#######################

# Function to extract MAC address and create and object based on it
def extractMac(line):
	global uniqDevObjCapt
	macPattern = r"(\d{2}:\d{2}:\d{2}\.\d{6}) (([0-9A-Fa-f]{2}:){5}([0-9A-Fa-f]{2}))"
	macAddrExtract = re.search(macPattern, line)

	if macAddrExtract:
		macAddr = macAddrExtract.group(2)
		if not findDeviceByMAC(macAddr):
			dev = Device(macAddr)
			uniqDevObjCapt[macAddr] = dev
		return macAddr
		

# Function to extract source IP
def extractSourceIP(line, macAddr):
	global ignoreIPs
	srcIPpattern = r"length \d+: ([\da-fA-F:.]+) > "
	srcIPextract = re.search(srcIPpattern, line)
	if srcIPextract:
		ipAddr = srcIPextract.group(1)
		if("." in ipAddr):
			ipAddr = remPortNum(ipAddr)

		if not (ipAddr in ignoreIPs):
			if(findDeviceByMAC(macAddr)):
				uniqDevObjCapt.get(macAddr).set_ip_addresses(ipAddr)
			else:
				dev = Device(macAddr)
				dev.set_ip_addresses(ipAddr)
				uniqDevObjCapt[macAddr] = dev

	
# Function to search for the device object
def findDeviceByMAC(macAddr):
	global uniqDevObjCapt

	for mac in uniqDevObjCapt:
		if mac == macAddr:
			return True
	return False

# Function to remove port number from the IPv4
def remPortNum(ipAddr):
	ipv4Pattern = r"(?:[0-9]{1,3}\.){3}[0-9]{1,3}"
	ipv6Pattern = r".*?(?=\.\d+)"
	ipSelect = r'[a-zA-Z]'

	if re.search(ipSelect, ipAddr):
		return ''.join(re.findall(ipv6Pattern, ipAddr))
	else:
		return ''.join(re.findall(ipv4Pattern, ipAddr))
	
# Function to extract addresses from the ptnet output
def extractAddrPtnet(devAddrArr):
	global uniqDevObjPtnet
	dev = Device("newDev")
	macPattern = r'\bMAC\b|\s+'
	ipv4Pattern = r'\bIPv4\b|\s+'
	ipv6Pattern = r'\bIPv6\b|\s+'

	for line in devAddrArr:
		if re.search('MAC', line):
			macAddr = re.sub(macPattern, '', line)
			dev.set_macAddr(macAddr)
			
		if re.search('IPv4', line):
			ipv4Addr = re.sub(ipv4Pattern, '', line)
			dev.set_ip_addresses(ipv4Addr)

		if re.search('IPv6', line):
			ipv6Addr = re.sub(ipv6Pattern, '', line)
			ipv6Addr = re.sub('\(possibleaddress\)', '', ipv6Addr)
			dev.set_ip_addresses(ipv6Addr)
	uniqDevObjPtnet[dev.get_macAddr()] = dev

# Function to extract addresses from the MLD packets (payload)
# Both MLDv1 and MLDv2
def extractMLDaddresses(line):
	global uniqDevObjCapt
	global ignoreIPs
	mldV2 = r'multicast listener report v2'
	solNodeMult = r'ff02::1:ff'
	macPattern = r"(\d{2}:\d{2}:\d{2}\.\d{6}) (([0-9A-Fa-f]{2}:){5}([0-9A-Fa-f]{2})) > "
	macAddrExtract = re.search(macPattern, line)

	if re.search(mldV2, line):
		addrPattern = r'gaddr ([\da-fA-F:]+)'
		ipv6addresses = re.findall(addrPattern, line)

		for i in range(len(ipv6addresses)):
			ipv6addresses[i] = re.sub(solNodeMult, '', ipv6addresses[i])
			if (re.search('ff02::', ipv6addresses[i]) or
					re.search('ff03::', ipv6addresses[i])
					or re.search('ff05::', ipv6addresses[i])
					or re.search('ff12::', ipv6addresses[i])
					or ipv6addresses[i] in ignoreIPs):
				continue
			else:
				if macAddrExtract:
					macAddr = macAddrExtract.group(2)
					if(findDeviceByMAC(macAddr)):
						uniqDevObjCapt.get(macAddr).set_possible_ip_addresses(ipv6addresses[i])
	else:
		addrPattern = r'addr: ([\da-fA-F:]+)$'
		findIPv6 = re.search(addrPattern, line)

		if findIPv6:
			ipv6addr = findIPv6.group(1)
			ipv6addr = re.sub(solNodeMult, '', ipv6addr)

			if re.search('ff02::', ipv6addr) or ipv6addr in ignoreIPs:
				return
			else:
				if macAddrExtract:
					macAddr = macAddrExtract.group(2)
					if(findDeviceByMAC(macAddr)):
						uniqDevObjCapt.get(macAddr).set_possible_ip_addresses(ipv6addr)

# Function to extract addresses from the MDNS packets (payload)
def extractMDNSaddresses(line):
	global uniqDevObjCapt
	ipv4pattern = r'\bA ([\d.]+)'
	ipv6pattern = r'AAAA ([\da-fA-F:]+)'
	macPattern = r"(\d{2}:\d{2}:\d{2}\.\d{6}) (([0-9A-Fa-f]{2}:){5}([0-9A-Fa-f]{2})) > "
	macAddrExtract = re.search(macPattern, line)

	if macAddrExtract:
		macAddr = macAddrExtract.group(2)
		if re.search(ipv4pattern, line):
			ipv4addresses = re.findall(ipv4pattern, line)
			for i in range(len(ipv4addresses)):
				if(findDeviceByMAC(macAddr)):
					uniqDevObjCapt.get(macAddr).set_ip_addresses(ipv4addresses[i])

		if re.search(ipv6pattern, line):
			ipv6addresses = re.findall(ipv6pattern, line)
			for i in range(len(ipv6addresses)):
				if(findDeviceByMAC(macAddr)):
					uniqDevObjCapt.get(macAddr).set_ip_addresses(ipv6addresses[i])

# Function to extract addresses from the LLMNR packets (payload)
def extractLLMNRaddresses(nodeArr):
	global uniqDevObjCapt
	macAddr = extractMac(nodeArr[0])
	lineWithBytes = r'^(\s*)0x[0-9a-z]{4}'
	bytesPattern = r'(?:[0-9a-f]{4}|[0-9a-f]{2})(?=\s)'
	extractedBytes = []


	for line in nodeArr:
		if re.match(lineWithBytes, line):
			lineBytes = re.findall(bytesPattern, line)
			for i in range(len(lineBytes)):
				extractedBytes.append(lineBytes[i])

	for id, byte in enumerate(extractedBytes):
		try:
			# PTR record
			if (byte == '000c'):
				if((extractedBytes[id+1] == '0001') and (extractedBytes[id+2] == '0000') and (extractedBytes[id+3] == '001e')):
					continue
			# A (IPv4) record
			elif (byte == '0001'):
				if((extractedBytes[id+1] == '0001') and	 (extractedBytes[id+2] == '0000') and (extractedBytes[id+3] == '001e')):
					ipv4addrLen = int(int(extractedBytes[id+4], 16)/2)
					ipv4addr = str()
					for i in range(ipv4addrLen):
						temp2Bytes = extractedBytes[id+5+i]
						byteArr = [int(temp2Bytes[j:j+2],16) for j in range(0, len(temp2Bytes), 2)]
						for num in byteArr:
							ipv4addr += str(num) + '.'
					ipv4addr = ipv4addr[:-1]
					if(findDeviceByMAC(macAddr)):
						uniqDevObjCapt.get(macAddr).set_ip_addresses(ipv4addr)
			# AAAA (IPv6) record
			elif(byte == '001c'):
				if((extractedBytes[id+1] == '0001') and (extractedBytes[id+2] == '0000') and (extractedBytes[id+3] == '001e')):
					ipv6addrLen = int(int(extractedBytes[id+4], 16)/2)
					ipv6addr = str()
					for i in range(ipv6addrLen):
						ipv6addr += extractedBytes[id+5+i].lstrip("0") + ':'
					ipv6addr = re.sub(':{2,}', '::', ipv6addr)
					ipv6addr = ipv6addr[:-1]
					if(findDeviceByMAC(macAddr)):
						uniqDevObjCapt.get(macAddr).set_ip_addresses(ipv6addr)
		except IndexError:
			continue

# Function to create possible IPv6 addresses by prepending X to the unknown part
def possibleAddresses(posAddr):
	countX = 0
	updatedAddr =str()
	posAddrArr = posAddr.split(':')
	updatePosAddr = posAddrArr[0]
	for i in range(1, len(posAddrArr)):
		updatePosAddr += ':' + (4-len(posAddrArr[i])) * '0' + posAddrArr[i]

	while(len(updatedAddr) != (39 - len(updatePosAddr))):
		updatedAddr += 'X'
		countX+=1
		if countX == 4:
			updatedAddr += ':'
			countX = 0
	updatedAddr += updatePosAddr
	return updatedAddr

def possibleAddressesMissed(posAddr):
	initAddrArr = posAddr.split('::')
	posAddrArr = initAddrArr[1].split(':')
	updatePosAddr = str()

	for i in range(1, len(posAddrArr)):
		updatePosAddr += (4 - len(posAddrArr[i])) * '0' + posAddrArr[i] + ":"

	return initAddrArr[0] + "::" + updatePosAddr.rstrip(":")

# Function to check if the possible address ending is already contained in the IP address list
def loopThroughAddresses(dev, posAddr):
	splitAddr = posAddr.split(":")
	editedAddr = str()
	containsDoubleColon = False

	for bytes in splitAddr:
		stripBytes = bytes.lstrip("0")
		if len(stripBytes) != 0:
			editedAddr += stripBytes
		else:
			if not containsDoubleColon:
				editedAddr += '::'
				containsDoubleColon = True
	
	if (editedAddr == '::'):
		containsDoubleColon = False

	for addr in dev.get_ip_addresses():
		if (containsDoubleColon):
			if editedAddr in addr:
				return True
			elif posAddr in addr:
				return True 
		elif posAddr in addr:
			return True
	return False

# Function to check the end time of ptnetinspector and 
def checkTimeStamp(line):
	global times
	lineTimePat = r'^(\d{2}:\d{2}:\d{2}.\d{6})'
	lineTimeExtract = re.search(lineTimePat, line)
	if lineTimeExtract:
		lineTime = lineTimeExtract.group(1)
		if (times[0] <= lineTime and times[1] >= lineTime):
			return True
		else:
			return False

# Function to check if the duration from input arguments is positive integer
def positive_int(num):
    tempValue = int(num)
    if tempValue <= 0:
        raise argparse.ArgumentTypeError("Invalid positive_int value: " + str(tempValue))
    return tempValue
	
def processTime():
	global times
	timePattern = r'\d{2}:\d{2}:\d{2}\.\d{6}'
	
	df = pd.read_csv('./src/tmp/start_end_mode.csv')
	times.append(df.iloc[0, 0])
	times.append(df.iloc[len(df)-1, 0])

	for i in range(len(times)):
		timeMatch = re.search(timePattern, times[i])
		if timeMatch:
			times[i] = timeMatch.group(0)

	
def checkPtnetOutErrors(line):
	errorPattern = r'\[\✗\]'
	errorExtract = re.search(errorPattern, line)

	if errorExtract:
		return True
	else:
		return False

#######################
# INPUT PARAMETERS
#######################

# Create file addr.txt and write there the output of 'ip a' command
with open('addr.txt', 'w') as f:
    subprocess.run(["ip","a"], stdout=f)

# Obtain list of available network interfaces
interfaces=[]
intPattern=r'\d+:\s*(.*?):\s*<'
with open('addr.txt', 'r') as f:
	for line in f:
		intExtract = re.search(intPattern, line)
		if intExtract:
			interfaces.append(intExtract.group(1))	
os.remove('addr.txt')

# Input parameters
parser=argparse.ArgumentParser(
    prog='verifyAddresses',
    description='Script to compare the output of ptnetinspector with captured packets on the interface')
sub_parsers = parser.add_subparsers(help='Select from the positional arguments, use \'-h\' after each to display options')
parser_mode = sub_parsers.add_parser('mode', help='Argument to select appropriate mode')
mode_sub_parsers = parser_mode.add_subparsers(help='Select from the positional arguments, use \'-h\' after each to display options', dest='mode')

parser_passive = mode_sub_parsers.add_parser('p', help='Passive mode')
parser_passive.add_argument('-d', '--duration', dest='pas_duration', metavar='SECONDS', required=False, type=positive_int, help='Duration of the passive mode listening')
parser_passive.add_argument('-more', required=False, dest='pas_more', action='store_true', help='Display more detailed output of ptnetinspector')

parser_active = mode_sub_parsers.add_parser('a', help='Active mode')
parser_active.add_argument('-more', required=False, dest='act_more', action='store_true', help='Display more detailed output of ptnetinspector')

parser_aggressive = mode_sub_parsers.add_parser('a+', help='Aggressive mode')
parser_aggressive.add_argument('-da+', '--duration', dest='agr_duration', metavar='SECONDS', required=False, type=positive_int, help='Duration of the aggressive mode')
parser_aggressive.add_argument('-p', '--prefix', dest='prf', metavar='IPv6_ADDR', type=str, required=False, help='Prefix for the aggressive mode')
parser_aggressive.add_argument('-period', dest='agr_period', metavar='RATE', required=False, type=positive_int, help='RA sending rate in the aggressive mode')
parser_aggressive.add_argument('-dns', dest='dns_addr', metavar='IPv6_ADDR', required=False, type=str, help='The IPv6 address of DNS server')
parser_aggressive.add_argument('-more', required=False, dest='agr_more', action='store_true', help='Display more detailed output of ptnetinspector')

interface_arg = parser.add_argument('-i', '--interface', help='Select working interface')
parser.add_argument('-nodel', required=False, action='store_false', help='Preserve the current CapturedPackets directory and do not run the bash script')
parser.add_argument('-debug', required=False, action='store_true', help='Show output for the debug purpose')

args, _ = parser.parse_known_args()

if args.nodel:
	sub_parsers.required=True
	interface_arg.required=True

args=parser.parse_args()
# Check if mode was set in the input arguments
if ('mode' in vars(args)):
	if (args.mode is None):
		parser.error("Mode cannot be empty.")

# Check if interface was set in the input arguments
if (args.interface is not None):

	# If the input interface is not available, print error and exit the program
	if not args.interface in interfaces:
		print("Interface ", args.interface, " is not available. Please, choose 1 interface from the following ones: ",interfaces, file=sys.stderr)
		exit()
		
	# Create file interface.txt and write there the output of 'ip a' command for specific interface
	with open('interface.txt', 'w') as f:
		subprocess.run(["ip","a","show",args.interface], stdout=f)
		
	# Extract MAC address of an interface
	interfaceMAC=str()
	intMACPattern=r'link/ether\s*(.*?)\s*brd'
	with open('interface.txt', 'r') as f:
		for line in f:
			intMACExtract = re.search(intMACPattern, line)
			if intMACExtract:
				interfaceMAC=intMACExtract.group(1)
	os.remove('interface.txt')

	if not interfaceMAC:
		print("MAC address not found for the interface ",args.interface,".", file=sys.stderr)
		exit()

#######################
# MAIN CODE
#######################

def main(): 

	# Store the user who initiated the script using sudo command 
	user = os.environ.get('SUDO_USER')

	if args.nodel:

		# Delete the previous folder
		if os.path.exists("CapturedPackets"):
			subprocess.run("sudo rm -R CapturedPackets", shell=True)

		if not os.path.isfile('ptnetinspector.py'):
			print("ptnetinspector not present. Exiting the script...")
			exit()
		# Run the bash script
		if args.mode == 'p':
			bash_captPackets = ["sudo","./captPackets.sh", args.mode, args.interface, interfaceMAC, str(args.pas_duration), str(args.pas_more)]
		elif args.mode == 'a':
			bash_captPackets = ["sudo","./captPackets.sh", args.mode, args.interface, interfaceMAC, str(args.act_more)]
		elif args.mode == 'a+':
			bash_captPackets = ["sudo","./captPackets.sh", args.mode, args.interface, interfaceMAC, str(args.agr_duration), str(args.prf), str(args.agr_period), str(args.dns_addr), str(args.agr_more)]

		#procBash = subprocess.run(bash_captPackets, capture_output=True, text=True)
		#ptnetinspectorEndTime = processTime(procBash.stdout)
		if args.debug:
			print("Starting bash script \'captPackets.sh\'...\n")
			print("Input parameters: ")
			print(args)
			print("Command sent to the script: ")
			print(bash_captPackets)
			procBash = subprocess.run(bash_captPackets)
			os.chown('./CapturedPackets', getpwnam(user).pw_uid, getpwnam(user).pw_gid)
		else:
			procBash = subprocess.run(bash_captPackets, capture_output=True, text=True)
			os.chown('./CapturedPackets', getpwnam(user).pw_uid, getpwnam(user).pw_gid)

		if os.path.getsize("./CapturedPackets/ptnetinspector_stderr.log") != 0:
			print("There was an error with ptnetisnpector. Please, check the \'ptnetinspector_stderr.log\' file.")
			exit()
		
		if procBash.returncode != 0:
			print(procBash)
			print("The \'captPackets.sh\' script did not run successfully. Exiting the code...")
			exit()
		
		else:
			if args.debug:
				print("Bash script \'captPackets.sh\' successfully finished... \n")
				print("Extracting the start time and end time of the ptnetinspector... \n")

			processTime()

	else:
		if os.path.getsize("./CapturedPackets/ptnetinspector_stderr.log") != 0:
			print("There was an error with ptnetisnpector. Please, check the \'ptnetinspector_stderr.log\' file.")
			exit()

		if args.debug:
				print("Extracting the start time and end time of the ptnetinspector... \n")
		processTime()

	# Process the captured packets and obtain unique devices
	if args.debug:
		print("Analysing all the packets to extract source MAC and IP addresses...\n")
	with open('./CapturedPackets/ALL_Packets.txt', 'r') as f:
		for line in f:
			if (checkTimeStamp(line)):
				macAddr = extractMac(line)
				extractSourceIP(line, macAddr)

	devPattern = r'Device number \d+:'
	devEndActivePattern = r'Active scan ended'
	devEndPassivePattern = r'Passive scan ended '
	devEndAggressivePattern = r'Aggressive scan ended'
	moreEndPattern = r'Time running'
	newDevice = False
	devAddrArr = []

	if args.debug:
		print("Analysing ptnetinspector results...\n")

	# Process ptnet output and obtain all the devices with their respective addresses
	with open('./CapturedPackets/ptnetOut.txt', 'r') as f:

		firstLine = f.readline().strip('\n')
		if checkPtnetOutErrors(firstLine):
				print("There is an error in the ptnetinspector...")
				print(firstLine)
				print("Exiting the program...")
				exit()

		for line in f:
			if (re.search(devPattern, line) and newDevice == False):
				newDevice = True
			elif(newDevice):
				if(re.search(devPattern, line)):
					extractAddrPtnet(devAddrArr)
					devAddrArr.clear()
				elif(re.search(devEndActivePattern, line) or re.search(devEndAggressivePattern, line) or re.search(devEndPassivePattern, line) or re.search(moreEndPattern, line)):
					newDevice = False
					extractAddrPtnet(devAddrArr)
					devAddrArr.clear()
					if (re.search(moreEndPattern, line)):
						break
				else:
					devAddrArr.append(line)

	if args.debug:
		print("Analysing MLDv1 and MLDv2 packets for addresses...\n")
	# Process MLDv1 and MLDv2 report messages
	with open('./CapturedPackets/MLD_report_Packets.txt', 'r') as f:
		for line in f:
			if (checkTimeStamp(line)):
				extractMLDaddresses(line)

	if args.debug:
		print("Analysing MDNS packets for addresses...\n")
	# Process MDNS messages
	with open('./CapturedPackets/MDNS_Packets.txt', 'r') as f:
		uniqNodeLines = str()
		firstLine = True
		fileNotEmpty = False
		pktTimeHigher = False
		uniqNode = r'^(\d{2}:\d{2}:\d{2}\.\d{6})'
		for line in f:
			fileNotEmpty = True
			if (re.match(uniqNode, line) and firstLine):
				if (checkTimeStamp(line)):
					uniqNodeLines += line
					firstLine = False
				else:
					pktTimeHigher = True
			elif (re.match(uniqNode, line) and not firstLine):
				pktTimeHigher = False

				if (checkTimeStamp(line)):
					extractMDNSaddresses(uniqNodeLines)
					uniqNodeLines = str()
					uniqNodeLines += line
				else:
					pktTimeHigher = True
			else:
				if pktTimeHigher:
					continue
				else:
					uniqNodeLines += line
		if fileNotEmpty:
			extractMDNSaddresses(uniqNodeLines)
			uniqNodeLines = str()


		#for line in f:
		#	if (checkTimeStamp(line)):
		#		extractMDNSaddresses(line)

	if args.debug:
		print("Analysing LLMNR packets for addresses...\n")
	# Process LLMNR messages
	with open('./CapturedPackets/LLMNR_Packets.txt', 'r') as f:
		uniqNodeLines = []
		firstLine = True
		fileNotEmpty = False
		pktTimeHigher = False
		uniqNode = r'^(\d{2}:\d{2}:\d{2}\.\d{6})'
		for line in f:
			fileNotEmpty = True
			if (re.match(uniqNode, line) and firstLine):
				if (checkTimeStamp(line)):
					uniqNodeLines.append(line)
					firstLine = False
				else:
					pktTimeHigher = True
			elif (re.match(uniqNode, line) and not firstLine):
				pktTimeHigher = False

				if (checkTimeStamp(line)):
					extractLLMNRaddresses(uniqNodeLines)
					uniqNodeLines.clear()
					uniqNodeLines.append(line)
				else:
					pktTimeHigher = True
			else:
				if pktTimeHigher:
					continue
				else:
					uniqNodeLines.append(line)
		if fileNotEmpty:
			extractLLMNRaddresses(uniqNodeLines)
			uniqNodeLines.clear()

	if args.debug:
		print("Setting possible IP addresses with XXXX... if they were not found during the communicaiton...\n")
	# Set possible IP addresses
	for dev in uniqDevObjCapt:
		for posAddr in uniqDevObjCapt[dev].get_possible_ip_addresses():
			if(loopThroughAddresses(uniqDevObjCapt[dev], posAddr)):
				continue
			if "::" in posAddr:
				addrWith0 = possibleAddressesMissed(posAddr)
				uniqDevObjCapt[dev].set_ip_addresses(addrWith0)
			else:
				addrWithX = possibleAddresses(posAddr)
				uniqDevObjCapt[dev].set_ip_addresses(addrWithX)
		if not args.debug:
			uniqDevObjCapt[dev].clear_possible_ip_addresses()

	with open('./CapturedPackets/CompareResults.txt', 'w') as f:

		print("####################### CAPTURED DEVICES")
		f.write("####################### CAPTURED DEVICES\n")
		for dev in uniqDevObjCapt:
			print("Device: ", uniqDevObjCapt[dev].get_macAddr())
			print("IP addresses: ", uniqDevObjCapt[dev].get_ip_addresses())
			if args.debug:
				print("Possible IP addresses: ", uniqDevObjCapt[dev].get_possible_ip_addresses())

			f.write("Device: {}\n".format(uniqDevObjCapt[dev].get_macAddr()))
			f.write("IP addresses: {}\n".format(uniqDevObjCapt[dev].get_ip_addresses()))
			if args.debug:
				f.write("Possible IP addresses: {}\n".format(uniqDevObjCapt[dev].get_possible_ip_addresses()))

		print("####################### OUTPUT OF PTNET")
		f.write("####################### OUTPUT OF PTNET\n")

		for dev in uniqDevObjPtnet:
			print("Device: ", uniqDevObjPtnet[dev].get_macAddr())
			print("IP addresses: ", uniqDevObjPtnet[dev].get_ip_addresses())

			f.write("Device: {}\n".format(uniqDevObjPtnet[dev].get_macAddr()))
			f.write("IP addresses: {}\n".format(uniqDevObjPtnet[dev].get_ip_addresses()))

		print("##############################################")
		f.write("##############################################\n")

		captOutBool = True
		ptnetOutBool = True

		print("##############")
		f.write("##############\n")

		print("Number of devices captured by the verifyAddresses script: ", len(uniqDevObjCapt))
		f.write("Number of devices captured by the verifyAddresses script: {}\n".format(len(uniqDevObjCapt)))
		print("Number of Addresses captured by the verifyAddresses script: ", sum(len(dev.get_ip_addresses()) for dev in uniqDevObjCapt.values()))
		f.write("Number of devices captured by the verifyAddresses script: {}\n".format(sum(len(dev.get_ip_addresses()) for dev in uniqDevObjCapt.values())))
		print("###")
		f.write("###\n")
		print("Number of devices captured by the ptnetinspector: ", len(uniqDevObjPtnet))
		f.write("Number of devices captured by the ptnetinspector: {}\n".format(len(uniqDevObjPtnet)))
		print("Number of Addresses captured by the ptnetinspector: ", sum(len(dev.get_ip_addresses()) for dev in uniqDevObjPtnet.values()))
		f.write("Number of Addresses captured by the ptnetinspector: {}\n".format(sum(len(dev.get_ip_addresses()) for dev in uniqDevObjPtnet.values())))

		print("##############")
		f.write("##############\n")

		print("\n##############")
		f.write("\n##############\n")

		# Compare captured results with ptnet output
		for dev in uniqDevObjCapt:
			if not dev in uniqDevObjPtnet:
				captOutBool = False
				print(dev, " was not captured by the ptNetInspector.")
				f.write("{} was not captured by the ptNetInspector.\n".format(dev))
				continue
			for addr in uniqDevObjCapt[dev].get_ip_addresses():
				if not addr in uniqDevObjPtnet[dev].get_ip_addresses():
					captOutBool = False
					print("The address ", addr, " was not captured by the ptNetInspector for the ", dev, " node.")
					f.write("The address {} was not captured by the ptNetInspector for the {} node.\n".format(addr, dev))
		if captOutBool and uniqDevObjCapt != {}:
			print("Every device and address captured was also found in the ptnet output.")
			f.write("Every device and address captured was also found in the ptnet output.\n")
		else:
			print("Some addresses were not found or the set is empty.")
			f.write("Some addresses were not found or the set is empty.\n")
		print("##############")
		print("\n##############")

		f.write("##############\n")
		f.write("\n##############\n")

		# Compare ptnet output with captured results
		for dev in uniqDevObjPtnet:
			if not dev in uniqDevObjCapt:
				ptnetOutBool = False
				print(dev, " was not found in the captured results.")
				f.write("{} was not found in the captured results.\n".format(dev))
				continue
			for addr in uniqDevObjPtnet[dev].get_ip_addresses():
				if not addr in uniqDevObjCapt[dev].get_ip_addresses():
					ptnetOutBool = False
					print("The address ", addr, " was not found in the captured results for the ", dev, " node.")
					f.write("The address {} was not found in the captured results for the {} node.\n".format(addr, dev))
		if ptnetOutBool and uniqDevObjPtnet != {}:
			print("Every device and address from the ptnet output was also found in the captured results.")
			f.write("Every device and address from the ptnet output was also found in the captured results.\n")
		else:
			print("Some addresses were not found or the set is empty.")
			f.write("Some addresses were not found or the set is empty.\n")
		print("##############")
		f.write("##############")

if __name__=="__main__": 
    main() 