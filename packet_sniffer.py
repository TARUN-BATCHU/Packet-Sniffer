import socket
import struct
import textwrap

# Ethernet
  		# 	IPV4
  		# 		data of ipv4
  		# 		data of ipv4
  		# 	    TCP
  		# 	      data of TCP
  		# 	      data of TCP

# To beautify
TAB_1 = '\t - '
TAB_2 = '\t\t - '
TAB_3 = '\t\t\t - '
TAB_4 = '\t\t\t\t - '

DATA_TAB_1 = '\t '
DATA_TAB_2 = '\t\t '
DATA_TAB_3 = '\t\t\t '
DATA_TAB_4 = '\t\t\t\t '

#socket connection
#last argument is it make sure that it compatable for all mechines 
def main():
	#The AF_PACKET socket in Linux allows an application to receive and send raw packets
    #AF_PACKET ---> is a address family constant for Low level packet interface 
    #A raw socket is a type of socket that allows access to the underlying transport provider
    #SOCK_RAW ----> Raw socket
    #The ntohs() function translates a short integer from network byte order to host byte order so that human can read
    conn = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
    print(TAB_1)
    print("=================START=================")
    print(TAB_1)
   
#runs forever
#looping forever and listening for packets when ever we see a packet take it and extract the information from it
    while True:
    #we were taking socket and when ever we see data we take it and store it in raw_data and address
    # the parameter passed into the method is buffer size
    #65565 is the mx buffer size     
        raw_data, addr = conn.recvfrom(6553)

# program Enough upto here to just see a raw packets 
# But human cant read or understand   


        #now we pass that data to ethernet_frame function 
        dest_mac, src_mac, eth_proto, data = ethernet_frame(raw_data)
        print('\nEthernet Frame:')
        print(TAB_1 + 'Destination: {}, Protocal: {}'.format(dest_mac, src_mac, eth_proto))
        
        # 8 is for IPV4
        if eth_proto == 8:
        	(version, header_length, ttl, proto, src, target, data) = ipv4_packet(data)
        	print(TAB_1 + 'IPV4 Packet:')
        	print(TAB_2 + 'version: {}, Header Length: {}, TTL: {}'.format(version, header_length, ttl))
        	print(TAB_2 + 'Protocal: {}, Source: {}, Target: {}'.format(proto, src, target))

		# 1 if for ICMP
			if  proto == 1:
				icmp_type, code, checksum, data = icmp_packet(data)
				print(TAB_1 + 'ICMP Packet:')
				print(TAB_2 + 'Type: {}, Code: {}, Checksum: {},'.format(icmp_type, code, checksum))
				print(TAB_2 + 'Data:')
				print(format_multi_line(DATA_TAB_3, data))

		# 6 is for TCP
			elif proto == 6:
				(src_prot, dest_port, sequence, acknowledgment, flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin)
				print(TAB_1 + 'TCP Segment:')
				print(TAB_2 + 'Source Port: {}, Destination Port: {}'.format(src_port, dest_port))
				print(TAB_2 + 'Sequence: {}, acknowledgment'.format(sequence, acknowledgment))
				print(TAB_2 + 'Flags:')
				print(TAB_3 + 'URG: {}, ACK: {}, PSH: {}, RST: {}, SYN: {}, FIN: {}'.format(flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin))
				print(TAB_2 + 'Data:')
				print(format_multi_line(DATA_TAB_3, data))

		# 17 is for UDP
			elif proto == 17:
				src_port, dest_port, length, data = udp_segment(data)
				print(TAB_1 + 'UDP Segment:')
				print(TAB_2 + 'Source Port: {}, Destination Port: {}'.format(src_port, dest_port))

		# for all other 
			else:
				print(TAB_1 + 'Data:')
				print(format_multi_line(DATA_TAB_2, data))chr
		else:
			print('Data:')
			print(format_multi_line(DATA_TAB_1, data))
				


# unpacking the ethernet frame
# Here when ever we see the o's and 1's going across the network we pass it in to this function
# then this function unpackes that frame and find what are those 1's & 0's
#this returns 4 different things 1>destination 2>source 3>ethernet type and 4>actual payload
#6s and 6s is destination and source MAC address of 1st 6 bytes and H is last unsigned short for ether type
def ethernet_frame(data):
	dest_mac, src_mac, proto = struct.unpack('! 6s 6s H', data[:14])
	return get_mac_addr(dest_mac), get_mac_addr(src_mac), socket.htons(proto), data[14:]

#This function will return the formated MAC address 
#some thing which looks like 00:11:22:33:44:55
def get_mac_addr(bytes_addr):
	bytes_str = map('{:02x}'.format, bytes_addr)
	return ':'.join(bytes_str).upper()


# now lets unpack those IPV4 packets 
# >> is shift to 4 characthers
def ipv4_packets(data):
	version_header_length = data[0]
	version = version_header_length >> 4
	#checks the length of the version_header_length is true or 
	header_length = (version_header_length & 15) * 4
	ttl, proto, src, traget = struct.unpack('! 8x B B 2x 4s 4s', data[:20])
	return version, header_length, ttl, proto, src, ipv4(src), ipv4(target), data[header_length:]


#returns properly formated IPV4 address
def ipv4(addr):
	# to return some thing like 127.234.367.1.9
	return '.'.join(map(str, addr)) 


# unpacks ICMP (Internet Control Message Comtrol Protocal) packets
def icmp_packets(data):
	icmp_type, code, checksum = struct.unpack('! B B H', data[:4])
	return icmp_type, code, checksum, data[4:]

#unpack TCP
# mostly most of the packets across the network were TCP like facebook insta etc...
def tcp_segment(data):
	(src_port, dest_port, sequence, acknowledgment, offset_reserved_flags) = struct.unpack('! H H L L H', data[:14])
	offset = (offset_reserved_flags >> 12) * 4
	flag_urg = (offset_reserved_flages & 32) >> 5
	flag_ack = (offset_reserved_flages & 16) >> 4
	flag_psh = (offset_reserved_flages & 8) >> 3
	flag_rst = (offset_reserved_flages & 4) >> 2
	flag_syn = (offset_reserved_flages & 2) >> 1
	flag_fin = offset_reserved_flages & 1
	return src_port, dest_port, sequence, acknowledgment, flag_fin, data[offset:]

#this function unpacks the udp packets
def udp_segment(data):
	src_port, dest_port, size = struct.unpack('! H H 2x H', data[:8])
	return src_port, dest_port, size, data[8:]

#this function is to formate the multile line data 
#in some cases we come across a large like 2000 10000 lines data then this function helps to break it line by line
def format_multi_line(prefix, string, size=80):
	size -= len(prefix)
	if isinstance(string, bytes):
		string = ''.join(r'\x{:02x}'.format(bytes) for bytes in string)
		if size % 2:
			size -= 1
	return '\n'.join([prefix + line for line in textwrap.wrap(string, size)])



# 	#ipv6 packet
# def ipv6Header(data, filter):
#     ipv6_first_word, ipv6_payload_legth, ipv6_next_header, ipv6_hoplimit = struct.unpack(">IHBB", data[0:8])
#     ipv6_src_ip = socket.inet_ntop(socket.AF_INET6, data[8:24])
#     ipv6_dst_ip = socket.inet_ntop(socket.AF_INET6, data[24:40])

#     bin(ipv6_first_word)
#     "{0:b}".format(ipv6_first_word)
#     version = ipv6_first_word >> 28
#     traffic_class = ipv6_first_word >> 16
#     traffic_class = int(traffic_class) & 4095
#     flow_label = int(ipv6_first_word) & 65535

#     ipv6_next_header = nextHeader(ipv6_next_header)
#     data = data[40:]

#     return data, ipv6_next_header


# def nextHeader(ipv6_next_header):
#     if (ipv6_next_header == 6):
#         ipv6_next_header = 'TCP'
#     elif (ipv6_next_header == 17):
#         ipv6_next_header = 'UDP'
#     elif (ipv6_next_header == 43):
#         ipv6_next_header = 'Routing'
#     elif (ipv6_next_header == 1):
#         ipv6_next_header = 'ICMP'
#     elif (ipv6_next_header == 58):
#         ipv6_next_header = 'ICMPv6'
#     elif (ipv6_next_header == 44):
#         ipv6_next_header = 'Fragment'
#     elif (ipv6_next_header == 0):
#         ipv6_next_header = 'HOPOPT'
#     elif (ipv6_next_header == 60):
#         ipv6_next_header = 'Destination'
#     elif (ipv6_next_header == 51):
#         ipv6_next_header = 'Authentication'
#     elif (ipv6_next_header == 50):
#         ipv6_next_header = 'Encapsuling'

#     return ipv6_next_header



main()