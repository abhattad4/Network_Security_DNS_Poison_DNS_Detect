Report - HW3
CSE 508 Network Security

Name: Abhishek Bhattad
SBU ID: 113277131

This report is regarding the successful completion of Homework 3 DNS Poisoning and Detecting. Along with this report, I am submitting two folders, one for dnspoisoning (spoofing) and another for dns detector (spoof detector) where all the code (dnspoison.go and dnsdetect.go),hostname file and pcap files used are present. The go version used is go1.16.2.
Below are the command line arguments/flags which need to be supported. The program doesn’t necessarily require the sequence of arguments and will run even if the arguments are shuffled. If an invalid argument is provided it will throw an error. All the arguments are optional and the code will run and listen on the first default interface for all the types of packets.


PART A ==> go run dnspoison.go [-i interface] [-f hostnames] expression

[-i interface]: if provided with the -i flag, it takes the immediate next argument as an interface input. If not provided, it will search for all the available interfaces and take the first interface. e.g.  eth0, ens33, etc. IP address is extracted from the same interface. The packets are captured from the interface in promiscuous mode. All the incoming packets will be spoofed if -f file is not provided

[-f hostnames]: if provided with the -f flag, it takes the next argument as a file name from where the hostnames and their corresponding spoofed IP will be read. File needs to be present in the same folder as dnspoison.go file. If an invalid file is provided, it will throw an error.

expression (Default filter applied is udp dst port 53): expression is a BPF filter that is applied for packet filtering. It takes the BPF filter in the same way you do it for tcpdump. The filter doesn’t need to be specified in quotes. It will work without it as well like in the case of tcpdump (e.g. src host 192.168.0.1).

Below is the code implementation flow:
	1. The arguments are read at the start and filtered based on how many arguments are provided and if any defaults are to be used.
	2. Packet reading and the iterating over each packet to extract information.
	3. Four layers are extracted namely ethernet, ip, udp and dns. Information is extracted to create a spoof packet.
	4. If multiple queries are present in a single dns packet, multiple responses will be sent in the same packet i.e. one for each query.
	5. Corner case where in a single packet one query matches the hostname in file and others don't. By default server's ip address is sent.
	6. Once packet is created it is sent using the same interface created above.
	
	

PART B ==> go run dnsdetect.go [-i interface] [-r tracefile] expression

[-i interface]: if provided with the -i flag, it takes the immediate next argument as an interface input. If not provided, it will search for all the available interfaces and take the first interface. e.g.  eth0, ens33, etc. The packets are captured from the interface in promiscuous mode. All the incoming packets will be check for spoofing.

[-r tracefile]: if provided with the -r flag, it takes the next argument as a pcap file name from where all the packets will be read and checked for spoofing. File needs to be present in the same folder as dnsdetect.go file. If an invalid file is provided, it will throw an error. If both -i and -r flags are provided, priority is given to -r flag.

expression (Default filter applied is udp src port 53): expression is a BPF filter that is applied for packet filtering. It takes the BPF filter in the same way you do it for tcpdump. The filter doesn’t need to be specified in quotes. It will work without it as well like in the case of tcpdump (e.g. src host 192.168.0.1).

Below is the code implementation flow:
	1. The arguments are read at the start and filtered based on how many arguments are provided and if any defaults are to be used.
	2. Packet reading and the iterating over each packet to extract information.
	3. Four layers are extracted namely ethernet, ip, udp and dns. Information is extracted to detect for spoof packets.
	4. I have used a HashMap (TXID -> Struct) data structure, where my Struct object contains all the info related to dns packet like srcPort, srcIP, dstPort, dstMac, dstIP, response IP, question Name, time, etc. If the packet with same TXID id comes I will check for few parameters to determine if the old and new packet are spoofed or false positives. False positives for same TXID and different queries are avoided my checking question name
	5. To avoid false positives for load balancers or different packet with same TXID, I have used time as a threshold to determine if the packet should be considered for spoofing or not. Because it's a spoof attack it should come fast or within some specified time. In code I have configured this threshold as 1000 ms i.e. 1 sec. It's configurable.
	6. If a packet is detected as a spoof packet, the information described in the problem statement is printed. I am priting Request (URL) and Answers (List of IPs)
	7. If spoof packet is not detected in a file, then no spoof is printed and the code terminates. If it's interface, then it will listen indefinitely. 

References:
https://pkg.go.dev/github.com/google/gopacket@v1.1.19/pcap
https://github.com/troyxmccall/gogospoofdns/blob/master/spoof.go
https://www.devdungeon.com/content/packet-capture-injection-and-analysis-gopacket


Below are the few sample outputs. I created few pcap files using dnspoison code and the same pcap files are used to display the output for dnsdetect.

Example 1:
root@ubuntu:/home/abhattad4/Downloads/detectnetsec# go run dnsdetect.go -r hw3.pcap
Interface: ens33
File: hw3.pcap
BPF: udp src port 53
2021-04-04 21:09:17.2657 DNS poisoning attempt
TXID 0xcf6f Request: www.bankofamerica.com
Answer1: [ 171.159.116.100 ]
Answer2: [ 192.168.29.128 ]
2021-04-04 21:09:44.035033 DNS poisoning attempt
TXID 0xed49 Request: www.cs.stonybrook.edu
Answer1: [ 192.168.66.6 ]
Answer2: [ 23.185.0.2 ]
root@ubuntu:/home/abhattad4/Downloads/detectnetsec# 

Example 2:
root@ubuntu:/home/abhattad4/Downloads/detectnetsec# go run dnsdetect.go -r t1hw3.pcap -i ens33
Interface: ens33
File: t1hw3.pcap
BPF: udp src port 53
2021-04-04 21:13:26.977132 DNS poisoning attempt
TXID 0x13dc Request: www.bankofamerica.com
Answer1: [ 171.159.116.100 ]
Answer2: [ 192.168.29.128 ]
2021-04-04 21:14:12.225373 DNS poisoning attempt
TXID 0xc142 Request: www.tcpdump.org
Answer1: [ 192.139.46.66, 159.89.89.188 ]
Answer2: [ 192.168.29.128 ]
2021-04-04 21:14:37.659877 DNS poisoning attempt
TXID 0xdd0a Request: foo.example.com
Answer1: [ 10.6.6.6 ]
Answer2: [  ]
2021-04-04 21:14:52.219196 DNS poisoning attempt
TXID 0xb7c8 Request: www.cs.stonybrook.edu
Answer1: [ 192.168.66.6 ]
Answer2: [ 23.185.0.2 ]
root@ubuntu:/home/abhattad4/Downloads/detectnetsec# 

Example 3:
root@ubuntu:/home/abhattad4/Downloads/detectnetsec# go run dnsdetect.go -r hw1.pcap -i ens33
Interface: ens33
File: hw1.pcap
BPF: udp src port 53
No Spoof found!!
root@ubuntu:/home/abhattad4/Downloads/detectnetsec# 

Example 4:
root@ubuntu:/home/abhattad4/Downloads/detectnetsec# go run dnsdetect.go -r poison.pcap -i ens33
Interface: ens33
File: poison.pcap
BPF: udp src port 53
2021-04-05 19:52:46.389092 DNS poisoning attempt
TXID 0x7ac8 Request: www.google.com
Answer1: [ 192.168.29.128 ]
Answer2: [ 172.217.6.196 ]
2021-04-05 19:52:47.162799 DNS poisoning attempt
TXID 0x305f Request: beacons.gcp.gvt2.com
Answer1: [ 192.168.29.128 ]
Answer2: [ 172.217.3.99 ]
2021-04-05 19:52:47.951359 DNS poisoning attempt
TXID 0x72a Request: www.flipkart.com
Answer1: [ 192.168.29.128 ]
Answer2: [ 163.53.78.110 ]
2021-04-05 19:52:48.623188 DNS poisoning attempt
TXID 0x427b Request: static-assets-web.flixcart.com
Answer1: [ 192.168.29.128 ]
Answer2: [ 23.219.94.213 ]
2021-04-05 19:52:49.174711 DNS poisoning attempt
TXID 0x3dad Request: www.gstatic.com
Answer1: [ 192.168.29.128 ]
Answer2: [ 172.217.10.67 ]
2021-04-05 19:52:49.840125 DNS poisoning attempt
TXID 0xa054 Request: beacons.gvt2.com
Answer1: [ 192.168.29.128 ]
Answer2: [ 172.217.6.195 ]
2021-04-05 19:52:51.811811 DNS poisoning attempt
TXID 0x34c5 Request: beacons2.gvt2.com
Answer1: [ 192.168.29.128 ]
Answer2: [ 172.217.167.163 ]
2021-04-05 19:52:53.237705 DNS poisoning attempt
TXID 0x3f79 Request: beacons3.gvt2.com
Answer1: [ 192.168.29.128 ]
Answer2: [ 172.217.11.3 ]
2021-04-05 19:52:53.503246 DNS poisoning attempt
TXID 0x72b1 Request: codex.nflxext.com
Answer1: [ 192.168.29.128 ]
Answer2: [ 45.57.91.1, 45.57.90.1 ]
2021-04-05 19:52:53.503252 DNS poisoning attempt
TXID 0xfeb2 Request: assets.nflxext.com
Answer1: [ 192.168.29.128 ]
Answer2: [ 45.57.91.1, 45.57.90.1 ]
2021-04-05 19:52:53.773044 DNS poisoning attempt
TXID 0xff78 Request: www.netflix.com
Answer1: [ 192.168.29.128 ]
Answer2: [ 54.160.93.182, 3.225.92.8, 3.211.157.115 ]
2021-04-05 19:52:53.773053 DNS poisoning attempt
TXID 0xf9da Request: cdn.cookielaw.org
Answer1: [ 192.168.29.128 ]
Answer2: [ 104.16.149.64, 104.16.148.64 ]
2021-04-05 19:52:55.841651 DNS poisoning attempt
TXID 0xbb79 Request: beacons4.gvt2.com
Answer1: [ 192.168.29.128 ]
Answer2: [ 216.239.32.116 ]
2021-04-05 19:52:57.020025 DNS poisoning attempt
TXID 0x874f Request: beacons5.gvt2.com
Answer1: [ 192.168.29.128 ]
Answer2: [ 216.239.32.116 ]
2021-04-05 19:52:58.393013 DNS poisoning attempt
TXID 0xa732 Request: beacons5.gvt3.com
Answer1: [ 192.168.29.128 ]
Answer2: [ 172.217.6.195 ]
2021-04-05 19:52:59.275639 DNS poisoning attempt
TXID 0x7718 Request: www.amazon.com
Answer1: [ 192.168.29.128 ]
Answer2: [ 13.225.212.37 ]
2021-04-05 19:53:00.2031 DNS poisoning attempt
TXID 0xf8d Request: clients2.google.com
Answer1: [ 192.168.29.128 ]
Answer2: [ 172.217.165.142 ]
2021-04-05 19:53:05.843873 DNS poisoning attempt
TXID 0x4c2b Request: google.com
Answer1: [ 192.168.29.128 ]
Answer2: [ 172.217.11.14 ]
2021-04-05 19:53:09.205219 DNS poisoning attempt
TXID 0x9791 Request: www.cs.stonybroo.edu
Answer1: [ 192.168.29.128 ]
Answer2: [  ]
2021-04-05 19:53:19.845701 DNS poisoning attempt
TXID 0x692 Request: www.cs.stonybrook.edu
Answer1: [ 192.168.29.128 ]
Answer2: [ 23.185.0.2 ]
2021-04-05 19:53:26.181838 DNS poisoning attempt
TXID 0xd88a Request: www.tcpdump.org
Answer1: [ 192.168.29.128 ]
Answer2: [ 192.139.46.66, 159.89.89.188 ]
2021-04-05 19:53:32.229559 DNS poisoning attempt
TXID 0x7997 Request: www.bankofamerica.com
Answer1: [ 192.168.29.128 ]
Answer2: [ 171.161.100.100 ]
2021-04-05 19:53:39.206831 DNS poisoning attempt
TXID 0xf7c4 Request: www.citibank.com
Answer1: [ 192.168.29.128 ]
Answer2: [ 104.107.45.29 ]
TXID 0x5c6 is matched but not a spoof attack
2021-04-05 19:56:18.77949 DNS poisoning attempt
TXID 0x1365 Request: www.irctc.com
Answer1: [ 192.168.29.128 ]
Answer2: [ 103.116.163.23 ]
TXID 0x609e is matched but not a spoof attack
2021-04-05 20:01:22.330908 DNS poisoning attempt
TXID 0xf8a9 Request: teredo.ipv6.microsoft.com
Answer1: [  ]
Answer2: [ 192.168.29.128 ]
2021-04-05 20:01:44.372644 DNS poisoning attempt
TXID 0x9b90 Request: www.gstatic.com
Answer1: [ 192.168.29.128 ]
Answer2: [ 172.217.10.67 ]
2021-04-05 20:01:46.477379 DNS poisoning attempt
TXID 0x349f Request: www.cs.stonybrook.edu
Answer1: [ 192.168.29.128 ]
Answer2: [ 23.185.0.2 ]
2021-04-05 20:03:59.063704 DNS poisoning attempt
TXID 0x3bf8 Request: beacons.gcp.gvt2.com
Answer1: [ 192.168.29.128 ]
Answer2: [ 172.217.3.99 ]
2021-04-05 20:04:09.555076 DNS poisoning attempt
TXID 0xb557 Request: beacons2.gvt2.com
Answer1: [ 192.168.29.128 ]
Answer2: [ 172.217.6.227 ]
2021-04-05 20:04:15.984025 DNS poisoning attempt
TXID 0x6594 Request: clients2.google.com
Answer1: [ 192.168.29.128 ]
Answer2: [ 172.217.165.142 ]
2021-04-05 20:04:19.75451 DNS poisoning attempt
TXID 0x4a40 Request: beacons3.gvt2.com
Answer1: [ 192.168.29.128 ]
Answer2: [ 172.217.10.131 ]
2021-04-05 20:04:19.960826 DNS poisoning attempt
TXID 0x29fb Request: beacons5.gvt2.com
Answer1: [ 192.168.29.128 ]
Answer2: [ 216.239.32.116 ]
2021-04-05 20:04:31.229166 DNS poisoning attempt
TXID 0xdbad Request: beacons5.gvt3.com
Answer1: [ 192.168.29.128 ]
Answer2: [ 172.217.11.35 ]
2021-04-05 20:04:41.167796 DNS poisoning attempt
TXID 0x45df Request: beacons.gvt2.com
Answer1: [ 192.168.29.128 ]
Answer2: [ 172.217.6.195 ]
2021-04-05 20:04:53.970899 DNS poisoning attempt
TXID 0x3a30 Request: google.com
Answer1: [ 192.168.29.128 ]
Answer2: [ 172.217.11.14 ]
2021-04-05 20:04:58.993864 DNS poisoning attempt
TXID 0xb8b Request: beacons4.gvt2.com
Answer1: [ 192.168.29.128 ]
Answer2: [ 216.239.32.116 ]
TXID 0xa46b is matched but not a spoof attack
2021-04-05 20:06:11.331155 DNS poisoning attempt
TXID 0x58dc Request: wpad.localdomain
Answer1: [ 192.168.29.128 ]
Answer2: [  ]
2021-04-05 20:06:11.391062 DNS poisoning attempt
TXID 0x3443 Request: sqm.microsoft.com
Answer1: [  ]
Answer2: [ 192.168.29.128 ]
2021-04-05 20:06:41.198461 DNS poisoning attempt
TXID 0x7cd2 Request: www.google.com
Answer1: [ 192.168.29.128 ]
Answer2: [ 172.217.6.196 ]
2021-04-05 20:06:46.933825 DNS poisoning attempt
TXID 0xa65c Request: www.tcpdump.org
Answer1: [ 192.168.29.128 ]
Answer2: [ 192.139.46.66, 159.89.89.188 ]
root@ubuntu:/home/abhattad4/Downloads/detectnetsec# 
