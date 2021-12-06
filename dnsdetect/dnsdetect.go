package main

import (
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

func main() {
	parameters := os.Args[1:]

	//Reading arguments
	var (
		dnsdetectInterface string = ""
		dnsdetectFile      string = ""
		dnsdetectBPF       string = ""
	)

	for i := 0; i < len(parameters); {
		if parameters[i] == "-i" {
			dnsdetectInterface = parameters[i+1]
			i = i + 2
		} else if parameters[i] == "-r" {
			dnsdetectFile = parameters[i+1]
			i = i + 2
		} else {
			if dnsdetectBPF == "" {
				dnsdetectBPF = parameters[i]
			} else {
				dnsdetectBPF = dnsdetectBPF + " " + parameters[i]
			}
			i++
		}
	}

	if dnsdetectInterface == "" {
		devices, err := pcap.FindAllDevs()
		if err != nil {
			fmt.Println("Error while reading default interface. Exiting")
			os.Exit(3)
		}
		dnsdetectInterface = strings.TrimSpace(devices[0].Name)
	}

	var myHandler *pcap.Handle
	if dnsdetectFile != "" {
		var fileError error
		myHandler, fileError = pcap.OpenOffline(dnsdetectFile)

		if fileError != nil {
			fmt.Println("Error while opening file " + dnsdetectFile + ". Exiting")
			os.Exit(3)
		}
		defer myHandler.Close()
	} else {
		var captureError error
		myHandler, captureError = pcap.OpenLive(dnsdetectInterface, 65535, true, pcap.BlockForever)
		if captureError != nil {
			fmt.Println("Error while capturing from interface " + dnsdetectInterface + ". Exiting")
			os.Exit(3)
		}
		defer myHandler.Close()
	}

	//setting BPF filter
	if dnsdetectBPF == "" {
		dnsdetectBPF += "udp src port 53"
	} else {
		dnsdetectBPF += " and udp src port 53"
	}
	var bpfError error = myHandler.SetBPFFilter(dnsdetectBPF)

	if bpfError != nil {
		fmt.Println("Error while setting BPF filter " + dnsdetectBPF + ". Exiting")
		os.Exit(3)
	}

	fmt.Println("Interface: " + dnsdetectInterface)
	fmt.Println("File: " + dnsdetectFile)
	fmt.Println("BPF: " + dnsdetectBPF)

	var (
		answerL layers.DNSResourceRecord
		ethL    layers.Ethernet
		ipv4L   layers.IPv4
		udpL    layers.UDP
		dnsL    layers.DNS
	)

	decoder := gopacket.NewDecodingLayerParser(layers.LayerTypeEthernet, &ethL, &ipv4L, &udpL, &dnsL)
	// this slick will hold the names of the layers successfully decoded
	decodedLayers := make([]gopacket.LayerType, 0, 4)

	var (
		i              uint16
		threshold      int64 = 1000 //Milliseconds
		srcipv4Address net.IP
		srcudpP        layers.UDPPort
		srcethernetMac net.HardwareAddr
		dstipv4Address net.IP
		dstudpP        layers.UDPPort
		dstethernetMac net.HardwareAddr
		currPacketTime time.Time
	)

	//Creating Struct
	type infoPacket struct {
		srcIP         string
		dstIP         string
		srcPort       string
		dstPort       string
		srcMac        string
		dstMac        string
		txID          uint16
		qName         string
		payloadPacket string
		resIP         string
		timePacket    time.Time
	}
	//Hashmap
	infoPacketMap := make(map[uint16]infoPacket)
	//Reading packets
	filePackets := gopacket.NewPacketSource(myHandler, myHandler.LinkType())
	var spoofCheck bool = false
	//Iterating over the packets
	for packet := range filePackets.Packets() {

		// decode this packet using the fast decoder
		var err = decoder.DecodeLayers(packet.Data(), &decodedLayers)
		if err != nil {
			fmt.Println("Decoding error!", err)
			continue
		}

		// only proceed if all layers decoded
		if len(decodedLayers) != 4 {
			fmt.Println("Not enough layers decoded")
			continue
		}

		// check that this is a response
		if !dnsL.QR {
			continue
		}

		currPacketTime = packet.Metadata().Timestamp

		srcethernetMac = ethL.SrcMAC
		dstethernetMac = ethL.DstMAC

		srcipv4Address = ipv4L.SrcIP
		dstipv4Address = ipv4L.DstIP

		srcudpP = udpL.SrcPort
		dstudpP = udpL.DstPort

		newPacketInfo := infoPacket{}
		newPacketInfo.payloadPacket = string(ipv4L.LayerPayload())
		newPacketInfo.srcIP = srcipv4Address.String()
		newPacketInfo.dstIP = dstipv4Address.String()
		newPacketInfo.srcMac = srcethernetMac.String()
		newPacketInfo.dstMac = dstethernetMac.String()
		newPacketInfo.srcPort = srcudpP.String()
		newPacketInfo.dstPort = dstudpP.String()
		newPacketInfo.timePacket = currPacketTime
		newPacketInfo.txID = dnsL.ID
		var isFirst bool = false
		var finalQuery = ""
		for _, dnsQuestion := range dnsL.Questions {
			finalQuery = string(dnsQuestion.Name)
			var finalResponse = ""
			for i = 0; i < dnsL.ANCount; i++ {
				// get the answer
				answerL = dnsL.Answers[i]
				// verify this is an A-IN record question
				if answerL.Type != layers.DNSTypeA || answerL.Class != layers.DNSClassIN {
					continue
				}
				if !isFirst {
					finalResponse += strings.TrimSpace(answerL.IP.String())
					isFirst = true
				} else {
					finalResponse = finalResponse + ", " + strings.TrimSpace(answerL.IP.String())
				}
			}
			newPacketInfo.resIP = finalResponse
			newPacketInfo.qName = finalQuery

			oldPacketInfo, isok := infoPacketMap[dnsL.ID]
			if !isok {
				infoPacketMap[dnsL.ID] = newPacketInfo
			} else {
				timeDiff := newPacketInfo.timePacket.Sub(oldPacketInfo.timePacket)
				if timeDiff.Milliseconds() > threshold {
					fmt.Println("Time difference", timeDiff.Milliseconds(), "to check for TXID 0x"+strconv.FormatUint(uint64(dnsL.ID), 16), "is greater than threshold", threshold, "milliseconds")
					infoPacketMap[dnsL.ID] = newPacketInfo
					continue
				} else {
					if oldPacketInfo.dstIP == newPacketInfo.dstIP &&
						oldPacketInfo.dstMac == newPacketInfo.dstMac &&
						oldPacketInfo.dstPort == newPacketInfo.dstPort &&
						oldPacketInfo.qName == newPacketInfo.qName &&
						oldPacketInfo.srcPort == newPacketInfo.srcPort &&
						oldPacketInfo.srcIP == newPacketInfo.srcIP &&
						oldPacketInfo.resIP != newPacketInfo.resIP {
						var fields = strings.Fields(newPacketInfo.timePacket.String())
						fmt.Printf(fields[0] + " " + fields[1])
						fmt.Println(" DNS poisoning attempt")
						fmt.Print("TXID 0x" + strconv.FormatUint(uint64(newPacketInfo.txID), 16))
						fmt.Println(" Request:", newPacketInfo.qName)
						fmt.Println("Answer1:", "[", oldPacketInfo.resIP, "]")
						fmt.Println("Answer2:", "[", newPacketInfo.resIP, "]")
						spoofCheck = true
					} else {
						fmt.Println("TXID 0x" + strconv.FormatUint(uint64(dnsL.ID), 16) + " is matched but not a spoof attack")
					}
					infoPacketMap[dnsL.ID] = newPacketInfo
				}
			}
		}
	}
	if !spoofCheck {
		fmt.Println("No Spoof found!!")
	}

}
