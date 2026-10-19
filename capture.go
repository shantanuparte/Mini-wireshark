package main

import (
	"fmt"
	"log"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap" //sniffing packgets from air(also get libpcap-devel as i dind't have that)
	// "github.com/google/gopacket/layers" //decoding
)

func smell_the_packets() error {

	fmt.Println("Smelling the packages....")

	// 1600 max size, true gets network into promiscuous mode-> reads every package which is also not to our mac address. any is linux specific

	handle, err := pcap.OpenLive("any", 1600, true, pcap.BlockForever)
	if err != nil {
		return fmt.Errorf("Error in openlive")
	}
	defer handle.Close()

	if err := handle.SetBPFFilter("tcp and port 80"); err != nil {
		return fmt.Errorf("Error in filter")
	}

	packet_src := gopacket.NewPacketSource(handle, handle.LinkType())

	for pack := range packet_src.Packets() {
		print_packet(pack)
	}

	return nil
}

func print_packet(pack gopacket.Packet) {

	log.Println(pack)

}
