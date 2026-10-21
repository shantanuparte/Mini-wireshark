package main

import (
	"fmt"
	// "log"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap" //sniffing packgets from air needs-> libpcap-devel
	// "github.com/google/gopacket/layers" //decoding
)

func smell_the_packets(net_inter, filter string, pack_size int) error {
	// max size, true gets network into promiscuous mode-> reads every package which is also not to our mac address. any is linux specific
	handle, err := pcap.OpenLive(net_inter, int32(pack_size), true, pcap.BlockForever)
	if err != nil {
		return fmt.Errorf("open live: %w", err)
	}
	defer handle.Close()

	if filter != "" {
		if err := handle.SetBPFFilter(filter); err != nil {
			return fmt.Errorf("set filter: %w", err)
		}

	}

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType()) //decodes everything
	for pack := range packetSource.Packets() {
		print_packet(pack)
	}

	return nil
}

func print_packet(pack gopacket.Packet) {

	

	metadata := pack.Metadata()

	fmt.Println(metadata)

}

func check_openlive_args(arg string) error {
	set := make(map[string]struct{})

	keywords := []string{"eth0", "wlan0", "any"}

	for _, v := range keywords {
		set[v] = struct{}{}
	}

	_, exist := set[arg]

	if exist == false {

		return fmt.Errorf("Invalid intwork interface")
	} else {
		return nil
	}

}
