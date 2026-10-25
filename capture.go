package main

import (
	"context"
	"fmt"
	"time"

	// "log"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap" //sniffing packgets from air needs-> libpcap-devel
)

var statistics = stat{
	Protocol: make(map[string]int),
	Port:     make(map[string]int),
}

func smell_the_packets(ctx context.Context, net_inter, filter string, pack_size int, log bool, dis int) error {
	// max size, true gets network into promiscuous mode-> reads every package which is also not to our mac address. any is linux specific
	handle, err := pcap.OpenLive(net_inter, int32(pack_size), true, time.Millisecond*500)
	var cur <-chan time.Time

	if err != nil {
		return fmt.Errorf("open live: %w", err)
	}
	defer handle.Close()

	if filter != "" {
		if err := handle.SetBPFFilter(filter); err != nil {
			return fmt.Errorf("set filter: %w", err)
		}

	}

	if log {
		log_file_inicilization(handle.LinkType(), uint32(handle.SnapLen())) // cause flags refer default value to 65k but if user add specific one then it should match
	}
	const rowFmt = "%-8s %-28s -> %s\n"

	var timer *time.Timer
	if dis >= 0 {
		timer = time.NewTimer(time.Duration(dis) * time.Second)
		defer timer.Stop()
		cur = timer.C
	}

	fmt.Printf(rowFmt, "PROTO", "SOURCE_IP:PORT", "DESTINATION_IP:PORT")
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType()) //decodes everything
	for {
		select {
		case <-ctx.Done():
			print_stat(&statistics)
			return nil

		case <-cur:
			print_stat(&statistics)
			return nil

		case pack, ok := <-packetSource.Packets():
			if !ok {
				return nil
			}

			if log {
				write_package(pack.Data(), *pack.Metadata())
			}

			if transport := pack.TransportLayer(); transport != nil {
				statistics.Port[transport.TransportFlow().Src().String()]++
			}

			if netLayer := pack.NetworkLayer(); netLayer != nil {
				statistics.Protocol[netLayer.LayerType().String()]++
			}

			statistics.Bytes += len(pack.Data())
			statistics.Total_pack += 1
			print_packet(pack)

		}

	}

}

func print_packet(pack gopacket.Packet) {

	src, dst := "unknown", "unknown"
	protocol := "Others"

	if netLayer := pack.NetworkLayer(); netLayer != nil {
		//osi model lol
		flow := netLayer.NetworkFlow() //ip layer
		src = flow.Src().String()
		dst = flow.Dst().String()

	}

	if transport := pack.TransportLayer(); transport != nil {
		protocol = transport.LayerType().String()

		src += ":" + transport.TransportFlow().Src().String()
		dst += ":" + transport.TransportFlow().Dst().String()

	}

	fmt.Printf("%-8s %-28s -> %s\n", protocol, src, dst)

}

func check_openlive_args(arg string) error {

	// any is linux specific
	if arg == "any" {
		return nil
	}

	devices, err := pcap.FindAllDevs()
	if err != nil {
		return fmt.Errorf("find interfaces %w", err)
	}

	for _, devices := range devices {
		if devices.Name == arg {
			return nil

		}
	}

	return fmt.Errorf("unknown network interfaces: %s", arg)
}

func jaw_function() error {
	pcap_file := "capture.pcap"
	handle, err := pcap.OpenOffline(pcap_file)
	if err != nil {
		return fmt.Errorf("open pcap: %w", err)
	}
	defer handle.Close()

	fmt.Printf("%-26s %-8s %-6s %-6s %-28s -> %s\n",
		"TIMESTAMP", "PROTO", "CAPLEN", "LEN", "SOURCE_IP:PORT", "DESTINATION_IP:PORT")

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for pack := range packetSource.Packets() {
		print_packet_with_meta(pack)
	}
	return nil
}

func print_packet_with_meta(pack gopacket.Packet) {
	src, dst := "unknown", "unknown"
	protocol := "Others"

	if netLayer := pack.NetworkLayer(); netLayer != nil {
		flow := netLayer.NetworkFlow()
		src = flow.Src().String()
		dst = flow.Dst().String()
	}

	if transport := pack.TransportLayer(); transport != nil {
		protocol = transport.LayerType().String()
		src += ":" + transport.TransportFlow().Src().String()
		dst += ":" + transport.TransportFlow().Dst().String()
	}

	meta := pack.Metadata() // *gopacket.PacketMetadata (embeds CaptureInfo)

	fmt.Printf("%-26s %-8s %-6d %-6d %-28s -> %s\n",
		meta.Timestamp.Format("2006-01-02 15:04:05.000"),
		protocol,
		meta.CaptureLength, // bytes actually saved in the file
		meta.Length,        // original size on the wire
		src, dst)
}
