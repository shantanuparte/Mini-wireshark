package main

import (
	"context"
	"fmt"

	// "log"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap" //sniffing packgets from air needs-> libpcap-devel
)

func smell_the_packets(ctx context.Context, net_inter, filter string, pack_size int, log bool) error {
	// max size, true gets network into promiscuous mode-> reads every package which is also not to our mac address. any is linux specific
	handle, err := pcap.OpenLive(net_inter, int32(pack_size), true, pcap.BlockForever)
	if err != nil {
		return fmt.Errorf("open live: %w", err)
	}
	defer handle.Close()

	stop_capture := context.AfterFunc(ctx, func() {
		handle.Close()
	})
	defer stop_capture()

	if filter != "" {
		if err := handle.SetBPFFilter(filter); err != nil {
			return fmt.Errorf("set filter: %w", err)
		}

	}

	if log {
		log_file_inicilization(handle.LinkType())
	}
	const rowFmt = "%-8s %-28s -> %s\n"

	fmt.Printf(rowFmt, "PROTO", "SOURCE_IP:PORT", "DESTINATION_IP:PORT")
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType()) //decodes everything
	for {
		select {
		case <-ctx.Done():
			return nil

		case pack, ok := <-packetSource.Packets():
			if !ok {
				return nil
			}

			if log {
				write_package(pack.Data(), *pack.Metadata())
			}

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
