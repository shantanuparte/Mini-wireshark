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
	// duration := *dur
	// if duration < 0 {
	// 	start := time.Now()

	// }else{
	// 	start := time.Now().Add(time.Second * time.Duration(duration))
	// }



func smell_the_packets(ctx context.Context, net_inter, filter string, pack_size int, log bool, dis int) error {
	// max size, true gets network into promiscuous mode-> reads every package which is also not to our mac address. any is linux specific
	handle, err := pcap.OpenLive(net_inter, int32(pack_size), true, time.Millisecond*500)
	var cur <- chan time.Time
	
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

	if dis != -1 {
		cur = time.After(time.Duration(dis)* time.Second)	
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

			if (pack.TransportLayer()) != nil {
				statistics.Port[pack.TransportLayer().TransportFlow().Src().String()] += 1
			}

			if (pack.NetworkLayer()) != nil {

				statistics.Protocol[pack.NetworkLayer().NetworkFlow().Src().String()] += 1
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
