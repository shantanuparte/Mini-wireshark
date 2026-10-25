package main

import (
	"context"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers" //decoding
	"github.com/google/gopacket/pcapgo" //writing pcap packets
)

// pointer cause every function creates it's own copy if we didn't and it'll --
var log_file *os.File
var pcapWriter *pcapgo.Writer

func log_file_inicilization(link_type layers.LinkType) {
	var err error
	log_file, err = os.OpenFile("capture.pcap", os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0664) //.pcap is network packet file for storing packets
	if err != nil {
		log.Fatalf("Failed to initilize the pcap file %v", err)
	}

	pcapWriter = pcapgo.NewWriter(log_file)

	err = pcapWriter.WriteFileHeader(65536, link_type)
	if err != nil {
		log.Fatalf("Failed to wirte %v", err)
	}

}

func write_package(pack_data []byte, metadata gopacket.PacketMetadata) {

	if log_file == nil { //skip wirting if the log is flase.
		return
	}

	pack_info := gopacket.CaptureInfo{
		Timestamp:     metadata.Timestamp,
		CaptureLength: len(pack_data),
		Length:        metadata.Length,
	}

	err := pcapWriter.WritePacket(pack_info, pack_data)
	if err != nil {
		log.Printf("Error in writingot pcap file: %v", err) //it doesn't support %w why
	}
}

func graceful_term() (context.Context, context.CancelFunc) {

	//contex -> signal handling
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)

	return ctx, stop

}





