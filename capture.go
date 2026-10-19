package main

import (
	"fmt"
	"hash"

	// "github.com/google/gopacket"
	"github.com/google/gopacket/pcap" //sniffing packgets from air(also get libpcap-devel as i dind't have that)
	// "github.com/google/gopacket/layers" //decoding
)


func smell_the_packets(){

	fmt.Println("Smelling the packages....")

	// 1600 max size, true gets network into promiscuous mode-> reads every package which is also not to our mac address
	if handle, err := pcap.OpenLive("eth0",1600, true,pcap.BlockForever);err!=nil{
		fmt.Errorf("Error in open live")
	}else if err := handle.bp

	


}