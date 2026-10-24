package main

import (
	"log"
	"os"
)

var log_file *os.File

func log_file_inicilization() {
	var err error
	log_file, err = os.OpenFile("out.pcap", os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0664) //.pcap is network packet file for storing packets
	if err != nil {
		log.Fatalf("Failed to initilize the log file %v", err)
	}

}

func write_package(pack_data []byte) {

}
