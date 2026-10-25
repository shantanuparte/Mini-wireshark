package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
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

	_, err := log_file.Write(pack_data)
	if err != nil {
		log.Printf("Error in writing package: %v\n", err)
	}

}

func graceful_term() (context.Context, context.CancelFunc){

	//contex -> signal handling
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	
	defer stop()

	fmt.Println("Application running")

	<-ctx.Done()

	fmt.Println("Shutdown signal recived")

	return ctx, stop

}
