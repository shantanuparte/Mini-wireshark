package main

import (
	"flag"
	"fmt"
	"os"
	"time"
)

func main() {

	// flags to implement(values are pointer lol)
	net_inter := flag.String("list", "any", "To get list of network interfaces")
	filter := flag.String("filter", "", "filter the packets you want")
	pack_size := flag.Int("pack_size", 65535, "The size of packge upto you wanna search")
	log := flag.Bool("log", false, "Set the value to true if you want a log file")
	dur := flag.Int("dur", -1, "How much time you wanna run the program")
	jaw := flag.Bool("jaw", false, "To read the pcap file")

	flag.Usage = func() {
			fmt.Println("WELCOME TO MINI WIRESHARK")
		fmt.Println("./wireshark has these Usage and filters")
		fmt.Println("Usage-> Read the packets and store them in file:")
		fmt.Println("1.filter -> can take arugmets for selecting protocol host ip etc. see SetBPFFilter arguemnts online for all")
		fmt.Println("2.log -> bool value of you want a .pcap file with which has all the records (default flase)")
		fmt.Println("3.time -> how to seocnds you wanna sniff packeges")
		fmt.Println("4.list->pariticular network interface like 'eth0'")
		fmt.Println("5.pack_size -> size of package you wanna search (default 65535)")
		fmt.Println()
		fmt.Println("Usage->Read .pcap file:")
		fmt.Println("jaw -> the .pacp file output")
	}
	flag.Parse()

	ctx, stop := graceful_term()
	defer stop()

	start := time.Now()

	if *jaw {
		if err := jaw_function(); err != nil {
			fmt.Println(err)
			return
		}
	} else {
		err := check_openlive_args(*net_inter)
		if err != nil {
			fmt.Printf("%v", err)
			return
		}
		err = smell_the_packets(ctx, *net_inter, *filter, *pack_size, *log, *dur)
		if err != nil {
			if log_file != nil {
				log_file.Close()
			}
			fmt.Fprintln(os.Stderr, "error:", err)
			os.Exit(1)
		}

	}

	if log_file != nil {
		if err := log_file.Close(); err != nil {
			fmt.Printf("Error closing pcap file %v\n", err)
		}
	}

	duration := time.Since(start)
	fmt.Printf("\nThe Program ran for %v\n\n", duration)

}



