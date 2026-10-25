package main

import (
	"flag"
	"fmt"
)

func main() {
	fmt.Println("Hello amigo's")
	fmt.Println("We're going to sniff some packages")

	// flags to implement(values are pointer lol)
	net_inter := flag.String("list", "any", "To get list of network interfaces")
	filter := flag.String("filter", "", "filter the packets you want")
	pack_size := flag.Int("pack_size", 65535, "The size of packge upto you wanna search")
	log := flag.Bool("log", false, "Set the value to true if you want a log file")

	flag.Parse()

	err := check_openlive_args(*net_inter)
	if err != nil {
		fmt.Printf("%v", err)
		return
	}

	err = smell_the_packets(*net_inter,*filter,*pack_size,*log)
	if err != nil {
		panic(err)
	}


	

}
