package main

import (
	"flag"
	"fmt"
)

func main() {
	fmt.Println("Hello amigo's")
	fmt.Println("We're going to sniff some packages")

	//flags to implement
	// list := flag.String("list", "", "To get list of network interfaces")
	// host := flag.String("host", "", "Sort by the host ip")
	// port := flag.String("port", "", "Sort by the port")

	flag.Parse()

	err := smell_the_packets()
	if err != nil {
		panic(err)
	}
	

}
