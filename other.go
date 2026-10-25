package main

import (
	"fmt"
	"slices"
)

// "fmt"

type stat struct {
	Total_pack int
	Bytes      int
	Protocol   (map[string]int)
	Port       map[string]int
}

type entry struct {
	Key   string
	Value int
}

func print_stat(s *stat) {
	fmt.Printf("\nTotal packets sniffed: %v", s.Total_pack)
	fmt.Printf("\nTotal KB captured: %v", s.Bytes/1024)
	fmt.Printf("\nTop 3 Protocols")
	upper3(&s.Protocol)
	fmt.Printf("\nTop 3 Ports:")
	upper3(&s.Port)
}

func upper3(m *map[string]int) {

	var list []entry

	for k, v := range *m {
		list = append(list, entry{Key: k, Value: v})

	}
	slices.SortFunc(list, func(a, b entry) int {
		return b.Value - a.Value
	})

	limit := min(3, len(list)) // will panic if there arne't more than 3

	for i := 0; i < limit; i++ {
		fmt.Printf("\n%v\t%v", list[i].Key, list[i].Value)
	}

}
