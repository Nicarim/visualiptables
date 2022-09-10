package main

import (
	"bufio"
	"fmt"
	"os"
	"visualiptables/internal/iptable"
)

func main() {
	readFile, err := os.Open("examplewrt.txt")
	if err != nil {
		fmt.Println(err)
		return
	}
	fileScanner := bufio.NewScanner(readFile)
	fileScanner.Split(bufio.ScanLines)

	for fileScanner.Scan() {
		iptable.ParseImportIpTables(fileScanner.Text())
	}

	err = readFile.Close()
	if err != nil {
		fmt.Println(err)
		return
	}
	//createTui()

}
